/**
 * v5 acceptance probe — four criteria, measured not assumed.
 *
 *   1. Scan duration ~30 s, not ~60 s. A single click used to run all 13
 *      modules twice (check_ip_stream + check_ip); the second run left no DB
 *      row, so the only visible trace was time and burned quota.
 *   2. Export writes a real file. Before, the panel held check_id B while the
 *      cache only ever had A, so export died with "Không có dữ liệu để xuất".
 *   3. History row id matches the panel's current result.
 *   4. "Check lại" re-runs with the correct id.
 *
 * This helper does the parts that do not need the UI: locate the DB, dump the
 * newest rows, and time a scan by watching the proxy log + the app process.
 * UI-driven steps are performed by the caller and printed here for the record.
 *
 * Usage: node tests/harness/v5-acceptance.mjs [--dump]
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const DUMP = process.argv.includes('--dump');

const DB_CANDIDATES = [
  path.join(os.homedir(), 'AppData', 'Roaming', 'ip-checker', 'app.db'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'com.ipchecker.desktop', 'app.db'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'com.ipchecker.app', 'app.db'),
];

const PROXY_LOG = 'C:\\cargo-target\\socks5-connections.log';

function findDb() {
  for (const p of DB_CANDIDATES) {
    if (fs.existsSync(p)) {
      const st = fs.statSync(p);
      return { path: p, size: st.size, mtime: st.mtime };
    }
  }
  return null;
}

/**
 * Read the newest `checks` rows through the sqlite3 CLI.
 *
 * Scanning the file image for UUID text does NOT work: SQLite stores the id as
 * a blob, and the live writes sit in `app.db-wal`, which is locked while the
 * app is running. Opening the database read-only through sqlite3 sees the
 * committed + WAL state without disturbing the running process.
 */
import { execFileSync } from 'node:child_process';

const SQLITE = 'C:\\msys64\\mingw64\\bin\\sqlite3.exe';

function query(db, sql) {
  try {
    return execFileSync(SQLITE, [`file:${db}?mode=ro`, sql], {
      encoding: 'utf8',
      timeout: 10000,
    }).trim();
  } catch (err) {
    return `ERR: ${err.message.split('\n')[0]}`;
  }
}

function dumpChecks(db) {
  const rows = query(db, 'SELECT id, ip, mode, checked_at FROM checks ORDER BY checked_at DESC LIMIT 8;');
  const count = query(db, 'SELECT COUNT(*) FROM checks;');
  const votes = query(db, 'SELECT COUNT(*) FROM provider_results;');
  return { rows, count, votes };
}

/** Count proxy CONNECTs since a byte offset, split app vs WebView2. */
function proxySince(offset) {
  if (!fs.existsSync(PROXY_LOG)) return null;
  const buf = fs.readFileSync(PROXY_LOG);
  const slice = buf.slice(offset).toString('utf8');
  const lines = slice.split(/\r?\n/).filter(Boolean);
  const browserRe =
    /google\.com|gstatic\.com|gvt1\.com|mtalk\.google\.com|googleapis\.com|android\.clients|edgedl/;
  const conns = [];
  for (const l of lines) {
    const m = /CONNECT\s+\d+\s+(\S+)/.exec(l);
    if (m) conns.push(m[1]);
  }
  const app = conns.filter((c) => !browserRe.test(c));
  const web = conns.filter((c) => browserRe.test(c));
  return { lines: lines.length, connects: conns.length, app: app.length, web: web.length, targets: [...new Set(app)] };
}

function logSize() {
  try {
    return fs.statSync(PROXY_LOG).size;
  } catch {
    return 0;
  }
}

const db = findDb();
console.log('=== v5 acceptance: environment ===');
if (db) {
  console.log(`  DB         : ${db.path}`);
  console.log(`  DB mtime   : ${db.mtime.toISOString()}  (${db.size} B)`);
} else {
  console.log('  DB         : NOT FOUND in any known profile dir');
}

const appExe = [
  'C:\\cargo-target\\ip-build-v5\\release\\ip-checker.exe',
  'C:\\cargo-target\\ip-build-v6\\release\\ip-checker.exe',
  'C:\\cargo-target\\ip-build-v4\\release\\ip-checker.exe',
].find((p) => fs.existsSync(p));
if (appExe) {
  const st = fs.statSync(appExe);
  console.log(`  binary     : ${appExe}`);
  console.log(`  built      : ${st.mtime.toISOString()}  ${st.size} B`);
  console.log(`  NOTE       : verify the RUNNING process path matches this before trusting results`);
}

console.log(`  proxy log  : ${PROXY_LOG} (${logSize()} B)`);

if (DUMP && db) {
  console.log('\n=== checks table (read-only, sees WAL) ===');
  const { rows, count, votes } = dumpChecks(db.path);
  console.log(`  checks rows           : ${count}`);
  console.log(`  provider_results rows : ${votes}`);
  console.log('  id | ip | mode | checked_at');
  for (const line of rows.split('\n')) console.log(`    ${line}`);
  console.log('\n  Cross-check: the id the UI exports MUST appear above.');
  console.log('  If it does not, one click ran more than once (see X13).');
}

console.log('\n=== how to use during a scan ===');
console.log('  1. note proxy log size now      : ' + logSize() + ' B');
console.log('  2. click SCAN, record t0');
console.log('  3. when the button returns to SCAN, record t1');
console.log('  4. re-run: node tests/harness/v5-acceptance.mjs --dump');
console.log('     - criteria 1: t1-t0 should be ~30 s (was ~60 s)');
console.log('     - criteria 1b: proxy CONNECT count should be about HALF the v4 count');
console.log('     - criteria 2: export must produce a file; if not, compare the');
console.log("        panel's id against the ids listed by --dump");
console.log('     - criteria 3/4: the history row id must equal the panel id');
