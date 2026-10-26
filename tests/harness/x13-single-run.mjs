/**
 * X13 — one scan, one run.
 *
 * A scan must invoke exactly ONE check command. When `startCheck` called both
 * `check_ip_stream` and `check_ip`, each ran all 13 modules:
 *
 *   check_ip_stream -> 13 modules -> check_id A -> written to the DB
 *   check_ip        -> 13 modules -> check_id B -> not written
 *   front-end kept B
 *
 * Visible damage:
 *   * EXPORT died — export asked for B, the cache only ever had A
 *     ("Không có dữ liệu để xuất cho check_id <B>").
 *   * One click cost TWICE the §4.3 module budget and twice the provider quota.
 *   * Scan took ~60 s instead of ~30 s. That reads as "slow", not as "ran twice".
 *   * HISTORY listed row A while the panel held B, so "Check lại" used a stale id.
 *
 * The arithmetic that exposed it: 3 clicks produced 3 rows, not 6. A second run
 * that leaves no row is invisible unless you count.
 *
 * This gate counts invocations inside the scan entry point. Static: reads
 * source, does not run the app.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const APP_TSX = path.join(ROOT, 'src', 'App.tsx');

/** Commands that perform a full check run. */
const CHECK_COMMANDS = ['checkIpStream', 'checkIp'];

/**
 * Extract the body of the scan entry point.
 *
 * It is an arrow function assigned with `useCallback(...)`, so there is no
 * `function name(` to anchor on. Anchor on the last `async (` that is followed
 * by a `ScanRequest` parameter, then brace-match to its end.
 */
export function extractStartCheck(src) {
  const anchor = /async\s*\(\s*request:\s*ScanRequest[^)]*\)\s*=>\s*\{/g;
  let m;
  let start = -1;
  let afterAnchor = -1;
  while ((m = anchor.exec(src))) {
    start = m.index;
    afterAnchor = m.index + m[0].length;
  }
  if (start < 0) return null;

  // `{` is the last char the anchor consumed.
  const open = afterAnchor - 1;
  if (src[open] !== '{') return null;

  let depth = 0;
  let i = open;
  let inStr = null;
  let prev = '';
  for (; i < src.length; i++) {
    const ch = src[i];
    if (inStr) {
      if (ch === '\\') { i++; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
    if (ch === '/' && src[i + 1] === '/') { i = src.indexOf('\n', i); if (i < 0) break; continue; }
    if (ch === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); if (e < 0) break; i = e + 1; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) { i++; break; }
    }
    prev = ch;
  }
  return src.slice(open, i);
}

/**
 * Count how many times each check command is CALLED (not mentioned).
 * A call is `api.checkIpStream(` / `checkIpStream(`, ignoring property access on
 * other objects and ignoring occurrences inside comments.
 */
export function countCheckCalls(body) {
  // Strip comments so prose about the removed call does not count.
  const code = body
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

  const hits = [];
  for (const cmd of CHECK_COMMANDS) {
    const re = new RegExp(`(?:\\bapi\\.)?\\b${cmd}\\s*\\(`, 'g');
    let m;
    while ((m = re.exec(code))) {
      // Ignore a definition-ish form (`checkIpStream:` in an object literal).
      const before = code.slice(Math.max(0, m.index - 24), m.index);
      if (/:\s*$/.test(before)) continue;
      hits.push({ cmd, index: m.index });
    }
  }
  hits.sort((a, b) => a.index - b.index);
  return hits;
}

export function runX13() {
  const checks = [];
  const add = (ok, label, detail) => checks.push({ ok, label, detail });

  if (!fs.existsSync(APP_TSX)) {
    add(false, 'App.tsx exists');
    return { pass: false, checks, calls: [], summary: 'App.tsx missing' };
  }
  add(true, 'App.tsx exists');

  const src = fs.readFileSync(APP_TSX, 'utf8');
  const body = extractStartCheck(src);
  if (!body) {
    add(false, 'scan entry point (`async (request: ScanRequest) => {`) found');
    return { pass: false, checks, calls: [], summary: 'startCheck not found' };
  }
  add(true, `scan entry point found (${body.length} chars)`);

  const calls = countCheckCalls(body);
  add(calls.length === 1, `exactly 1 check command invoked per scan (found ${calls.length})`,
    calls.length ? calls.map((c) => c.cmd).join(' + ') : null);

  // Both ids must come from the single run; a second call would overwrite it.
  const setsCheckId = /checkId:\s*session\.check_id/.test(body);
  add(setsCheckId, 'checkId comes from the single session.check_id (not a second result)',
    setsCheckId ? null : 'scan does not assign checkId from session.check_id');

  // The result shown must be the same run's result, not a later call's.
  const setsResult = /result:\s*session\.result/.test(body);
  add(setsResult, 'displayed result comes from the same session.result',
    setsResult ? null : 'scan does not assign result from session.result');

  const pass = checks.every((c) => c.ok);
  return {
    pass,
    checks,
    calls,
    summary: `${calls.length} check command invocation(s) in the scan entry point`,
  };
}

/* ------------------------------------------------------------------ */

const invokedDirectly =
  process.argv[1] && /x13-single-run\.mjs$/.test(process.argv[1].replace(/\\/g, '/'));

if (invokedDirectly) {
  const r = runX13();
  console.log('X13 — one scan, one run (§4.3, §10.2, §13.9)');
  console.log(`  scope: startCheck in ${path.relative(ROOT, APP_TSX)}`);
  console.log('');
  for (const c of r.checks) {
    console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.label}${c.detail ? `\n          ${c.detail}` : ''}`);
  }
  console.log(`\n  ${r.summary}`);
  console.log(r.pass ? '\nX13: PASS' : '\nX13: FAIL — one click must be one run');
  process.exit(r.pass ? 0 : 1);
}
