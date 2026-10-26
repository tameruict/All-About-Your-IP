/**
 * X11 — IPC parameter naming (§2.3, §4.2)
 *
 * `#[tauri::command]` makes Tauri rename every command parameter to camelCase
 * at the IPC boundary. So a Rust parameter `check_id` is invoked as `checkId`.
 * When `api.ts` sends snake_case and the command has no
 * `#[tauri::command(rename_all = "snake_case")]`, the call fails at runtime with
 *
 *     invalid args `checkId` for command `export_report`:
 *       command export_report missing required key checkId
 *
 * `cargo test` cannot see this: Rust tests call the function directly and never
 * cross the IPC wrapper the macro generates. This gate replaces "run the app and
 * click every button" with a static comparison of the two sides.
 *
 * Reads only; writes nothing.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const COMMANDS = path.join(ROOT, 'src-tauri', 'src', 'commands.rs');
const API = path.join(ROOT, 'src', 'lib', 'api.ts');

const SNAKE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;
const CAMEL = /^[a-z][a-zA-Z0-9]*$/;

/** Parse `pub async fn name(...)` bodies out of commands.rs. */
function parseCommands(src) {
  const out = [];
  const lines = src.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /pub\s+async\s+fn\s+(\w+)\s*\(/.exec(lines[i]);
    if (!m) continue;
    // Attribute lines sit above the fn; walk back over the attribute block.
    let attrs = '';
    for (let j = i - 1; j >= 0 && j > i - 6; j--) {
      attrs = lines[j] + '\n' + attrs;
      if (/^\s*#\[|^\s*\/\/|^\s*$/.test(lines[j])) continue;
      break;
    }
    const params = [];
    let j = i + 1;
    while (j < lines.length && !/\)\s*->/.test(lines[j])) {
      const pm = /^\s*(\w+)\s*:\s*/.exec(lines[j]);
      if (pm) params.push(pm[1]);
      j++;
    }
    out.push({
      name: m[1],
      params,
      renameSnake: /rename_all\s*=\s*"snake_case"/.test(attrs),
      renameCamel: /rename_all\s*=\s*"camelCase"/.test(attrs),
      line: i + 1,
    });
  }
  return out;
}

/** Parse `call("cmd", { key: value, ... })` argument objects out of api.ts. */
function parseCalls(src) {
  const map = new Map();
  const re = /call\(\s*"([a-z0-9_]+)"\s*(?:,\s*\{([^}]*)\})?/g;
  let m;
  while ((m = re.exec(src))) {
    const cmd = m[1];
    const body = m[2] || '';
    const keys = [];
    const kre = /([A-Za-z_][A-Za-z0-9_]*)\s*:/g;
    let k;
    while ((k = kre.exec(body))) keys.push(k[1]);
    // `{ limit }` shorthand
    const shorthand = /(?:^|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=,|$)/.exec(body);
    if (!keys.length && shorthand) keys.push(shorthand[1]);
    if (!map.has(cmd)) map.set(cmd, keys);
  }
  return map;
}

export function runX11() {
  const checks = [];
  const add = (ok, label) => checks.push({ ok, label });

  for (const [label, file] of [['commands.rs', COMMANDS], ['api.ts', API]]) {
    if (!fs.existsSync(file)) {
      add(false, `${label} exists`);
      return { pass: false, checks, commands: [], summary: `${label} missing` };
    }
    add(true, `${label} exists`);
  }

  const commands = parseCommands(fs.readFileSync(COMMANDS, 'utf8'));
  const calls = parseCalls(fs.readFileSync(API, 'utf8'));
  add(commands.length >= 8, `${commands.length} Tauri command(s) parsed`);

  let mismatches = 0;
  let camelConflicts = 0;
  const rows = [];
  const seen = [];

  for (const cmd of commands) {
    const snakeParams = cmd.params.filter((p) => SNAKE.test(p));
    const payload = calls.get(cmd.name);
    if (!payload) continue; // declared but not called from api.ts
    seen.push(cmd.name);

    const payloadSnake = payload.filter((p) => SNAKE.test(p));
    const payloadCamel = payload.filter((p) => CAMEL.test(p) && !SNAKE.test(p));

    if (cmd.renameCamel && payloadSnake.length) {
      camelConflicts++;
      rows.push({ cmd: cmd.name, verdict: 'FAIL', why: `rename_all="camelCase" but api.ts sends ${payloadSnake.join(',')}` });
      continue;
    }

    if (snakeParams.length && payloadSnake.length && !cmd.renameSnake) {
      const renamed = snakeParams.map((p) => p.replace(/_([a-z])/g, (_, c) => c.toUpperCase()));
      mismatches++;
      rows.push({
        cmd: cmd.name,
        verdict: 'FAIL',
        why: `api.ts sends ${payloadSnake.join(',')} but command lacks rename_all="snake_case" (Tauri will demand ${renamed.join(',')})`,
      });
      continue;
    }

    rows.push({ cmd: cmd.name, verdict: 'PASS', why: `${payload.length} arg(s), naming aligned` });
  }

  add(mismatches === 0, `no snake_case payload vs camelCase command mismatch (${mismatches} found)`);
  add(camelConflicts === 0, `no rename_all="camelCase" on a snake_case caller (${camelConflicts} found)`);

  const pass = checks.every((c) => c.ok);
  return { pass, checks, rows, commands: seen, summary: `${seen.length} command(s) cross-checked` };
}

/* ------------------------------------------------------------------ */

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('x11-ipc-naming.mjs')) {
  const r = runX11();
  console.log('X11 — IPC parameter naming (§2.3, §4.2)');
  console.log(`  scope: runCheck from ${path.relative(ROOT, COMMANDS)} vs ${path.relative(ROOT, API)}`);
  for (const c of r.checks) console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.label}`);
  console.log('');
  for (const row of r.rows) console.log(`  ${row.verdict.padEnd(5)} ${row.cmd.padEnd(22)} ${row.why}`);
  console.log(`\n  ${r.summary}`);
  console.log(r.pass ? '\nX11: PASS' : '\nX11: FAIL — the app will throw `missing required key` at runtime');
  process.exit(r.pass ? 0 : 1);
}
