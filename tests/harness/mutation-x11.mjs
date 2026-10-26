import fs from 'node:fs';
import path from 'node:path';

// Prove X11 is not a no-op: take the real commands.rs, apply the proposed fix in
// memory, and confirm the gate flips FAIL -> PASS. Nothing is written to the
// repository; the patched copy lives under C:\cargo-target only.
const ROOT = 'E:\\auto-reg\\check-ip\\ip-checker';
const SRC = path.join(ROOT, 'src-tauri', 'src', 'commands.rs');
const API = path.join(ROOT, 'src', 'lib', 'api.ts');
const PATCHED = 'C:\\cargo-target\\commands-patched.rs';

// --- import the gate's own parsers by re-implementing the same logic on a path
const SNAKE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;

function parseCommands(src) {
  const out = [];
  const lines = src.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /pub\s+async\s+fn\s+(\w+)\s*\(/.exec(lines[i]);
    if (!m) continue;
    const attrs = (lines[i - 1] || '') + '\n' + (lines[i - 2] || '');
    const params = [];
    let j = i + 1;
    while (j < lines.length && !/\)\s*->/.test(lines[j])) {
      const pm = /^\s*(\w+)\s*:\s*/.exec(lines[j]);
      if (pm) params.push(pm[1]);
      j++;
    }
    out.push({ name: m[1], params, renameSnake: /rename_all\s*=\s*"snake_case"/.test(attrs) });
  }
  return out;
}
function parseCalls(src) {
  const map = new Map();
  const re = /call\(\s*"([a-z0-9_]+)"\s*(?:,\s*\{([^}]*)\})?/g;
  let m;
  while ((m = re.exec(src))) {
    const keys = [...(m[2] || '').matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*:/g)].map((k) => k[1]);
    if (!map.has(m[1])) map.set(m[1], keys);
  }
  return map;
}
function audit(cmdSrc, apiSrc) {
  const cmds = parseCommands(cmdSrc);
  const calls = parseCalls(apiSrc);
  const bad = [];
  for (const c of cmds) {
    const payload = calls.get(c.name);
    if (!payload) continue;
    const snakeParams = c.params.filter((p) => SNAKE.test(p));
    const payloadSnake = payload.filter((p) => SNAKE.test(p));
    if (snakeParams.length && payloadSnake.length && !c.renameSnake) bad.push(c.name);
  }
  return { total: cmds.length, bad };
}

const orig = fs.readFileSync(SRC, 'utf8');
const api = fs.readFileSync(API, 'utf8');

const before = audit(orig, api);
console.log(`BEFORE fix : ${before.total} commands, ${before.bad.length} broken -> ${before.bad.join(', ') || 'none'}`);

// Apply the proposed fix: annotate every bare #[tauri::command].
const patched = orig.replace(/(?<!#\[tauri::command)[^\S\r\n]*#\[tauri::command\]/g, '#[tauri::command(rename_all = "snake_case")]');
fs.writeFileSync(PATCHED, patched, 'utf8');
const relCount = (patched.match(/#\[tauri::command\(rename_all = "snake_case"\)\]/g) || []).length;
console.log(`patched copy: ${PATCHED} (${relCount} annotated attributes)`);

const after = audit(patched, api);
console.log(`AFTER  fix : ${after.total} commands, ${after.bad.length} broken -> ${after.bad.join(', ') || 'none'}`);

const flips = before.bad.length > 0 && after.bad.length === 0;
console.log(`\nX11 is NOT a no-op: ${flips ? 'YES — FAIL flips to PASS when the fix is applied' : 'NO — investigate'}`);
process.exit(flips ? 0 : 1);
