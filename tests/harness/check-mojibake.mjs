// Detect double-encoded Vietnamese (UTF-8 bytes reinterpreted as Latin-1/CP1252)
// in source files. This is the damage left behind by writing UTF-8 text through
// PowerShell's `Set-Content -Encoding utf8` or a mis-decoded stream.
//
// A correct Vietnamese string contains codepoints in the Latin Extended-A/Additional
// blocks (U+1EA0..U+1EF9) and U+0110/U+0111. A mojibaked one instead shows the
// classic Latin-1 pairs: "Ã", "Â", "â€", "Æ", "¡", "º", "Ä", "áº".
//
// The detector works by RE-ENCODING: take the line, encode it as latin1, then
// decode those bytes as UTF-8. If that produces valid Vietnamese characters that
// were not there before, the line was double-encoded.
import fs from 'node:fs';
import path from 'node:path';

const roots = process.argv.slice(2);
if (roots.length === 0) roots.push('src-tauri/src', 'src');

const EXTS = new Set(['.rs', '.ts', '.tsx', '.css', '.json', '.md', '.html']);

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === 'target' || e.name === 'dist') continue;
      walk(p, out);
    } else if (EXTS.has(path.extname(e.name))) {
      out.push(p);
    }
  }
  return out;
}

function tryFix(line) {
  // Only attempt when the line looks suspicious.
  if (!/[\u00C2\u00C3\u00E2\u20AC\u00C4\u00E1\u00BA\u00E6\u0192]/.test(line)) return null;
  try {
    const bytes = Buffer.from(line, 'latin1');
    const decoded = bytes.toString('utf8');
    if (decoded.includes('\uFFFD')) return null;
    // Require an actual Vietnamese character to appear after fixing.
    if (!/[\u1EA0-\u1EF9\u0110\u0111\u00E0-\u00FD]/.test(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

let total = 0;
for (const root of roots) {
  if (!fs.existsSync(root)) {
    console.log(`  skip ${root} (absent)`);
    continue;
  }
  for (const file of walk(root)) {
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    const bad = [];
    lines.forEach((line, i) => {
      const fixed = tryFix(line);
      if (fixed && fixed !== line) bad.push({ n: i + 1, line: line.trim(), fixed: fixed.trim() });
    });
    if (bad.length) {
      total += bad.length;
      console.log(`  ${file}: ${bad.length} line(s)`);
      for (const b of bad.slice(0, 4)) {
        console.log(`    ${b.n}: ${b.line.slice(0, 100)}`);
        console.log(`      -> ${b.fixed.slice(0, 100)}`);
      }
    }
  }
}
console.log(total === 0 ? '\n  0 mojibake lines' : `\n  ${total} mojibake line(s) found`);
process.exit(total === 0 ? 0 : 1);
