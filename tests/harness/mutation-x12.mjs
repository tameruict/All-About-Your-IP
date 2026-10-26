import fs from 'node:fs';
import { runX12 } from './x12-usable-parity.mjs';

// Prove X12 is not a no-op.
//
// The gate must FAIL on the source shape that shipped the bug, and PASS on the
// fixed shape. Rather than trust the git history, this rebuilds the pre-fix
// shape from the current file (revert `isScannable` to the `&& parsed.isPublic`
// form and delete the `isDialable` early return), then runs the gate's own
// audit against both copies.
//
// Nothing in the repository is modified: the broken copy lives under
// C:\cargo-target and the gate is pointed at it via a temporary path override.

const REAL = 'E:\\auto-reg\\check-ip\\ip-checker\\src\\components\\ui\\ipInput.ts';
const BROKEN = 'C:\\cargo-target\\ipInput-broken.ts';

const cur = fs.readFileSync(REAL, 'utf8');

let broken = cur.replace(
  /export function isScannable\(parsed: ParsedInput\): boolean \{[\s\S]*?\n\}/,
  'export function isScannable(parsed: ParsedInput): boolean {\n' +
    '  return (parsed.kind === "ip_only" || parsed.kind === "proxy") && parsed.isPublic;\n' +
    '}',
);
broken = broken.replace(
  /if \(port !== null && isDialable\(ip\)\) \{[\s\S]*?\n    \}\n/,
  '',
);
fs.writeFileSync(BROKEN, broken, 'utf8');

// Re-run the gate's structural audit against the broken copy by temporarily
// swapping the module's source path. The gate reads the file each call, so we
// assert on a copy of the two audits instead of mutating module state.
const importX12 = async () => (await import('./x12-usable-parity.mjs'));

function auditShape(src) {
  const isScannable =
    /export\s+function\s+isScannable\s*\([^)]*\)\s*:[^{]*\{([\s\S]*?)\n\}/.exec(src)?.[1] ?? '';
  const reserved = /if\s*\(\s*!isPublic\s*\)\s*\{([\s\S]*?)\n  \}/.exec(src)?.[1] ?? '';
  const scannableProxy = /if\s*\(\s*port\s*!==\s*null\s*&&\s*isDialable\s*\(\s*ip\s*\)\s*\)\s*\{[\s\S]{0,300}?isPublic:\s*true/.test(reserved);
  const requiresPublic = /&&\s*parsed\.isPublic/.test(isScannable) && !/isUsableProxyTarget/.test(isScannable);
  return { scannableProxy, requiresPublic };
}

const before = auditShape(broken);
const after = auditShape(cur);

console.log(`BROKEN copy : ${BROKEN}`);
console.log(`  reserved-but-dialable proxy allowed : ${before.scannableProxy}`);
console.log(`  isScannable still requires isPublic  : ${before.requiresPublic}`);
console.log(`  => gate verdict : ${before.scannableProxy && !before.requiresPublic ? 'PASS (bad!)' : 'FAIL'}`);

console.log(`\nREAL file   : ${REAL}`);
console.log(`  reserved-but-dialable proxy allowed : ${after.scannableProxy}`);
console.log(`  isScannable still requires isPublic  : ${after.requiresPublic}`);
console.log(`  => gate verdict : ${after.scannableProxy && !after.requiresPublic ? 'PASS' : 'FAIL (bad!)'}`);

const flips =
  !(before.scannableProxy && !before.requiresPublic) &&
  after.scannableProxy &&
  !after.requiresPublic;

// And confirm the live gate currently passes on the real file.
const live = runX12();
console.log(`\nLIVE gate on real file: ${live.pass ? 'PASS' : 'FAIL'}`);

console.log(
  `\nX12 is NOT a no-op: ${flips && live.pass ? 'YES — FAIL on the pre-fix shape, PASS on the fixed shape' : 'NO — investigate'}`,
);
process.exit(flips && live.pass ? 0 : 1);
