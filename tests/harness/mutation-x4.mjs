// Mutation test for X4's weight gate.
// Copies scoring.rs to a temp file, corrupts one weight, and checks that the
// SAME parsing the harness does actually flags it. A gate that cannot fail is
// not a gate.
import fs from 'node:fs';

const SRC = 'E:\\auto-reg\\check-ip\\ip-checker\\src-tauri\\src\\scoring.rs';
const real = fs.readFileSync(SRC, 'utf8');

const WEIGHTS_RE = /WEIGHTS\s*:\s*\[[^\]]*\]\s*=\s*\[([\s\S]*?)\];/;
const PAIR_RE = /\("([a-z_]+)"\s*,\s*([0-9.]+)\)/g;

function parseWeights(text) {
  const stripped = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const m = stripped.match(WEIGHTS_RE);
  if (!m) return null;
  return Object.fromEntries([...m[1].matchAll(PAIR_RE)].map((x) => [x[1], Number(x[2])]));
}

const EXPECT = { fraud: 0.35, blacklist: 0.25, asn: 0.2, abuse: 0.1, consistency: 0.1 };

function evaluate(text) {
  const w = parseWeights(text);
  if (!w) return { parsed: null, mismatched: ['<could not parse WEIGHTS>'], sum: NaN };
  const mismatched = Object.entries(EXPECT)
    .filter(([n, want]) => w[n] === undefined || Math.abs(w[n] - want) >= 1e-9)
    .map(([n, want]) => `${n}: want ${want * 100}% got ${w[n] === undefined ? 'missing' : w[n] * 100 + '%'}`);
  const sum = Object.values(w).reduce((a, b) => a + b, 0);
  return { parsed: w, mismatched, sum };
}

let pass = 0;
let fail = 0;
const say = (ok, msg) => {
  console.log((ok ? '  OK   ' : '  FAIL ') + msg);
  if (ok) pass++; else fail++;
};

// 1. the real file must pass
const base = evaluate(real);
say(base.parsed !== null, `baseline: WEIGHTS parsed (${base.parsed ? Object.entries(base.parsed).map(([k, v]) => k + '=' + v).join(' ') : 'none'})`);
say(base.mismatched.length === 0, `baseline: all 5 weights match spec (§6.4)`);
say(Math.abs(base.sum - 1.0) < 1e-6, `baseline: weights sum to 1.0 (got ${base.sum.toFixed(4)})`);

// 2. corrupt asn 0.20 -> 0.30 (sum still reachable, so sum-check alone would miss it)
const m1 = real.replace('("asn", 0.20)', '("asn", 0.30)');
if (m1 === real) {
  say(false, 'mutation could not be applied — the literal changed, update this test');
} else {
  const r1 = evaluate(m1);
  say(r1.mismatched.some((x) => x.startsWith('asn:')), `mutation asn=0.30 is caught (${r1.mismatched.join('; ') || 'MISSED'})`);
  say(Math.abs(r1.sum - 1.0) >= 1e-6, `and the sum check also fires (sum=${r1.sum.toFixed(4)})`);
}

// 3. corrupt consistently so the sum stays 1.0 — per-aspect check must still catch it
//    asn 0.20 -> 0.30, abuse 0.10 -> 0.00  (sum = 1.0 again)
const m2 = real.replace('("asn", 0.20)', '("asn", 0.30)').replace('("abuse", 0.10)', '("abuse", 0.00)');
if (m2 === real) {
  say(false, 'second mutation could not be applied');
} else {
  const r2 = evaluate(m2);
  say(r2.mismatched.length >= 2, `sum-preserving corruption still caught (${r2.mismatched.join('; ')})`);
  say(Math.abs(r2.sum - 1.0) < 1e-6, `(sum is ${r2.sum.toFixed(4)} — sum check alone would pass here)`);
}

// 4. wrong threshold must be caught by the const reader
const thrRe = (name) => new RegExp(`const\\s+${name}\\s*:\\s*f64\\s*=\\s*([0-9.]+)`);
const m3 = real.replace('pub const CLEAN_VERDICT_MIN: f64 = 85.0;', 'pub const CLEAN_VERDICT_MIN: f64 = 80.0;');
if (m3 === real) {
  say(false, 'threshold mutation could not be applied');
} else {
  const got = Number(m3.match(thrRe('CLEAN_VERDICT_MIN'))[1]);
  say(got !== 85, `mutation CLEAN_VERDICT_MIN=80 is caught (parsed ${got})`);
}

// 5. the old, buggy regex must be shown to be broken — documents WHY this was rewritten
const ASN_OLD = /0\.2\b/;
say(!ASN_OLD.test('("asn", 0.20)'), 'old /0\\.2\\b/ does NOT match "0.20" (confirms the bug that was fixed)');
say(/0\.20?\b/.test('("asn", 0.20)'), 'new /0\\.20?\\b/ does match "0.20"');

console.log(`\n  ${pass} ok / ${fail} fail`);
process.exit(fail > 0 ? 1 : 0);
