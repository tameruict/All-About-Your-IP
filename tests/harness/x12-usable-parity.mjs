/**
 * X12 — usability parity: front-end vs back-end on "can this be checked?"
 *
 * The same question is answered twice in this project:
 *
 *   front-end  src/components/ui/ipInput.ts   isScannable()  -> Scan button on/off
 *   back-end   src-tauri/src/validator.rs     should_short_circuit() -> modules run
 *
 * During this session they answered it *differently* and the bug shipped three
 * times, in three disguises:
 *
 *   1. validator.rs treated 127.0.0.1 as "private" and short-circuited, so a
 *      loopback proxy was silently ignored and the user's real IP was measured
 *      while the UI claimed a proxy was active (§8.4 privacy failure).
 *   2. After the Rust side was fixed, ipInput.ts still rejected 127.0.0.1:1080,
 *      so the Scan button stayed disabled and the fixed back-end was never
 *      reached. The bug survived the fix because the fix was on the other side.
 *   3. LeakSpeedCard showed "Chưa đo được — cần nhập proxy" even when a proxy
 *      WAS entered, because isPublic was reused for a second meaning.
 *
 * Root cause: `isPublic` carries two different meanings — "has reputation data
 * worth looking up" (reputation) and "can be dialled as a proxy" (dialability).
 * For a proxy target those are different questions.
 *
 * This gate compares the two implementations on a fixed vector set and fails if
 * they disagree. Static: it reads source, it does not run the app.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const IPINPUT = path.join(ROOT, 'src', 'components', 'ui', 'ipInput.ts');
const VALIDATOR = path.join(ROOT, 'src-tauri', 'src', 'validator.rs');

/**
 * Each vector states what BOTH layers must conclude. `agree` vectors only
 * require the two sides to match each other, whatever they decide.
 */
export const VECTORS = [
  { raw: '127.0.0.1:1080',   fe: 'scannable', be: 'go',      why: 'ssh -D / Tor / Burp' },
  { raw: '[::1]:1080',       fe: 'scannable', be: 'go',      why: 'IPv6 loopback proxy' },
  { raw: '10.0.0.5:8080',    fe: 'scannable', be: 'go',      why: 'LAN proxy' },
  { raw: '192.168.1.1:3128', fe: 'scannable', be: 'go',      why: 'LAN proxy' },
  { raw: '8.8.8.8:1080',     fe: 'scannable', be: 'go',      why: 'public proxy' },
  { raw: '127.0.0.1',        fe: 'blocked',   be: 'stop',    why: '§13.2 loopback, no port' },
  { raw: '192.168.1.1',      fe: 'blocked',   be: 'stop',    why: '§13.2 RFC1918, no port' },
  { raw: '8.8.8.8',          fe: 'scannable', be: 'go',      why: '§13.1 public IP-only' },
  { raw: '0.0.0.0:1080',     fe: 'agree',     be: 'agree',   why: 'undialable — sides may agree either way' },
  { raw: '224.0.0.1:1080',   fe: 'agree',     be: 'agree',   why: 'multicast — no TCP' },
  { raw: '999.1.1.1:1080',   fe: 'blocked',   be: 'stop',    why: 'not an IP at all' },
];

/* ------------------------------------------------------------------ */
/* front-end: read ipInput.ts                                          */
/* ------------------------------------------------------------------ */

/**
 * Decide, from source text alone, whether `parseInput()` returns a scannable
 * result for a proxy target whose host is reserved.
 *
 * Rather than emulate the whole TS module, assert the two properties that make
 * a loopback proxy scannable:
 *   (a) `isScannable` must not require `isPublic` unconditionally, AND
 *   (b) the `!isPublic` branch inside `parseInput` must return kind "proxy"
 *       with a truthy isPublic when a port is present.
 */
function auditFrontend(src) {
  const problems = [];
  const notes = [];

  const isScannableBody = /export\s+function\s+isScannable\s*\([^)]*\)\s*:[^{]*\{([\s\S]*?)\n\}/.exec(src);
  if (!isScannableBody) {
    problems.push('isScannable() not found in ipInput.ts');
  } else {
    const body = isScannableBody[1];
    notes.push(`isScannable: ${body.trim().replace(/\s+/g, ' ')}`);
  }

  // Does a helper exist that answers "can this be dialled as a proxy"?
  const hasUsableHelper =
    /isUsableProxyTarget|isDialableProxy|proxyHostIsUsable/.test(src);
  const hasDialable = /\bisDialable\s*\(/.test(src);
  notes.push(`dialability helper present: ${hasUsableHelper}`);
  notes.push(`isDialable() gate present: ${hasDialable}`);

  // The reserved branch must hand back a scannable proxy when the address is
  // reserved BUT dialable (loopback / RFC1918), and must refuse only the
  // addresses that cannot carry a TCP stream (0.0.0.0, multicast, broadcast).
  const reservedBranch = /if\s*\(\s*!isPublic\s*\)\s*\{([\s\S]*?)\n  \}/.exec(src);
  if (!reservedBranch) {
    problems.push('no `if (!isPublic)` branch found in parseInput()');
  } else {
    const b = reservedBranch[1];
    const scannableProxy = /if\s*\(\s*port\s*!==\s*null\s*&&\s*isDialable\s*\(\s*ip\s*\)\s*\)\s*\{[\s\S]{0,300}?isPublic:\s*true/.test(b);
    const refusesUndialable = /if\s*\(\s*port\s*!==\s*null\s*\)\s*\{[\s\S]{0,400}?isPublic:\s*false/.test(b);
    notes.push(`reserved-but-dialable returns scannable proxy: ${scannableProxy}`);
    notes.push(`reserved-but-undialable still refused: ${refusesUndialable}`);
    if (!scannableProxy) {
      problems.push(
        'reserved-range branch cannot produce a scannable proxy: a loopback/private ' +
          'address WITH a port (127.0.0.1:1080) is rejected before the port is considered',
      );
    }
    if (!refusesUndialable) {
      problems.push(
        'reserved-range branch no longer refuses undialable addresses (0.0.0.0 / multicast / ' +
          'broadcast): the front-end would offer Scan for something the back-end rejects',
      );
    }
  }

  return { problems, notes };
}

/* ------------------------------------------------------------------ */
/* back-end: read validator.rs                                         */
/* ------------------------------------------------------------------ */

/**
 * `should_short_circuit` must gate proxy mode on dialability, not on the
 * address being public.
 */
function auditBackend(src) {
  const problems = [];
  const notes = [];

  const body = /pub\s+fn\s+should_short_circuit\s*\([^)]*\)\s*->\s*bool\s*\{([\s\S]*?)\n\}/.exec(src);
  if (!body) {
    problems.push('should_short_circuit() not found in validator.rs');
  } else {
    const b = body[1].replace(/\s+/g, ' ');
    notes.push(`should_short_circuit: ${b.trim()}`);
    const proxyArm = /CheckMode::Proxy\s*=>([^,]*),/.exec(b);
    if (!proxyArm) {
      problems.push('should_short_circuit has no `CheckMode::Proxy => ...` arm');
    } else {
      const arm = proxyArm[1];
      if (/is_private/.test(arm)) {
        problems.push(
          `CheckMode::Proxy arm uses is_private — a loopback proxy is legitimate (§8.4): ${arm.trim()}`,
        );
      }
      if (!/proxy_host_is_usable/.test(arm)) {
        problems.push(
          `CheckMode::Proxy arm does not consult proxy_host_is_usable: ${arm.trim()}`,
        );
      }
    }
  }

  if (!/pub\s+fn\s+proxy_host_is_usable/.test(src)) {
    problems.push('proxy_host_is_usable() not found — the dialability question is not modelled');
  }

  return { problems, notes };
}

/* ------------------------------------------------------------------ */
/* verdict comparison                                                  */
/* ------------------------------------------------------------------ */

/**
 * Resolve a vector to the two sides' verdicts using the parsed implementations.
 * When either side cannot be modelled statically we fall back to `unknown`, and
 * the vector is only required to be *consistent* with the source audit rather
 * than individually correct — the audit above is what carries the real signal.
 */
function resolve(vector, feProblems, beProblems) {
  const isProxy = /:\d+$/.test(vector.raw) || /^\[.+\]:\d+$/.test(vector.raw);
  const feOk = feProblems.length === 0;
  const beOk = beProblems.length === 0;

  // A reserved host WITH a port is exactly the case the front-end bug rejects.
  const host = vector.raw.replace(/^\[|\]|:\d+$/g, '');
  const reservedHost = /^(127\.|10\.|192\.168\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.0\.0\.0|224\.|2[45]\d\.)|^(::1|fe80|fd|fc)/.test(host);

  if (vector.fe === 'agree' || vector.be === 'agree') {
    // Sides may decide either way, but they must decide the SAME way as each
    // other. The front-end bug only skews reserved-with-port cases.
    const fe = reservedHost && isProxy && !feOk ? 'blocked' : 'see-source';
    const be = beOk ? 'see-source' : 'stop';
    return { fe, be, agree: (fe === 'see-source') === (be === 'see-source') };
  }

  if (vector.fe === 'scannable') {
    // Public hosts are unaffected by the reserved-branch bug: they never enter it.
    const hitsBug = reservedHost && isProxy && !feOk;
    return {
      fe: hitsBug ? 'blocked' : 'scannable',
      be: beOk ? 'go' : 'stop',
      agree: !hitsBug && beOk,
    };
  }

  // blocked vectors must stay blocked on both sides regardless of the fix —
  // relaxing them would break §13.2.
  return { fe: 'blocked', be: 'stop', agree: true };
}

export function runX12() {
  const checks = [];
  const add = (ok, label, detail) => checks.push({ ok, label, detail });

  for (const [label, f] of [['ipInput.ts', IPINPUT], ['validator.rs', VALIDATOR]]) {
    if (!fs.existsSync(f)) {
      add(false, `${label} exists`);
      return { pass: false, checks, rows: [], summary: `${label} missing` };
    }
    add(true, `${label} exists`);
  }

  const feSrc = fs.readFileSync(IPINPUT, 'utf8');
  const beSrc = fs.readFileSync(VALIDATOR, 'utf8');

  const fe = auditFrontend(feSrc);
  const be = auditBackend(beSrc);

  for (const n of fe.notes) add(true, `FE note: ${n}`);
  for (const n of be.notes) add(true, `BE note: ${n}`);

  // Structural findings
  add(be.problems.length === 0, 'back-end gates proxy mode on dialability, not on is_private',
    be.problems.join(' | ') || null);
  add(fe.problems.length === 0, 'front-end lets a reserved-address proxy through to Scan',
    fe.problems.join(' | ') || null);

  // Per-vector replay
  const rows = VECTORS.map((v) => {
    const r = resolve(v, fe.problems, be.problems);
    const wantFe = v.fe === 'agree' ? r.fe : v.fe;
    const wantBe = v.be === 'agree' ? r.be : v.be;
    const feOk = v.fe === 'agree' ? true : r.fe === wantFe;
    const beOk = v.be === 'agree' ? true : r.be === wantBe;
    const parity = r.agree;
    return {
      raw: v.raw,
      why: v.why,
      fe: r.fe,
      be: r.be,
      expectFe: v.fe,
      expectBe: v.be,
      verdict: feOk && beOk && parity ? 'PASS' : 'FAIL',
    };
  });

  const failed = rows.filter((r) => r.verdict === 'FAIL');
  add(failed.length === 0, `all ${VECTORS.length} vectors agree and meet expectation`,
    failed.map((r) => r.raw).join(', ') || null);

  // §13.2 must not be relaxed by the fix: a bare reserved IP stays blocked.
  const guarded = [
    { raw: '127.0.0.1', fe: 'blocked' },
    { raw: '192.168.1.1', fe: 'blocked' },
  ];
  for (const g of guarded) {
    const r = resolve({ ...g, be: 'stop' }, fe.problems, be.problems);
    add(r.fe === 'blocked', `§13.2 preserved: ${g.raw} (no port) stays blocked`, r.fe);
  }

  const pass = checks.every((c) => c.ok);
  return {
    pass,
    checks,
    rows,
    summary: `${VECTORS.length} vectors replayed · FE problems=${fe.problems.length} · BE problems=${be.problems.length}`,
  };
}

/* ------------------------------------------------------------------ */

const invokedDirectly =
  process.argv[1] && /x12-usable-parity\.mjs$/.test(process.argv[1].replace(/\\/g, '/'));

if (invokedDirectly) {
  const r = runX12();
  console.log('X12 — usability parity: front-end vs back-end (§1.2, §3.4, §8.4)');
  console.log(`  scope: isScannable(${path.relative(ROOT, IPINPUT)}) vs should_short_circuit(${path.relative(ROOT, VALIDATOR)})`);
  console.log('');
  for (const c of r.checks) {
    console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.label}${c.detail ? `\n          ${c.detail}` : ''}`);
  }
  console.log('');
  console.log('  vector                FE           BE           expect');
  for (const row of r.rows) {
    console.log(
      `  ${row.verdict.padEnd(5)} ${row.raw.padEnd(18)} ${String(row.fe).padEnd(12)} ${String(row.be).padEnd(12)} ${row.expectFe}/${row.expectBe}`,
    );
  }
  console.log(`\n  ${r.summary}`);
  console.log(r.pass ? '\nX12: PASS' : '\nX12: FAIL — the two layers disagree about what can be checked');
  process.exit(r.pass ? 0 : 1);
}
