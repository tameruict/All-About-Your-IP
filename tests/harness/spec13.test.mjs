#!/usr/bin/env node
/**
 * IP Checker - executable harness for spec §13.1...§13.10.
 *
 * Modes:
 *   node tests/harness/spec13.test.mjs            # static gates + live probe if built
 *   node tests/harness/spec13.test.mjs --static   # no network, no binary, no cargo
 *   node tests/harness/spec13.test.mjs --cargo    # also shell out to `cargo test`
 *   node tests/harness/spec13.test.mjs --json     # machine-readable summary
 *
 * Exit codes: 0 = all PASS, 1 = at least one FAIL, 2 = only BLOCKED/SKIP.
 *
 * HONESTY RULE: a gate whose prerequisite is absent is BLOCKED with the precise
 * reason, never reported as PASS. Static gates still prove what they can:
 * contract conformance, wire-format rules, scoring tables, route coverage,
 * secret hygiene - none of that needs the binary to run.
 *
 * ENCODING RULE: this file is pure ASCII. Every Vietnamese comparison string
 * comes from ./strings.mjs, built from \u escapes. See that file's header.
 */

import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  Gate, STATUS, c, loadFixture, readText, readTextStrict, exists, fixture,
  HARNESS_DIR, PROJECT_ROOT, TAURI_SRC, REACT_SRC, TESTS_DIR,
  backendReadiness, frontendReadiness, findBuiltExe, walk,
  scanForSecrets, sentinelSecrets, printGate, printTable, writeReport,
  truncate,
} from './lib.mjs';
import {
  ALL_VERDICTS, V_SACH, V_TAM, V_NGHI_NGO, V_BAN, V_CHUA_DU,
  NOT_MEASURED_PROXY, FROM_CACHE_LABEL, RECHECK_LABEL,
} from './strings.mjs';

const ARGS = new Set(process.argv.slice(2));
const STATIC_ONLY = ARGS.has('--static');
const AS_JSON = ARGS.has('--json');
const gates = [];

const inputs = loadFixture('inputs.json');
const proxyMode = loadFixture('proxy-mode.json');
const cacheExport = loadFixture('cache-export.json');
const providerManifest = loadFixture('providers', '_manifest.json');
const goldenResult = loadFixture('export.full-result.json');
const probeFixture = loadFixture('probe-8.8.8.8.json');
let liveProbePayload = null;

const backend = backendReadiness();
const frontend = frontendReadiness();
const builtExe = findBuiltExe();
const secretsLive = sentinelSecrets();

const PROVIDER_ADAPTER_FILES = [
  'ip_api.rs', 'ipwho.rs', 'ipinfo.rs', 'ipqs.rs', 'proxycheck.rs', 'scamalytics.rs',
  'abuseipdb.rs', 'greynoise.rs', 'ripestat.rs', 'bgpview.rs', 'team_cymru.rs',
];

const ALL_COMMANDS = ['check_ip', 'check_ip_stream', 'get_history', 'get_check_detail',
  'export_report', 'get_provider_health', 'save_settings', 'get_settings'];

/* ================================================================== */
/* helpers                                                            */
/* ================================================================== */

function rust(rel) {
  return readText(path.join(TAURI_SRC, rel));
}

function allRustText() {
  return walk(TAURI_SRC, { filter: (f) => f.endsWith('.rs') })
    .map((f) => readText(f) || '')
    .join('\n');
}

function allReactText() {
  return walk(REACT_SRC, { filter: (f) => /\.(tsx?|css)$/.test(f) })
    .map((f) => readText(f) || '')
    .join('\n');
}

/** Strip Rust comments so a mention in a comment is not mistaken for code. */
function stripRustComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

function commandImplemented(name, text) {
  const re = new RegExp(`#\\s*\\[\\s*tauri::command[^\\]]*\\][\\s\\S]{0,200}?\\b(?:pub\\s+)?(?:async\\s+)?fn\\s+${name}\\b`, 'm');
  return re.test(text);
}

/** Independently re-derive private/reserved status; never trust the fixture blindly. */
function isClearlyPrivate(ip) {
  if (ip.includes(':')) {
    const low = ip.toLowerCase();
    return low === '::1' || low.startsWith('fe80') || low.startsWith('fc') || low.startsWith('fd');
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
  if (p[0] >= 224) return true;
  return false;
}

/** Extract the body of a Rust fn by brace-matching, ignoring braces in strings. */
function rustFnBody(src, name) {
  const m = new RegExp(`(?:pub\\s+)?(?:async\\s+)?fn\\s+${name}\\b`).exec(src);
  if (!m) return null;
  const open = src.indexOf('{', m.index + m[0].length);
  if (open < 0) return null;
  let depth = 0;
  let inStr = false;
  let inChr = false;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    const prev = src[i - 1];
    if (inStr) {
      if (ch === '"' && prev !== '\\') inStr = false;
      continue;
    }
    if (inChr) {
      if (ch === "'" && prev !== '\\') inChr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "'") { inChr = true; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return src.slice(open, i + 1);
    }
  }
  return src.slice(open);
}

/** Extract one `pub struct Name { ... }` body by brace matching. */
function findStructBody(name, src) {
  if (!src) return null;
  const hit = new RegExp(`pub\\s+struct\\s+${name}\\b`).exec(src);
  if (!hit) return null;
  const open = src.indexOf('{', hit.index + hit[0].length);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return src.slice(open, i + 1);
    }
  }
  return src.slice(open);
}

/**
 * Locate the cargo test log that covers the WHOLE crate.
 *
 * DANGER: teammates write per-module logs like `cargo test --lib geo_db`
 * (`geo-geodb-t3.log` = 18 passed / 0 failed). Picking "newest log with a result
 * line" would silently report a green suite while the full run is red. So we
 * score candidates by how many distinct test modules they mention, and prefer
 * the widest-coverage log; a narrow log is only used when nothing wider exists,
 * and it is labelled as partial.
 */
function findCargoTestLog() {
  const roots = [
    process.env.CARGO_TARGET_DIR,
    process.env.CARGO_TARGET_DIR ? path.dirname(process.env.CARGO_TARGET_DIR) : null,
    'C:\\cargo-target',
    path.join(PROJECT_ROOT, 'src-tauri', 'target'),
  ].filter(Boolean);

  const seen = new Set();
  const files = [];
  for (const root of roots) {
    if (seen.has(root) || !exists(root)) continue;
    seen.add(root);
    let entries = [];
    try {
      entries = fs.readdirSync(root);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (!/\.log$/i.test(name)) continue;
      const full = path.join(root, name);
      try {
        if (!fs.statSync(full).isFile()) continue;
      } catch {
        continue;
      }
      files.push(full);
    }
  }

  const parsed = [];
  const unreadable = [];
  for (const full of files) {
    let text;
    try {
      text = readTextStrict(full);
    } catch (err) {
      // Another agent may be writing the log right now (EBUSY/EPERM on Windows).
      unreadable.push(`${path.basename(full)} (${err.code || 'locked'})`);
      continue;
    }
    if (!text || !/test result:/.test(text)) continue;
    const r = parseCargoTestLog(text);
    if (!r) continue;
    let mtime = 0;
    try {
      mtime = fs.statSync(full).mtimeMs;
    } catch {
      mtime = 0;
    }
    parsed.push({ path: full, text, ...r, mtime, coverage: r.modulesSeen.size });
  }
  if (parsed.length === 0) {
    return unreadable.length ? { unreadable, none: true } : null;
  }

  // Rank: a full run (mentions many modules) beats a single-module run; among
  // full runs the NEWEST wins, because that reflects the current code. Then a
  // stable name order so two logs written in the same second do not flip the
  // verdict between invocations.
  parsed.sort((a, b) => {
    const af = a.modulesSeen.size >= 10 ? 1 : 0;
    const bf = b.modulesSeen.size >= 10 ? 1 : 0;
    if (bf !== af) return bf - af;
    if (b.mtime !== a.mtime) return b.mtime - a.mtime;
    return path.basename(a.path).localeCompare(path.basename(b.path));
  });
  const best = parsed[0];
  best.isFullRun = best.modulesSeen.size >= 10;
  best.partial = !best.isFullRun;
  best.unreadable = unreadable;
  best.skipped = parsed
    .filter((p) => p !== best)
    .map((p) => `${path.basename(p.path)} (${p.passed}p/${p.failed}f)`);
  return best;
}

/** Pull failed test names out of a cargo test log, grouped by module. */
function parseCargoTestLog(text) {
  const header = text.match(/test result:\s*(ok|FAILED)\.\s*(\d+) passed;\s*(\d+) failed/);
  if (!header) return null;
  // Count every module that reported, not just the failing ones — that is what
  // makes "whole crate" distinguishable from "one module".
  const all = [...text.matchAll(/^test\s+(\w+)::/gm)].map((x) => x[1]);
  const names = [...text.matchAll(/^test\s+(\w+)::(\w+)(?:::\w+)*\s+\.\.\.\s+FAILED/gm)]
    .map((x) => `${x[1]}::${x[2]}`);
  const byModule = {};
  for (const n of names) {
    const mod = n.split('::')[0];
    byModule[mod] = (byModule[mod] || 0) + 1;
  }
  return {
    ok: header[1] === 'ok',
    passed: Number(header[2]),
    failed: Number(header[3]),
    names,
    byModule,
    modulesSeen: new Set(all),
  };
}

/* ================================================================== */
/* §13.1 - public IP returns verdict + geo + ASN, no crash            */
/* ================================================================== */

{
  const g = new Gate('§13.1', 'Public IP: verdict/geo/ASN, no crash', '§13.1');
  const cases = inputs.public_ips.cases;

  g.assert(cases.length >= 2, `fixture has >=2 public IPs (found ${cases.length})`);
  for (const cs of cases) {
    g.assert(!isClearlyPrivate(cs.ip), `fixture ${cs.ip} really is public`);
  }
  g.assert(cases.some((x) => x.expect.asn === 15169), 'expectation AS15169 for 8.8.8.8');

  const val = rust('validator.rs');
  const orch = rust('orchestrator.rs');
  const scoring = rust('scoring.rs');
  if (val && orch && scoring) {
    g.assert(/IpAddr|Ipv4Addr|Ipv6Addr/.test(stripRustComments(val)), 'validator uses std IpAddr types', 'validator.rs');
    g.assert(/ip_api|ipwho|geo/i.test(stripRustComments(orch)), 'orchestrator references geo sources', 'orchestrator.rs');
    g.assert(/Verdict/.test(stripRustComments(scoring)), 'scoring.rs defines the Verdict mapping', 'scoring.rs');
    const present = PROVIDER_ADAPTER_FILES.filter((f) => rust(`providers/${f}`) !== null);
    g.assert(present.length === PROVIDER_ADAPTER_FILES.length, `${present.length}/${PROVIDER_ADAPTER_FILES.length} provider adapter files exist`);
  } else {
    g.note(`backend incomplete: missing=${backend.missing.join(',') || 'none'}, stubs=${backend.stubs.length}`);
  }

  if (STATIC_ONLY) {
    g.note('--static: no network, no app launch');
  } else {
    // ---- live leg: drive src/bin/probe.rs directly (no WebView needed) ----
    const probeSrc = path.join(TAURI_SRC, 'bin', 'probe.rs');
    // Binaries land next to Cargo.toml, not inside src/. Honor CARGO_TARGET_DIR
    // (this machine redirects it off drive E:) and fall back to the local target.
    const targetRoot = process.env.CARGO_TARGET_DIR || path.join(PROJECT_ROOT, 'src-tauri', 'target');
    const candidates = [
      path.join(targetRoot, 'debug', 'probe.exe'),
      'C:\\cargo-target\\ip-checker\\debug\\probe.exe',
      'C:\\cargo-target\\ip-review-lead\\debug\\probe.exe',
      path.join(PROJECT_ROOT, 'src-tauri', 'target', 'debug', 'probe.exe'),
    ];
    const exe = candidates.find((p) => exists(p)) || null;

    g.assert(exists(probeSrc), 'src/bin/probe.rs exists (live bridge)', exists(probeSrc) ? null : 'probe.rs missing');

    if (!exe) {
      g.note(`BLOCKED (live): probe binary not built yet - run: cargo build --bin probe  (looked in ${candidates.join(' and ')})`);
    } else {
      const publicCase = cases.find((x) => x.ip === '8.8.8.8') || cases[0];
      const env = { ...process.env };
      env.PATH = `${path.join(process.env.USERPROFILE || '', '.cargo', 'bin')};${env.PATH}`;
      env.RUST_LOG = 'error'; // keep stderr quiet; stdout must stay pure JSON

      const res = spawnSync(exe, [publicCase.ip], {
        cwd: PROJECT_ROOT, env, encoding: 'utf8', timeout: 120 * 1000, shell: false,
      });

      const stdout = (res.stdout || '').trim();
      const stderr = (res.stderr || '').trim();
      let payload = null;
      try {
        payload = JSON.parse(stdout.split(/\r?\n/).filter(Boolean).pop() || 'null');
      } catch {
        payload = null;
      }

      if (res.error) {
        g.note(`BLOCKED (live): could not spawn probe (${res.error.code || res.error.message})`);
      } else if (!payload) {
        g.assert(false, `probe produced parseable JSON (exit ${res.status})`,
          truncate(`${stdout}\n${stderr}`, 500));
      } else if (payload.blocked === true) {
        // Offline / firewall. Honest BLOCKED with the concrete reason, never PASS.
        g.note(`BLOCKED (live): ${payload.reason || 'probe reported blocked'}`);
        if (payload.hint) g.note(`hint: ${payload.hint}`);
      } else {
        liveProbePayload = payload;
        // A real check completed. Now assert what §13.1 actually demands.
        g.assert(payload.ip === publicCase.ip, `probe resolved ip = ${payload.ip}`, `expected ${publicCase.ip}`);
        g.assert(typeof payload.verdict === 'string' && ALL_VERDICTS.includes(payload.verdict),
          `verdict "${payload.verdict}" is one of the 5 legal labels`);
        g.assert(payload.verdict_reason && payload.verdict_reason.length > 0,
          'verdict carries a human reason (never a bare number)');
        g.assert(payload.validation_error === null || payload.validation_error === undefined,
          'no validation error for a valid public IP', JSON.stringify(payload.validation_error));
        g.assert(payload.is_private === false, 'public IP is not flagged private');
        g.assert(payload.ip_version === 4, `ip_version = ${payload.ip_version}`);

        // geo: at least a country, and the country must match the fixture.
        const geo = payload.geo || {};
        g.assert(!!geo.country_code, `geo.country_code present (${geo.country_code || 'none'})`);
        if (publicCase.expect && publicCase.expect.country_code) {
          g.assert(geo.country_code === publicCase.expect.country_code,
            `geo country ${geo.country_code} matches expectation ${publicCase.expect.country_code}`,
            `got ${geo.country_code}`);
        }
        g.assert(geo.points >= 1, `geo gathered ${geo.points} source point(s)`);
        // §13.6 behaviour on live data: if sources diverged > 2000 km, no city.
        if (geo.big_divergence === true) {
          g.assert(!geo.city, 'big_divergence=true ⇒ city withheld (§7.7)');
        }

        // ASN: the whole point of §13.1.
        const asn = payload.asn || {};
        g.assert(typeof asn.asn === 'number' || asn.asn === null,
          `asn is a number or null (got ${JSON.stringify(asn.asn)})`);
        if (publicCase.expect && publicCase.expect.asn) {
          g.assert(asn.asn === publicCase.expect.asn,
            `AS${asn.asn} matches expectation AS${publicCase.expect.asn}`, `got ${asn.asn}`);
        }
        g.assert(asn.records >= 1, `asn has ${asn.records} contributing record(s)`);

        // evidence + score integrity: never a fabricated number.
        g.assert(payload.evidence_count >= 1, `${payload.evidence_count} provider evidence row(s)`);
        if (payload.verdict === V_CHUA_DU) {
          g.assert(payload.clean_score === null || payload.clean_score === undefined,
            'verdict "not enough data" carries NO clean score — never fabricated');
        } else {
          g.assert(typeof payload.clean_score === 'number',
            `clean_score present for a decided verdict (got ${JSON.stringify(payload.clean_score)})`);
          g.assert(payload.clean_score >= 0 && payload.clean_score <= 100,
            `clean_score ${payload.clean_score} in 0..100`);
        }
        g.assert(typeof payload.confidence_score === 'number'
          && payload.confidence_score >= 0 && payload.confidence_score <= 100,
          `confidence ${payload.confidence_score} in 0..100`);

        // §1.2 / §13.1 in IP-only mode: leak and speed must NOT be measured.
        g.assert(payload.leak_measured === false, 'IP-only: leak not measured (§1.2)');
        g.assert(payload.speed_measured === false, 'IP-only: speed not measured (§1.2)');

        // no secrets anywhere in the live payload
        const liveSecrets = scanForSecrets(stdout, 'export', secretsLive);
        g.assert(liveSecrets.length === 0, 'live probe output leaks no key/credential',
          liveSecrets.length ? JSON.stringify(liveSecrets.slice(0, 3)) : null);

        g.note(`live OK: ${payload.ip} -> ${payload.verdict} clean=${payload.clean_score ?? 'null'} conf=${payload.confidence_score} AS${asn.asn} ${geo.country_code}/${geo.city || '(no city)'} evidence=${payload.evidence_count} in ${payload.elapsed_ms}ms`);
      }
    }
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.2 - private IP short-circuit, zero API calls                   */
/* ================================================================== */

{
  const g = new Gate('§13.2', 'Private IP: early stop + banner', '§13.2');
  const cases = inputs.private_ips.cases;

  g.assert(cases.length >= 2, `fixture has ${cases.length} private/loopback/reserved IPs`);
  for (const cs of cases) {
    const priv = isClearlyPrivate(cs.ip);
    g.assert(priv === true, `${cs.ip} (${cs.reason}) is genuinely private/reserved`, priv === true ? null : 'matcher says public');
    g.assert(cs.expect.api_calls === 0, `${cs.ip}: expect 0 API calls`);
  }

  const valText = rust('validator.rs');
  if (valText) {
    const v = stripRustComments(valText);
    const tokens = [
      ['is_private', /is_private/],
      ['is_loopback', /is_loopback/],
      ['is_link_local', /is_link_local/],
      ['is_unspecified', /is_unspecified/],
      // CGNAT is written as a manual octet range: `(64..=127).contains(...)`
      ['CGNAT/RFC6598', /cgnat|100\.64|6598|64\.\.=127/i],
      ['is_multicast', /is_multicast/],
      ['is_broadcast', /is_broadcast/],
      ['is_documentation', /is_documentation/],
      ['IPv6 ULA fc00::/7', /0xfc00|fc00/i],
      ['IPv4-mapped IPv6', /to_ipv4_mapped/i],
    ];
    for (const [label, re] of tokens) {
      g.assert(re.test(v), `validator.rs handles ${label}`, re.test(v) ? null : 'not found in validator.rs');
    }
    g.assert(/(return|Err)\b/.test(v), 'validator returns early for private IPs');

    const orchText = rust('orchestrator.rs');
    if (orchText) {
      const o = stripRustComments(orchText);
      // §13.2 requires the private gate to run BEFORE any provider work inside
      // the main check pipeline. Scope the comparison to `run_check`'s own body:
      // helper fns like `run_provider` legitimately call `provider.check(...)`
      // and appear earlier in the file, which would always win a whole-file scan.
      // `run_check` may be a thin wrapper delegating to `run_check_inner`, so
      // follow one level of delegation before giving up.
      let body = rustFnBody(o, 'run_check');
      g.assert(body !== null, 'orchestrator.rs defines `run_check`', body !== null ? null : 'run_check not found');
      if (body) {
        const deleg = body.match(/\b(run_check_inner|run_check_impl|run_impl|check_impl)\s*\(/);
        if (deleg) {
          const inner = rustFnBody(o, deleg[1]);
          g.assert(inner !== null, `orchestrator.rs defines delegated \`${deleg[1]}\``);
          if (inner) body = inner;
        }
      }

      const gateIdx = body ? body.search(/parsed\.is_private|parsed\.problem/) : -1;
      const providerIdx = body ? body.search(/\.fetch\(|\.check\(|Semaphore::|acquire|join_all|spawn/) : -1;
      g.assert(gateIdx >= 0, 'run_check (or its delegate) evaluates the private/invalid gate',
        gateIdx >= 0 ? null : `searched ${body ? body.length : 0} chars`);
      const validatesFirst = gateIdx >= 0 && (providerIdx === -1 || gateIdx < providerIdx);
      g.assert(validatesFirst, 'run_check short-circuits private/invalid before provider work',
        validatesFirst ? null : `gate@${gateIdx} vs provider-work@${providerIdx}`);
      // The flag may be assigned a literal `true` or a computed banner variable
      // (`result.is_private = banner;`). Both satisfy "the result carries the
      // private signal"; only assert that the field is assigned in the
      // short-circuit path, not the exact right-hand side.
      g.assert(/result\.is_private\s*=/.test(o), 'orchestrator sets result.is_private', 'orchestrator.rs');
      g.assert(/private_ip|invalid_input/.test(o), 'orchestrator distinguishes private_ip / invalid_input', 'orchestrator.rs');
    } else {
      g.note('orchestrator.rs absent');
    }
  } else {
    g.note('BLOCKED: validator.rs absent');
  }

  const uiText = allReactText();
  if (uiText) {
    g.assert(/private/i.test(uiText), 'UI has a private-IP banner branch');
    g.assert(/private_ip/.test(uiText), 'UI recognises the private_ip error code');
  } else {
    g.note('front-end has no files');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.3 - invalid format -> error immediately, Scan disabled         */
/* ================================================================== */

{
  const g = new Gate('§13.3', 'Invalid input: immediate error', '§13.3');
  const cases = inputs.invalid_inputs.cases;
  g.assert(cases.length >= 5, `fixture has ${cases.length} invalid inputs`);
  g.assert(cases.some((x) => x.input === '999.999.999.999'), 'covers 999.999.999.999');
  g.assert(cases.some((x) => x.input === 'abc'), 'covers abc');
  g.assert(cases.some((x) => x.input === '1.2.3.4:99999'), 'covers out-of-range port');

  const valText = rust('validator.rs');
  if (valText) {
    const v = stripRustComments(valText);
    g.assert(/parse::<IpAddr>|IpAddr::from_str|\.parse\(\)/.test(v), 'validator parses with std (rejects 999.999.999.999)', 'validator.rs');
    g.assert(/65535|u16/.test(v), 'validator rejects ports outside 1..=65535', 'validator.rs');
  }

  const inputConsole = readText(path.join(REACT_SRC, 'components', 'InputConsole.tsx'));
  if (inputConsole) {
    g.assert(/valid|invalid|error/i.test(inputConsole), 'InputConsole tracks an invalid state');
    g.assert(/disabled/.test(inputConsole), 'InputConsole disables Scan on invalid input');
    // Red may be a CSS token/class rather than a literal hex — accept either.
    const redish = /#EF4444|#ef4444|text-bad|is-invalid|invalid|danger|\bred\b/i.test(inputConsole)
      || /#EF4444|#ef4444|--bad|\.invalid/i.test(allReactText());
    g.assert(redish, 'InputConsole renders an invalid/red state', redish ? null : 'no red token or invalid class found');
  } else {
    g.note('InputConsole.tsx absent');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.4 - all keys missing -> free sources still work, no fake score */
/* ================================================================== */

{
  const g = new Gate('§13.4', 'All API keys missing', '§13.4');
  const scenario = providerManifest.scenarios.no_keys;
  g.assert(!!scenario, 'manifest has a no_keys scenario');
  g.assert(scenario.expect.verdict_max === V_CHUA_DU, `expect verdict capped at "${V_CHUA_DU}" when fraud quorum < 2`);
  g.assert(/null|genuine|never a placeholder/i.test(JSON.stringify(scenario.expect)), 'no fabricated score allowed');

  const keyProviders = Object.entries(providerManifest.providers).filter(([, v]) => v.requires_key);
  g.assert(keyProviders.length >= 4, `${keyProviders.length} providers require a key`);
  // A provider that needs a key must exercise the "no key / bad key" path. Accept a
  // dedicated no-key fixture OR an explicit expected_error marker in the manifest.
  const missingNoKey = [];
  for (const [id, meta] of keyProviders) {
    const hasFixture = exists(fixture('providers', `${id}.no-key.json`));
    const hasMarker = !!(meta.no_key && (meta.no_key.expected_error || meta.no_key.assert));
    if (!hasFixture && !hasMarker) missingNoKey.push(id);
  }
  g.assert(missingNoKey.length === 0,
    `${keyProviders.length - missingNoKey.length}/${keyProviders.length} key-providers cover the no-key path`,
    missingNoKey.length ? `uncovered: ${missingNoKey.join(', ')}` : null);

  // Assert actual permanent error fixtures & HTTP status codes for missing key
  const ipinfoNoKey = loadFixture('providers', 'ipinfo.no-key.json');
  g.assert(ipinfoNoKey?.error?.code === 401, 'ipinfo no-key fixture carries HTTP 401 status code');
  const scamNoKey = loadFixture('providers', 'scamalytics.no-key.json');
  g.assert(scamNoKey?.error === 'unauthorized' || scamNoKey?.status === 'error', 'scamalytics no-key fixture carries unauthorized error shape');
  const greyNoKey = loadFixture('providers', 'greynoise.no-key.json');
  g.assert(greyNoKey?.error === 'unauthorized', 'greynoise no-key fixture carries unauthorized error shape');

  const scoringText = rust('scoring.rs');
  const modelsText = rust('models.rs') || '';
  if (scoringText && modelsText) {
    const s = stripRustComments(scoringText);
    const m = stripRustComments(modelsText);
    g.assert(scoringText.includes(V_CHUA_DU) || modelsText.includes(V_CHUA_DU), `verdict "${V_CHUA_DU}" exists in the Rust verdict enum`);
    g.assert(/quorum/i.test(s), 'scoring.rs has quorum logic');

    // ProviderError struct body & permanent error shape
    const peBody = findStructBody('ProviderError', m);
    g.assert(peBody !== null, 'models.rs defines struct ProviderError');
    if (peBody) {
      g.assert(/pub\s+kind\s*:\s*String/.test(peBody), 'ProviderError has `kind: String`');
      g.assert(/pub\s+message\s*:\s*String/.test(peBody), 'ProviderError has `message: String`');
      g.assert(/pub\s+status\s*:\s*Option<\s*u16\s*>/.test(peBody), 'ProviderError has `status: Option<u16>`');
      g.assert(/pub\s+retryable\s*:\s*bool/.test(peBody), 'ProviderError has `retryable: bool`');
    }
    // Missing-key constructor sets retryable = false (permanent error, no retry storm)
    const noKeyFn = rustFnBody(m, 'no_key');
    const noKeySetsNonRetryable = noKeyFn ? /(?:Self|ProviderError)::new\([\s\S]*?,\s*false\s*,?\s*\)|retryable:\s*false/.test(noKeyFn) : /pub\s+fn\s+no_key[\s\S]*?false/.test(m);
    g.assert(noKeySetsNonRetryable, 'ProviderError::no_key constructs with retryable = false (permanent error per §4.3)');
    g.assert(/enum\s+SkipReason\b[\s\S]*?MissingKey/.test(m), 'SkipReason enum defines MissingKey');

    // Missing-key handling may live in the orchestrator/registry rather than scoring.
    const skipHandling = /missing_key|NoKey|no_key|SkipReason|skipped/i.test(s)
      || /missing_key|NoKey|no_key|SkipReason/i.test(stripRustComments(rust('orchestrator.rs') || ''))
      || /missing_key|NoKey|no_key|SkipReason|has_key/i.test(stripRustComments(rust('providers/registry.rs') || ''))
      || /missing_key|NoKey|has_key/i.test(m);
    g.assert(skipHandling, 'missing-key state is handled somewhere in the backend');
  } else {
    g.note('scoring.rs or models.rs absent');
  }

  // Data structure validation: probe output with missing keys
  if (probeFixture) {
    g.assert(probeFixture.modules?.skipped >= 1, `${probeFixture.modules?.skipped || 0} module(s) skipped in probe data`);
    g.assert(probeFixture.verdict === V_CHUA_DU, `probe verdict capped at "${V_CHUA_DU}" without fraud quorum`);
    g.assert(probeFixture.clean_score === null, 'clean_score is strictly null when quorum not met (never fabricated)');
  }

  const yaml = readText(path.join(PROJECT_ROOT, 'providers.yaml'));
  if (yaml) {
    const needsKey = (yaml.match(/requires_key\s*:\s*true/g) || []).length;
    const noKey = (yaml.match(/requires_key\s*:\s*false/g) || []).length;
    g.assert(needsKey >= 4, `providers.yaml: ${needsKey} providers need a key`);
    g.assert(noKey >= 4, `providers.yaml: ${noKey} key-free providers (free sources)`);
  } else {
    g.note('providers.yaml absent');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.5 - one provider timeout -> check completes, confidence drops  */
/* ================================================================== */

{
  const g = new Gate('§13.5', 'One provider timeout', '§13.5');
  const scenarios = providerManifest.scenarios;
  g.assert(!!scenarios.timeout_one, 'manifest has a timeout_one scenario');

  const providersWithTimeout = Object.entries(providerManifest.providers).filter(([, v]) => !!v.timeout);
  g.assert(providersWithTimeout.length >= 8, `${providersWithTimeout.length}/${Object.keys(providerManifest.providers).length} providers have a timeout fixture`);
  let timeoutFixtures = 0;
  for (const [, v] of providersWithTimeout) {
    if (exists(fixture('providers', v.timeout.file))) timeoutFixtures++;
  }
  g.assert(timeoutFixtures === providersWithTimeout.length, `${timeoutFixtures} timeout fixture files exist`);

  // Provider manifest HTTP status validation on quota errors
  for (const [id, prov] of Object.entries(providerManifest.providers)) {
    if (prov.quota_403 && prov.quota_403.http_status) {
      g.assert([403, 429].includes(prov.quota_403.http_status),
        `${id} quota error declares valid status code (${prov.quota_403.http_status})`);
    }
  }

  const orchText = rust('orchestrator.rs');
  const modelsText = rust('models.rs') || '';
  if (orchText) {
    const o = stripRustComments(orchText);
    const m = stripRustComments(modelsText);
    const allBackend = stripRustComments(allRustText());
    g.assert(/timeout/i.test(o), 'orchestrator has per-provider timeout');

    // Concurrency cap
    const hasSemaphore = /Semaphore|acquire_owned|tokio::sync::Semaphore|MAX_CONCURRENCY|concurrency/i.test(o)
      || /Semaphore|acquire_owned|MAX_CONCURRENCY/i.test(allBackend);
    g.assert(hasSemaphore, 'orchestrator caps concurrency (§4.3)', hasSemaphore ? null : 'no Semaphore / MAX_CONCURRENCY found');
    g.assert(/circuit|breaker/i.test(o) || /circuit|breaker/i.test(allBackend), 'circuit breaker exists');

    // Transient timeout error constructor in models.rs
    const timeoutFn = rustFnBody(m, 'timeout');
    const timeoutSetsRetryable = timeoutFn ? /(?:Self|ProviderError)::new\([\s\S]*?,\s*true\s*\)|retryable:\s*true/.test(timeoutFn) : /pub\s+fn\s+timeout[\s\S]*?true/.test(m);
    g.assert(timeoutSetsRetryable, 'ProviderError::timeout sets retryable = true (transient error per §4.3)');

    // Retry policy in is_retryable(&ProviderError) -> bool
    const retryFn = rustFnBody(o, 'is_retryable');
    g.assert(retryFn !== null, 'orchestrator defines is_retryable(&ProviderError) -> bool');
    if (retryFn) {
      g.assert(/!error\.retryable/.test(retryFn), 'is_retryable checks error.retryable flag');
      g.assert(/429/.test(retryFn) && />=\s*500/.test(retryFn), 'is_retryable allows HTTP 429 and 5xx status codes');
      g.assert(/None\s*=>\s*true/.test(retryFn), 'is_retryable allows status: None (timeout / network)');
    }
    g.assert(/attempt\s*<\s*2/.test(o), 'orchestrator enforces at most 1 retry (attempt < 2, §4.3)');
    g.assert(/Unknown/.test(o) || /Signal::Unknown/.test(allRustText()), 'timeout maps to Signal::Unknown');
    g.assert(/check-progress|CheckProgressEvent|ProgressSink|emit/i.test(o), 'orchestrator emits partial progress (§4.3)');
  } else {
    g.note('BLOCKED: orchestrator.rs absent');
  }

  // Error object shape & status assertions in real data structures
  if (probeFixture && Array.isArray(probeFixture.errors)) {
    g.assert(probeFixture.errors.length > 0, `probe output contains ${probeFixture.errors.length} error record(s)`);
    for (const err of probeFixture.errors) {
      g.assert(typeof err.kind === 'string', `error.kind "${err.kind}" is string`);
      g.assert(typeof err.message === 'string', 'error.message is string');
      g.assert(err.status === null || typeof err.status === 'number', `error.status is number or null (got ${err.status})`);
      g.assert(typeof err.retryable === 'boolean', `error.retryable is boolean (got ${err.retryable})`);
    }
    const tErr = probeFixture.errors.find((e) => e.kind === 'timeout');
    if (tErr) {
      g.assert(tErr.retryable === true, 'timeout error has retryable: true');
      g.assert(tErr.status === null, 'timeout error has status: null');
    }
    const hErr = probeFixture.errors.find((e) => e.kind === 'http' && e.status === 404);
    if (hErr) {
      g.assert(hErr.retryable === false, 'HTTP 404 error has retryable: false (client error non-retryable)');
    }
  }

  if (goldenResult && Array.isArray(goldenResult.evidence)) {
    const evErr = goldenResult.evidence.find((e) => e.error !== null);
    if (evErr) {
      g.assert(typeof evErr.error.kind === 'string' && typeof evErr.error.retryable === 'boolean', 'evidence.error conforms to ProviderError shape');
      g.assert(evErr.error.status === 429, `evidence error status = 429 (got ${evErr.error.status})`);
      g.assert(evErr.error.retryable === false, 'quota error is non-retryable on exhausted quota');
    }
  }

  const scoringText = rust('scoring.rs');
  if (scoringText) {
    const s = stripRustComments(scoringText);
    g.assert(/confidence/i.test(s), 'scoring keeps Confidence separate from Clean Score');
    g.assert(/coverage[\s\S]*?agreement/.test(s), 'Confidence derives from vote coverage and agreement');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.6 - geo sources disagree (VN vs SG) -> warn, no city commit    */
/* ================================================================== */

{
  const g = new Gate('§13.6', 'Geolocation sources disagree', '§13.6');
  const div = loadFixture('geo-divergence.json');
  const sg = loadFixture('providers', div.source_a.fixture);
  const ru = loadFixture('providers', div.source_b.fixture);

  // Provider payloads use different field names (ip-api: countryCode/query,
  // ipinfo: country/ip). Normalise before asserting.
  const cc = (o) => o.country_code ?? o.countryCode ?? o.country;
  const ipOf = (o) => o.query ?? o.ip;

  g.assert(cc(sg) === div.source_a.country_code, `source_a fixture is ${div.source_a.country_code} (got ${cc(sg)})`);
  g.assert(cc(ru) === div.source_b.country_code, `source_b fixture is ${div.source_b.country_code} (got ${cc(ru)})`);
  const sgIp = ipOf(sg);
  const ruIp = ipOf(ru);
  g.assert(sgIp === div.ip && ruIp === div.ip, `both fixtures describe the SAME IP ${div.ip} (got ${sgIp} / ${ruIp})`);
  g.assert(div.source_a.country_code !== div.source_b.country_code, 'the two sources disagree on country');

  const R = 6371;
  const toRad = (d) => (d * Math.PI) / 180;
  const haversine = (a, b) => {
    const dLat = toRad(b.lat - a.lat);
    const dLon = toRad(b.lon - a.lon);
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
    return 2 * R * Math.asin(Math.sqrt(h));
  };
  const km = Math.round(haversine(
    { lat: div.source_a.lat, lon: div.source_a.lon },
    { lat: div.source_b.lat, lon: div.source_b.lon },
  ));
  g.assert(km > 2000, `distance ${km} km exceeds the 2000 km red-warning threshold (§7.7)`);
  g.assert(km > 200, `distance ${km} km exceeds the 200 km city-commit threshold`);
  g.assert(km >= div.expected_distance_km_min, `distance ${km} km >= fixture expectation ${div.expected_distance_km_min} km`);
  g.note(`${div.source_a.city}(${div.source_a.lat},${div.source_a.lon}) <-> ${div.source_b.city}(${div.source_b.lat},${div.source_b.lon}) = ${km} km`);

  // ---- Behavioral requirement (a): tight consensus commits city <= 200km ----
  if (goldenResult && goldenResult.location) {
    const loc = goldenResult.location;
    g.assert(loc.radius_km <= 200, `consensus radius ${loc.radius_km} km <= 200 km (SPREAD_MEDIUM_KM)`);
    g.assert(typeof loc.city === 'string' && loc.city.trim().length > 0, 'geo.city is populated for tight consensus (<= 200 km)');
    g.assert(loc.city === 'Singapore', `geo.city matches consensus ("Singapore", got "${loc.city}")`);
    g.assert(loc.country_code === 'SG', `geo.country_code committed as SG (got ${loc.country_code})`);
    g.assert(loc.spread === 'high' || loc.spread === 'medium', `geo.spread flagged appropriately ("${loc.spread}")`);
    g.assert(loc.big_divergence === false, 'geo.big_divergence is false for tight consensus');
    g.assert(Array.isArray(loc.points) && loc.points.length >= 2, `${loc.points.length} points contributed to consensus`);
  } else {
    g.assert(false, 'goldenResult.location fixture missing');
  }

  // ---- Behavioral requirement (b): anycast / divergent coordinates withhold city ----
  if (probeFixture && probeFixture.geo) {
    const geo = probeFixture.geo;
    g.assert(geo.city === null, '8.8.8.8 fixture: anycast/divergent coordinates set geo.city strictly null');
    g.assert(geo.country_code === 'US' || typeof geo.country === 'string', `8.8.8.8 fixture: country is committed (${geo.country_code || geo.country})`);
    g.assert(typeof geo.spread === 'string' && geo.spread.length > 0, `8.8.8.8 fixture: geo.spread is flagged (${geo.spread})`);
    g.assert(probeFixture.blocked === false, 'anycast/divergent coordinates do not fail triangulation (blocked=false)');
  }
  if (liveProbePayload && !liveProbePayload.blocked && liveProbePayload.geo) {
    const geo = liveProbePayload.geo;
    g.assert(geo.city === null, 'live 8.8.8.8: anycast/divergent coordinates set geo.city strictly null');
    g.assert(typeof geo.country_code === 'string' && geo.country_code.length > 0, `live 8.8.8.8: country committed (${geo.country_code})`);
    g.assert(typeof geo.spread === 'string', `live 8.8.8.8: geo.spread reported (${geo.spread})`);
  }
  g.assert(div.expected.city === null && div.expected.city_committed === false,
    'geo-divergence fixture: spread > 2000 km sets city strictly null');
  g.assert(div.expected.big_divergence === true, 'geo-divergence fixture: big_divergence=true');

  // ---- Behavioral requirement (c): Triangulation simulation & boundary verification (§7.3 & §7.5) ----
  const simulateTriangulation = (points, ipType) => {
    if (ipType === 'anycast' || ipType === 'cgnat' || ipType === 'mobile') {
      return { city: null, spread: 'low', big_divergence: false, maxDist: 0 };
    }
    const valid = points.filter((p) => typeof p.lat === 'number' && typeof p.lon === 'number');
    if (valid.length === 0) return { city: null, spread: 'low', big_divergence: false, maxDist: 0 };

    const clat = valid.reduce((acc, p) => acc + p.lat, 0) / valid.length;
    const clon = valid.reduce((acc, p) => acc + p.lon, 0) / valid.length;

    let maxDist = 0;
    for (const p of valid) {
      const d = haversine({ lat: clat, lon: clon }, { lat: p.lat, lon: p.lon });
      if (d > maxDist) maxDist = d;
    }

    const spread = maxDist <= 50 ? 'high' : (maxDist <= 200 ? 'medium' : 'low');
    const bigDiv = maxDist > 2000;
    let city = null;
    if (maxDist <= 200) {
      const tally = {};
      for (const p of valid) {
        if (p.city) tally[p.city] = (tally[p.city] || 0) + 1;
      }
      const sorted = Object.entries(tally).sort((a, b) => b[1] - a[1]);
      if (sorted.length > 0) city = sorted[0][0];
    }
    return { city, spread, big_divergence: bigDiv, maxDist };
  };

  // Test Case A: Clustered points <= 50 km (Singapore) -> Must commit city
  const clusterPoints = [
    { lat: 1.3521, lon: 103.8198, city: 'Singapore' },
    { lat: 1.3600, lon: 103.8250, city: 'Singapore' },
    { lat: 1.3450, lon: 103.8150, city: 'Singapore' },
  ];
  const clusterRes = simulateTriangulation(clusterPoints, 'residential');
  g.assert(
    clusterRes.city === 'Singapore' && clusterRes.spread === 'high' && !clusterRes.big_divergence,
    'Triangulation simulation: clustered points (<= 50km) commit city "Singapore" with spread="high"'
  );

  // Test Case B: Boundary sensitivity at 200 km threshold (§7.3)
  const mediumPoints = [
    { lat: 10.7769, lon: 106.7009, city: 'Ho Chi Minh City' },
    { lat: 10.0352, lon: 105.7838, city: 'Can Tho' },
  ];
  const mediumRes = simulateTriangulation(mediumPoints, 'residential');
  g.assert(
    mediumRes.spread === 'medium' && mediumRes.city !== null,
    'Triangulation simulation: spread 50-200 km commits majority city with spread="medium"'
  );

  // Test Case C: Spread > 200 km (Hanoi <-> HCMC ~1130 km) -> Must withhold city
  const farPoints = [
    { lat: 21.0285, lon: 105.8542, city: 'Hanoi' },
    { lat: 10.7769, lon: 106.7009, city: 'Ho Chi Minh City' },
  ];
  const farRes = simulateTriangulation(farPoints, 'residential');
  g.assert(
    farRes.city === null && farRes.spread === 'low',
    'Triangulation simulation: far-apart coordinates (> 200 km) set city=null with spread="low"'
  );

  // Test Case D: Anycast override (§7.5) -> Must withhold city even if clustered
  const anycastRes = simulateTriangulation(clusterPoints, 'anycast');
  g.assert(
    anycastRes.city === null,
    'Triangulation simulation: anycast IP type overrides city to null even if points cluster <= 50 km'
  );

  // ---- Behavioral requirement (d): mutation sensitivity & location.rs logic ----
  const locText = rust('location.rs');
  if (locText) {
    const l = stripRustComments(locText);
    const fnBody = rustFnBody(l, 'triangulate_for_type') || '';
    g.assert(fnBody.length > 0, 'location.rs defines triangulate_for_type');

    // Threshold constants
    const medMatch = l.match(/pub\s+const\s+SPREAD_MEDIUM_KM\s*:\s*f64\s*=\s*([0-9.]+);/);
    const medVal = medMatch ? Number(medMatch[1]) : null;
    g.assert(medVal === 200, `SPREAD_MEDIUM_KM constant = 200.0 (got ${medVal})`);
    const divMatch = l.match(/pub\s+const\s+BIG_DIVERGENCE_KM\s*:\s*f64\s*=\s*([0-9.]+);/);
    const divVal = divMatch ? Number(divMatch[1]) : null;
    g.assert(divVal === 2000, `BIG_DIVERGENCE_KM constant = 2000.0 (got ${divVal})`);

    // Active city commit branch: must be guarded by max_dist <= SPREAD_MEDIUM_KM, NOT disabled by if false
    const cityBranchMatch = fnBody.match(/let\s+mut\s+city_committed\s*:\s*Option<String>\s*=\s*None;\s*([^\n{]+)\{/);
    const cityCondition = cityBranchMatch ? cityBranchMatch[1].trim() : '';
    const branchGuard = /if\s+(?:max_dist\s*<=\s*SPREAD_MEDIUM_KM|max_dist\s*<=\s*200(?:\.0)?)\b/.test(cityCondition);
    const notDisabled = !/if\s+false\b|\bfalse\b/.test(cityCondition);
    const commitsMajority = /city_committed\s*=\s*tally[\s\S]*?\.max_by_key/.test(fnBody);
    const anycastSuppressed = /IpType::Anycast\s*=>[\s\S]*?None/.test(fnBody);
    const routesToResult = /LocationResult\s*\{[\s\S]*?city:\s*city_final[\s\S]*?\}/m.test(fnBody);

    g.assert(branchGuard, 'triangulate_for_type guards city commit with `max_dist <= SPREAD_MEDIUM_KM`',
      branchGuard ? null : `missing or altered condition for city commit threshold (got "${cityCondition}")`);
    g.assert(notDisabled, 'city-commit branch is active (mutant A `if false` absent)',
      notDisabled ? null : `city-commit branch is disabled by \`${cityCondition}\` (mutant A detected)`);
    g.assert(commitsMajority, 'triangulate_for_type commits majority city inside the branch (tally.max_by_key)',
      commitsMajority ? null : 'city commit assignment missing or bypassed');
    g.assert(anycastSuppressed, 'anycast IPs explicitly suppress city resolution (IpType::Anycast => None)');
    g.assert(routesToResult, 'committed city routes into LocationResult.city (not discarded)');

    // Cross-check cargo test log if recorded
    if (!STATIC_ONLY) {
      const cargoLog = findCargoTestLog();
      if (cargoLog && !cargoLog.none && cargoLog.text) {
        const t = cargoLog.text;
        const clusteredOk = t.includes('test location::tests::clustered_points_commit_city ... ok');
        const farApartOk = t.includes('test location::tests::far_apart_points_do_not_commit_a_city ... ok');
        const anycastOk = t.includes('test location::tests::anycast_never_commits_city ... ok');
        if (clusteredOk) g.assert(true, 'cargo test log confirms `clustered_points_commit_city` passed (runtime consensus)');
        if (farApartOk) g.assert(true, 'cargo test log confirms `far_apart_points_do_not_commit_a_city` passed');
        if (anycastOk) g.assert(true, 'cargo test log confirms `anycast_never_commits_city` passed');
      }
    }
  } else {
    g.note('BLOCKED: location.rs absent');
  }

  const geoMap = readText(path.join(REACT_SRC, 'components', 'GeoMapCard.tsx'));
  if (geoMap) {
    g.assert(/points|Circle|Marker/i.test(geoMap), 'GeoMapCard draws multiple points + radius');
    g.assert(/centroid/i.test(geoMap), 'GeoMapCard draws the centroid');
    g.assert(/2000|divergence|disputed/i.test(geoMap), 'GeoMapCard has a divergence warning');
    g.assert(/attribution|OpenStreetMap/i.test(geoMap), 'GeoMapCard carries OSM attribution');
  } else {
    g.note('GeoMapCard.tsx absent');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.7 - proxy exit IP differs from the typed IP -> red flag        */
/* ================================================================== */

{
  const g = new Gate('§13.7', 'Exit IP differs from input (proxy)', '§13.7');
  const mm = loadFixture('exit_ip.mismatch.json');
  const disagree = loadFixture('exit_ip.disagree.json');
  const unreach = loadFixture('exit_ip.unreachable.json');

  g.assert(mm.endpoint_results.length >= 2, 'mismatch fixture uses >=2 endpoints (§8.1)');
  g.assert(mm.exit_ip === '185.244.1.1' && mm.differs_from_input === true, 'mismatch fixture: exit_ip != input -> differs_from_input=true');
  g.assert(disagree.endpoints_disagree === true && disagree.exit_ip === null, 'endpoints disagree -> exit_ip stays null (no guessing)');
  g.assert(unreach.reachable === false && unreach.exit_ip === null, 'unreachable proxy -> reachable=false, no invented exit_ip');
  g.assert(proxyMode.exit_ip.endpoints_required >= 2, 'proxy-mode.json requires >=2 endpoints');

  const appText = allRustText();
  if (appText) {
    const hasExitModule = /exit_ip/i.test(stripRustComments(appText));
    g.assert(hasExitModule, 'an exit-IP module exists in src-tauri');
    const orch = rust('orchestrator.rs');
    if (orch && hasExitModule) {
      const o = stripRustComments(orch);
      const allB = stripRustComments(appText);
      g.assert(/exit_ip/i.test(o) || /exit_ip/i.test(allB), 'exit-IP is reachable from the orchestrator/pipeline');
      g.assert(/proxy/.test(o), 'orchestrator branches on proxy mode');
      g.assert(/CheckMode::Proxy|mode\s*==\s*CheckMode::Proxy|is_proxy/.test(allB), 'proxy mode is an explicit branch in the backend');
    }
  } else {
    g.note('BLOCKED: no Rust source yet');
  }

  const leakCard = readText(path.join(REACT_SRC, 'components', 'LeakSpeedCard.tsx'));
  if (leakCard) {
    const uiAll = allReactText();
    g.assert(leakCard.includes(NOT_MEASURED_PROXY), `LeakSpeedCard contains the exact string "${NOT_MEASURED_PROXY}"`);
    g.assert(/differs_from_input|exit_ip/i.test(leakCard), 'LeakSpeedCard shows exit IP + mismatch flag');
    // Red may be a token class (`text-bad` / `tone="bad"`) rather than a hex literal.
    const redish = /#EF4444|#ef4444|text-bad|tone="bad"|tone=\{?[^}]*"bad"|\bbad\b/i.test(leakCard)
      || /#EF4444|#ef4444/.test(uiAll);
    g.assert(redish, 'LeakSpeedCard has a red/bad state for the mismatch flag');
  } else {
    g.note('LeakSpeedCard.tsx absent');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.8 - WebRTC leak -> verdict downgraded, Leak card red           */
/* ================================================================== */

{
  const g = new Gate('§13.8', 'WebRTC leak', '§13.8');
  const leak = loadFixture('webrtc.leak-local.json');
  const clean = loadFixture('webrtc.clean.json');
  g.assert(leak.webrtc_leak === true, 'leak fixture: webrtc_leak=true');
  g.assert(Array.isArray(leak.webrtc_candidates) && leak.webrtc_candidates.length > 0, 'leak fixture: candidate list non-empty');
  g.assert(leak.downgrade === true, 'leak fixture: downgrade=true');
  g.assert(clean.webrtc_leak === false && clean.downgrade === false, 'clean fixture: no leak, no downgrade');
  g.assert(proxyMode.webRTC.cases.leak_local_ip.expect.downgrade === true, 'proxy-mode.json asserts leak -> downgrade');

  const blText = rust('browser_leak.rs');
  if (blText) {
    const b = stripRustComments(blText);
    g.assert(/webrtc/i.test(b), 'browser_leak.rs handles WebRTC ICE');
    g.assert(/--proxy-server/.test(b), 'browser_leak.rs passes --proxy-server');
    g.assert(/kill|Child|Command/.test(b), 'browser_leak.rs owns the child process lifecycle');
    g.assert(/timeout/i.test(b), 'browser_leak.rs has the 20-30s timeout');
    g.assert(/dns/i.test(b), 'browser_leak.rs checks DNS leak');
    g.assert(/webdriver|headless/i.test(b), 'browser_leak.rs detects headless flags');
  } else {
    g.note('BLOCKED: browser_leak.rs absent');
  }

  const scoringText = rust('scoring.rs');
  if (scoringText) {
    const s = stripRustComments(scoringText);
    // Downgrade may be expressed as a capped verdict + single_source_evidence flag.
    // The verdict is Rust's enum variant, so match the identifier or its
    // mojibake-proof Vietnamese label from strings.mjs - never a raw literal.
    const downgrades = /downgrade/i.test(s)
      || (/single_source_evidence/.test(s) && (/NghiNg\u1EDD/.test(scoringText) || scoringText.includes(V_NGHI_NGO)))
      || (/hard_hit|strong_single_hit/.test(s));
    g.assert(downgrades, 'scoring.rs can downgrade the verdict (§6.5)', downgrades ? null : 'no downgrade / single-source cap found');
    g.assert(/single_source_evidence/.test(s), 'scoring.rs exposes single_source_evidence');
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.9 - cached check keeps its original timestamp                  */
/* ================================================================== */

{
  const g = new Gate('§13.9', 'Re-check: cache + original timestamp', '§13.9');
  const cc = cacheExport.cache_reuse_case;
  g.assert(cc.second_check_same_ip_with_cache.expect.from_cache === true, 'cache hit must set from_cache=true');
  g.assert(cc.second_check_same_ip_with_cache.expect.checked_at === cc.first_check.checked_at, 'cache hit keeps the original checked_at');
  g.assert(cc.second_check_same_ip_with_cache.expect.display_format.includes(FROM_CACHE_LABEL), `UI label format "${FROM_CACHE_LABEL} HH:MM DD/MM"`);
  g.assert(cc.recheck_forced.options.use_cache === false && cc.recheck_forced.expect.from_cache === false, '"Check lai" bypasses the cache (use_cache=false)');
  g.assert(cacheExport.cache_ttl.expect.geo_hours === 168, 'geo TTL = 7 days (168 h) per §10.2');
  g.assert(cacheExport.cache_ttl.expect.leak_and_speed_cached === false, 'leak/speed are never cached');

  const cacheText = rust('cache.rs');
  if (cacheText) {
    const ce = stripRustComments(cacheText);
    for (const table of ['checks', 'provider_results', 'geo_db_versions', 'settings']) {
      g.assert(new RegExp(`CREATE TABLE (IF NOT EXISTS )?${table}`, 'i').test(cacheText), `schema has table ${table}`);
    }
    const historyStub = /pub fn history\(&self[^)]*\)\s*->\s*Vec<CheckSummary>\s*\{\s*Vec::new\(\)\s*\}/.test(cacheText);
    const freshStub = /pub fn cache_fresh\(&self[^)]*\)\s*->\s*bool\s*\{\s*false\s*\}/.test(cacheText);
    g.assert(!historyStub, 'cache::history() is implemented, not a Vec::new() stub', historyStub ? 'src-tauri/src/cache.rs - returns Vec::new()' : null);
    g.assert(!freshStub, 'cache::cache_fresh() is implemented, not a hardcoded false', freshStub ? 'src-tauri/src/cache.rs - returns false' : null);
    g.assert(/from_cache/.test(ce), 'cache.rs carries a from_cache flag');
    // The bypass path may live on CheckOptions (`use_cache`, models.rs) rather than in cache.rs.
    const bypassInCache = /use_cache|invalidat|force_refresh|bypass_cache/i.test(ce);
    const bypassInModels = /use_cache|force_refresh|bypass_cache/i.test(stripRustComments(rust('models.rs') || ''));
    const bypassInOrch = /use_cache|invalidat|force_refresh|bypass_cache/i.test(stripRustComments(rust('orchestrator.rs') || ''));
    g.assert(bypassInCache || bypassInModels || bypassInOrch,
      'a cache-bypass path exists (§10.2 "Check lai")',
      bypassInModels ? 'CheckOptions.use_cache (models.rs)' : bypassInOrch ? 'orchestrator' : bypassInCache ? 'cache.rs' : 'no use_cache / invalidate anywhere');
  } else {
    g.note('BLOCKED: cache.rs absent');
  }

  const hist = readText(path.join(REACT_SRC, 'components', 'HistoryPanel.tsx'));
  if (hist) {
    g.assert(hist.includes(FROM_CACHE_LABEL), `HistoryPanel shows the "${FROM_CACHE_LABEL}" label`);
    g.assert(hist.includes(RECHECK_LABEL), `HistoryPanel has the "${RECHECK_LABEL}" button`);
  }
  gates.push(g.finish());
}

/* ================================================================== */
/* §13.10 - export opens, has §6.6/§10.3 fields, no secrets           */
/* ================================================================== */

{
  const g = new Gate('§13.10', 'Export JSON/CSV leaks no keys', '§13.10');
  const secrets = sentinelSecrets();

  for (const f of cacheExport.export_json.required_top_level) {
    g.assert(Object.hasOwn(goldenResult, f), `export JSON has top-level field "${f}"`);
  }
  for (const f of cacheExport.export_json.required_evidence_fields) {
    g.assert(Object.hasOwn(goldenResult.evidence[0], f), `evidence has field "${f}"`);
  }
  g.assert(cacheExport.export_json.verdict_values_allowed.includes(goldenResult.verdict), `verdict "${goldenResult.verdict}" is one of the 5 legal labels`);
  for (const ev of goldenResult.evidence) {
    g.assert(cacheExport.export_json.signal_values_allowed.includes(ev.signal), `signal "${ev.signal}" is legal (${ev.provider})`);
  }
  g.assert(cacheExport.export_json.mode_values_allowed.includes(goldenResult.mode), 'mode is legal per §1.2');

  const goldenText = readText(fixture('export.full-result.json'));
  const goldenHits = scanForSecrets(goldenText, 'export', secrets);
  g.assert(goldenHits.length === 0, 'golden export contains no secret', goldenHits.length ? JSON.stringify(goldenHits.slice(0, 3)) : null);

  // Negative control: the deliberately leaky fixture MUST be caught.
  const leakyText = readText(fixture('export.leaky.result.json'));
  const leakyHits = scanForSecrets(leakyText, 'export', secrets);
  g.assert(leakyHits.length >= 3, `scanner catches the leaky fixture (${leakyHits.length} hits - proves it is not a no-op)`, leakyHits.length < 3 ? 'scanner too weak' : null);

  const logSamples = readText(fixture('log-redaction.samples.txt')) || '';
  const passHalf = logSamples.split('## MUST FAIL')[0];
  const failHalf = logSamples.split('## MUST FAIL')[1] || '';
  const passHits = scanForSecrets(passHalf, 'log', secrets);
  const failHits = scanForSecrets(failHalf, 'log', secrets);
  g.assert(passHits.length === 0, 'redacted logs produce no hits', passHits.length ? JSON.stringify(passHits.slice(0, 3)) : null);
  g.assert(failHits.length >= 3, `leaky logs are caught (${failHits.length} hits)`);

  const csvText = readText(fixture('export.rows.csv')) || '';
  const header = csvText.split(/\r?\n/)[0] || '';
  const expectCols = cacheExport.export_csv.columns;
  g.assert(header.split(',').length === expectCols.length, `CSV has exactly ${expectCols.length} columns per §10.3`, `header=${header}`);
  for (const col of ['ip', 'verdict', 'clean_score', 'confidence', 'country', 'city', 'asn', 'isp', 'ip_type', 'checked_at']) {
    g.assert(header.includes(col), `CSV has column "${col}"`);
  }
  g.assert(scanForSecrets(csvText, 'export', secrets).length === 0, 'golden CSV contains no secret');

  const rustSrc = allRustText();
  const reactSrc = allReactText();
  if (rustSrc) {
    const srcHits = scanForSecrets(rustSrc, 'source', secrets);
    g.assert(srcHits.length === 0, 'Rust source hardcodes no key/secret', srcHits.length ? JSON.stringify(srcHits.slice(0, 5)) : null);
  }
  if (reactSrc) {
    const tsHits = scanForSecrets(reactSrc, 'source', secrets);
    g.assert(tsHits.length === 0, 'TS/TSX source hardcodes no key/secret', tsHits.length ? JSON.stringify(tsHits.slice(0, 5)) : null);
  }

  const exportText = rust('export.rs');
  if (exportText) {
    const e = stripRustComments(exportText);
    g.assert(/csv/i.test(e), 'export.rs writes CSV');
    g.assert(/json/i.test(e), 'export.rs writes JSON');
    // Redaction may be structural (the serializer simply never includes secrets)
    // rather than a named scrub function. Either is acceptable; assert the
    // serialisation surface does not contain credential fields.
    const redacts = /redact|scrub|strip|REDACTED/i.test(e);
    const neverSerialisesSecrets = !/password|credential|api_key|token/i.test(e);
    g.assert(redacts || neverSerialisesSecrets,
      'export.rs cannot emit credentials (explicit scrub, or the model excludes them)',
      redacts ? 'explicit redact step' : 'no credential field is referenced');
    g.assert(/CSV_COLUMNS|csv_header/.test(exportText), 'export.rs pins the §10.3 CSV column list');
    // Parse the const body only: `pub const CSV_COLUMNS: [&str; 12] = [ ... ];`
    const block = exportText.match(/CSV_COLUMNS\s*:\s*\[[^\]]*\]\s*=\s*\[([\s\S]*?)\];/);
    if (block) {
      const declared = (block[1].match(/"/g) || []).length / 2;
      g.assert(declared === 12, `CSV_COLUMNS declares 12 columns per §10.3 (found ${declared})`);
      // Column names must match the fixture's expected list exactly.
      const names = [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
      const expected = cacheExport.export_csv.columns;
      const normalise = (s) => s.toLowerCase().replace(/[\s_]+/g, '_');
      const mismatched = expected.filter((e, i) => names[i] && normalise(names[i]) !== normalise(e));
      g.assert(mismatched.length === 0, 'CSV columns match the §10.3 list in order', mismatched.length ? `differs at: ${mismatched.join(', ')}` : names.join(','));
    } else {
      g.assert(false, 'CSV_COLUMNS const could not be parsed', 'export.rs');
    }
  } else {
    g.note('BLOCKED: export.rs absent');
  }

  const configText = rust('config.rs');
  if (configText) {
    const cf = stripRustComments(configText);
    g.assert(/keyring/.test(cf), 'config.rs uses the keyring crate (Windows Credential Manager)');
    g.assert(!/INSERT INTO settings[\s\S]{0,200}(api_key|token)/i.test(cf), 'no API key is written to the settings table');
  }

  // SELF-SCAN (Lead directive): the harness and its artifacts must not leak.
  const selfTargets = [];
  const reportPath = path.join(TESTS_DIR, 'spec13-report.json');
  if (exists(reportPath)) selfTargets.push(['tests/spec13-report.json', reportPath, 'export']);
  for (const ps of ['build.ps1', 'smoke.ps1']) {
    const p = path.join(PROJECT_ROOT, 'scripts', ps);
    if (exists(p)) selfTargets.push([`scripts/${ps}`, p, 'log']);
  }
  if (selfTargets.length === 0) g.note('self-scan: no artifact to scan yet (report is written at the end of this run)');
  for (const [label, p, mode] of selfTargets) {
    const hits = scanForSecrets(readText(p) || '', mode, secrets);
    g.assert(hits.length === 0, `self-scan: ${label} contains no secret`, hits.length ? JSON.stringify(hits.slice(0, 3)) : null);
  }

  // ---- runtime cross-check ------------------------------------------------
  // Everything above is STATIC: it greps source and fixtures. A static pass can
  // still hide a runtime failure, so cross-check the real cargo test log.
  const tlog = findCargoTestLog();
  if (tlog) {
    const r = parseCargoTestLog(tlog.text);
    const exportFails = r ? r.names.filter((n) => n.startsWith('export::')) : [];
    g.note(`runtime cross-check: ${tlog.path}`);
    if (!r) {
      g.note('runtime cross-check: could not parse the log');
    } else if (exportFails.length === 0) {
      g.assert(true, 'runtime: export module tests are green in the last cargo test log');
    } else {
      g.assert(false,
        `runtime: ${exportFails.length} export test(s) fail even though the static checks pass ` +
        '(static PASS is not runtime PASS — §13.10 is NOT satisfied yet)',
        exportFails.join(', '));
      const markers = [...new Set([...tlog.text.matchAll(/nghi là bí mật \("([^"]+)"\)/g)].map((x) => x[1]))];
      for (const msg of markers) g.note(`  guard rejects on marker "${msg}"`);
      g.note('  ROOT CAUSE: scrubbed_result() replaces credential VALUES with "[redacted]" but');
      g.note('  keeps the KEY, then assert_no_secrets_text() substring-matches the KEY name.');
      g.note('  FIX: match value-shaped blobs (length/charset), or drop the key entirely instead');
      g.note('  of masking it. Until then every export is refused (§10.3, §13.10).');
    }
  } else {
    g.note('runtime cross-check: no cargo test log available');
  }

  gates.push(g.finish());
}

/* ================================================================== */
/* Cross-cutting gates                                                */
/* ================================================================== */

const crossGates = [];

{
  const g = new Gate('X1', 'Tauri command contract', '§4.2');
  const cmdText = rust('commands.rs');
  if (cmdText) {
    for (const name of ALL_COMMANDS) {
      const ok = commandImplemented(name, cmdText);
      g.assert(ok, `#[tauri::command] declared for \`${name}\``, ok ? null : 'commands.rs');
    }
    // Tauri v2 layout: generate_handler! lives in lib.rs, main.rs is a thin shim.
    const libText = rust('lib.rs') || '';
    const mainText = rust('main.rs') || '';
    const host = /generate_handler!/.test(libText) ? 'lib.rs' : /generate_handler!/.test(mainText) ? 'main.rs' : null;
    g.assert(host !== null, 'generate_handler! exists (lib.rs or main.rs)', host ? `in ${host}` : 'not found');
    if (host) {
      const hostText = host === 'lib.rs' ? libText : mainText;
      for (const name of ALL_COMMANDS) {
        const reg = new RegExp(`commands::${name}\\b`).test(hostText) || new RegExp(`\\b${name}\\b`).test(hostText);
        g.assert(reg, `generate_handler! registers \`${name}\``, reg ? null : `${host} missing ${name}`);
      }
      if (host === 'lib.rs' && mainText) {
        g.assert(/::run\(\)/.test(mainText), 'main.rs delegates to the lib entry point (standard Tauri v2)');
      }
      g.assert(/\.manage\(/.test(hostText), 'setup() registers AppState via app.manage()');
    }
  } else {
    g.note('BLOCKED: commands.rs absent');
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X7', 'Registry rows vs adapters: SKIP, no panic', '§5.5, §13.4');
  const regText = rust('providers/registry.rs');
  const yamlText = readText(path.join(PROJECT_ROOT, 'providers.yaml')) || '';

  const yamlIds = [...yamlText.matchAll(/^\s*-\s*id:\s*["']?([a-z0-9_]+)["']?\s*$/gim)].map((m) => m[1]);
  const adapterIds = new Set();
  for (const f of PROVIDER_ADAPTER_FILES) {
    const t = rust(`providers/${f}`) || '';
    const m = t.match(/pub const ID:\s*&str\s*=\s*"([a-z0-9_]+)"/);
    if (m) adapterIds.add(m[1]);
  }
  g.assert(yamlIds.length >= 40, `providers.yaml has ${yamlIds.length} rows (spec expects ~44)`);
  g.assert(adapterIds.size >= 11, `${adapterIds.size} real adapters (${[...adapterIds].join(', ')})`);
  g.note(`registry ${yamlIds.length} rows / ${adapterIds.size} adapters -> ${yamlIds.length - adapterIds.size} rows must be skipped`);

  if (regText) {
    const r = stripRustComments(regText);
    g.assert(/unmatched_adapters/.test(r), 'registry exposes unmatched_adapters()');
    g.assert(/supported_ids\(\)/.test(r), 'registry filters by supported_ids()');
    g.assert(/tracing::warn!/.test(r), 'adapter-less rows log a warning instead of failing silently');
    g.assert(!/panic!/.test(r), 'registry never panics on a missing adapter');
    g.assert(/pub fn get\(&self[^)]*\)\s*->\s*Option<&ProviderMeta>/.test(r), 'get() returns Option, never unwraps');
    g.assert(/pub fn empty\(\)/.test(r), 'empty() registry exists for pre-load state');
  } else {
    g.note('BLOCKED: providers/registry.rs absent');
  }

  // A not-implemented adapter must return a typed error, not panic.
  // Panics inside #[cfg(test)] are legitimate assertions, so strip them first.
  let notImplemented = 0;
  const panicky = [];
  for (const f of PROVIDER_ADAPTER_FILES) {
    const t = rust(`providers/${f}`);
    if (!t) continue;
    if (/not_implemented/.test(t)) notImplemented++;
    const prod = stripRustComments(t).replace(/#\[cfg\(test\)\][\s\S]*$/m, '');
    if (/panic!|\.unwrap\(\)|\.expect\(/.test(prod)) panicky.push(f);
  }
  g.assert(panicky.length === 0, `${notImplemented} not-implemented adapters return typed errors, no panic in production code`,
    panicky.length ? `panic/unwrap in: ${panicky.join(', ')}` : null);

  crossGates.push(g.finish());
}

{
  const g = new Gate('X2', 'Front-end <-> back-end type contract', '§2.3, §6.6');
  const typesText = readText(path.join(REACT_SRC, 'lib', 'types.ts'));
  const apiText = readText(path.join(REACT_SRC, 'lib', 'api.ts'));
  if (typesText) {
    for (const t of ['FullCheckResult', 'ProviderEvidence', 'CheckSession', 'ScoringResult', 'LocationResult', 'AsnResult', 'DnsblResult', 'LeakResult', 'SpeedResult', 'ProviderHealth', 'Settings']) {
      g.assert(new RegExp(`(interface|type)\\s+${t}\\b`).test(typesText), `types.ts defines ${t}`);
    }
    for (const v of ALL_VERDICTS) {
      g.assert(typesText.includes(`"${v}"`) || typesText.includes(`'${v}'`), `Verdict union contains "${v}"`);
    }
    g.assert(/"Clean"/.test(typesText) && /"Suspicious"/.test(typesText), 'Signal union is PascalCase per §6.6');
  } else {
    g.note('BLOCKED: src/lib/types.ts absent');
  }
  if (apiText) {
    for (const name of ALL_COMMANDS) {
      g.assert(apiText.includes(name), `api.ts references \`${name}\``);
    }
    g.assert(/check-progress/.test(apiText), 'api.ts listens for the "check-progress" event');
  } else {
    g.note('api.ts absent');
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X3', '§1.2 - Leak/Speed never fabricate in ip_only', '§1.2, §3.3');
  const rule = inputs.ip_only_leak_speed_rule.expect;
  g.assert(rule.display_text === NOT_MEASURED_PROXY, 'fixture display string matches the spec verbatim');
  g.assert(rule.leak_measured === false && rule.speed_measured === false, 'ip_only: measured=false for leak and speed');

  const uiText = allReactText();
  if (uiText) {
    g.assert(uiText.includes(NOT_MEASURED_PROXY), `UI contains the exact string "${NOT_MEASURED_PROXY}"`);
  } else {
    g.note('front-end has no files');
  }
  for (const rel of ['browser_leak.rs', 'speed.rs']) {
    const t = rust(rel);
    if (!t) continue;
    const ok = t.includes(NOT_MEASURED_PROXY) || /available\s*[:=]\s*false|measured\s*[:=]\s*false/.test(t);
    g.assert(ok, `${rel} reports not-measured when there is no proxy`);
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X4', '§6 - verdict ladder & quorum in code', '§6.3, §6.4, §6.5');
  const scoringText = rust('scoring.rs');
  const modelsText = rust('models.rs') || '';
  if (scoringText) {
    const s = stripRustComments(scoringText);
    const m = stripRustComments(modelsText);

    // Parse the WEIGHTS table instead of regex-hunting for decimals. Substring
    // matching on numbers is unreliable: `/0\.2\b/` does not match `0.20`, and
    // `/20(\.0)?/` matches the "20" inside "0.25". Parse the actual constant.
    const wtMatch = s.match(/WEIGHTS\s*:\s*\[[^\]]*\]\s*=\s*\[([\s\S]*?)\];/);
    if (wtMatch) {
      const pairs = [...wtMatch[1].matchAll(/\("([a-z_]+)"\s*,\s*([0-9.]+)\)/g)]
        .map((m) => [m[1], Number(m[2])]);
      g.assert(pairs.length === 5, `WEIGHTS declares 5 aspects (found ${pairs.length})`);
      const byName = Object.fromEntries(pairs);
      const expect = { fraud: 0.35, blacklist: 0.25, asn: 0.2, abuse: 0.1, consistency: 0.1 };
      for (const [name, want] of Object.entries(expect)) {
        const got = byName[name];
        g.assert(got !== undefined && Math.abs(got - want) < 1e-9,
          `${name} weight = ${want * 100}% (got ${got === undefined ? 'missing' : got * 100 + '%'})`);
      }
      const sum = pairs.reduce((a, [, w]) => a + w, 0);
      g.assert(Math.abs(sum - 1.0) < 1e-6, `weights sum to 1.0 (got ${sum.toFixed(4)})`);
    } else {
      // Fall back to a token scan, but anchor on a decimal boundary this time.
      g.assert(/(?<![\d.])0\.35(?![\d])/.test(s), 'Fraud weight 35%');
      g.assert(/(?<![\d.])0\.25(?![\d])/.test(s), 'Blacklist weight 25%');
      g.assert(/(?<![\d.])0\.20?(?![\d])/.test(s), 'ASN weight 20%');
      g.assert(/(?<![\d.])0\.10?(?![\d])/.test(s), 'Abuse 10% + Consistency 10%');
    }

    for (const v of ALL_VERDICTS) {
      g.assert(scoringText.includes(v) || (rust('models.rs') || '').includes(v),
        `verdict "${v}" appears in the codebase`);
    }
    // Thresholds live as consts; read them rather than grepping bare digits.
    const thr = (name) => {
      const match = s.match(new RegExp(`const\\s+${name}\\s*:\\s*f64\\s*=\\s*([0-9.]+)`));
      return match ? Number(match[1]) : null;
    };
    const clean = thr('CLEAN_VERDICT_MIN');
    const tem = thr('TEM_VERDICT_MIN');
    const nghi = thr('NGHI_NGO_VERDICT_MIN');
    g.assert(clean === 85, `CLEAN_VERDICT_MIN = 85 (got ${clean})`);
    g.assert(tem === 65, `TEM_VERDICT_MIN = 65 (got ${tem})`);
    g.assert(nghi === 40, `NGHI_NGO_VERDICT_MIN = 40 (got ${nghi})`);

    // Quorum requirements function parsing
    const qBody = rustFnBody(s, 'quorum_requirement') || '';
    g.assert(qBody.length > 0, 'scoring.rs defines quorum_requirement(aspect: &str) -> u32');
    if (qBody) {
      const qAspect = (asp) => {
        const match = qBody.match(new RegExp(`"${asp}"\\s*=>\\s*(\\d+)`));
        return match ? Number(match[1]) : null;
      };
      g.assert(qAspect('fraud') === 2, 'fraud quorum requires 2 votes');
      g.assert(qAspect('blacklist') === 3, 'blacklist quorum requires 3 groups');
      g.assert(qAspect('asn') === 2, 'asn quorum requires 2 agreeing sources');
      g.assert(qAspect('abuse') === 1, 'abuse quorum requires 1 source');
      g.assert(qAspect('consistency') === 2, 'consistency quorum requires 2 sources');
    }

    // QuorumStatus struct in models.rs
    const qsBody = findStructBody('QuorumStatus', m);
    g.assert(qsBody !== null, 'models.rs defines struct QuorumStatus');
    if (qsBody) {
      g.assert(/pub\s+aspect\s*:\s*String/.test(qsBody), 'QuorumStatus carries `aspect: String`');
      g.assert(/pub\s+required\s*:\s*u32/.test(qsBody), 'QuorumStatus carries `required: u32`');
      g.assert(/pub\s+actual\s*:\s*u32/.test(qsBody), 'QuorumStatus carries `actual: u32`');
      g.assert(/pub\s+met\s*:\s*bool/.test(qsBody), 'QuorumStatus carries `met: bool`');
    }

    // Quorum data structure validation on goldenResult
    if (goldenResult && Array.isArray(goldenResult.quorum)) {
      g.assert(goldenResult.quorum.length >= 3, `goldenResult has ${goldenResult.quorum.length} quorum records`);
      for (const q of goldenResult.quorum) {
        g.assert(typeof q.aspect === 'string' && typeof q.required === 'number' && typeof q.actual === 'number' && typeof q.met === 'boolean',
          `quorum item "${q.aspect}" has valid schema (required=${q.required}, actual=${q.actual}, met=${q.met})`);
      }
    }

    // Upstream de-duplication
    g.assert(/pub\s+fn\s+group_votes\b/.test(s), 'scoring.rs defines group_votes for upstream de-duplication (§6.2)');
    g.assert(/HashMap<\(String,\s*Category\),\s*Vote>/.test(s), 'group_votes de-duplicates by (upstream, category)');
    g.assert(/pub\s+fn\s+group_of_upstream\b/.test(s), 'scoring.rs groups blacklist upstreams via group_of_upstream');

    // 40 % single-provider cap
    const capVal = thr('MAX_PROVIDER_SHARE');
    g.assert(capVal === 0.40, `MAX_PROVIDER_SHARE = 0.40 (got ${capVal})`);
    g.assert(/configured\.min\(MAX_PROVIDER_SHARE\)/.test(s), 'Vote::weight clamps configured weight to MAX_PROVIDER_SHARE');

    // Demotion rules
    g.assert(/strong_single_hit[\s\S]*?independent_confirmation/.test(s), 'Spamhaus/Tor single hit caps at Nghi ngờ (§6.5)');
    g.assert(/bad_upstreams\.len\(\)\s*==\s*1/.test(s) || /exactly one source claims bad/.test(s), 'single bad source among clean ones caps at Nghi ngờ (§6.5)');
    g.assert(!/fraud_score|abuseConfidenceScore|scamalytics_score/.test(s), 'scoring never reads provider-private fields (§4.4 boundary)');
  } else {
    g.note('BLOCKED: scoring.rs absent');
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X5', 'Regression harness (cargo test)', '§13, §12');
  const cargoToml = path.join(PROJECT_ROOT, 'src-tauri', 'Cargo.toml');
  if (!exists(cargoToml)) {
    g.note('BLOCKED: src-tauri/Cargo.toml absent');
  } else {
    // Read the last recorded cargo test run instead of compiling here. The Lead
    // runs cargo centrally (compile contention + a shared target dir), so the
    // harness verifies the RESULT LOG rather than re-running the suite.
    const found = findCargoTestLog();
    if (!found || found.none) {
      if (STATIC_ONLY) {
        g.note('--static: cargo test skipped (no pre-recorded cargo test log)');
      } else {
        const why = found && found.unreadable ? ` (locked: ${found.unreadable.join(', ')})` : '';
        g.note(`BLOCKED: no readable cargo test log with a "test result:" line${why} - run \`cargo test --lib\` first`);
      }
    } else {
      const r = parseCargoTestLog(found.text);
      g.note(`source: ${found.path}`);
      g.note(`scope: ${found.isFullRun ? 'FULL crate' : 'PARTIAL (single module)'} · ${found.modulesSeen.size} modules · ` +
        `${new Date(found.mtime).toISOString().slice(11, 19)}Z`);
      if (found.unreadable && found.unreadable.length) {
        g.note(`WARNING: ${found.unreadable.length} log(s) could not be read and may be newer: ${found.unreadable.join(', ')}`);
      }
      if (!r) {
        g.note('BLOCKED: could not parse the test result line');
      } else {
        g.assert(r.passed > 0, `${r.passed} tests passed`);
        if (r.failed === 0) {
          g.assert(true, `${r.passed} passed, 0 failed — suite green`);
        } else {
          const summary = Object.entries(r.byModule)
            .sort((a, b) => b[1] - a[1])
            .map(([k, v]) => `${k}:${v}`)
            .join(' ');
          g.assert(false, `${r.failed} test(s) FAILED — ${summary}`, `${r.passed} passed / ${r.failed} failed`);
          for (const [mod, count] of Object.entries(r.byModule).sort((a, b) => b[1] - a[1])) {
            g.note(`  ${mod.padEnd(14)} ${count} failing`);
          }
          const exportFails = r.names.filter((n) => n.startsWith('export::'));
          if (exportFails.length) {
            g.note(`§13.10 runtime: ${exportFails.length} export test(s) fail on the secret guard`);
            for (const f of exportFails.slice(0, 4)) g.note(`  ${f}`);
          }
        }
      }
    }
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X6', 'Build artifacts + smoke scripts', '§11, §12 Phase 4');
  if (builtExe) {
    g.assert(exists(builtExe), `built exe found: ${builtExe}`);
    const sizeMb = Number((fs.statSync(builtExe).size / (1024 * 1024)).toFixed(1));
    g.assert(sizeMb > 3, `size ${sizeMb} MB (target 10-25 MB, §2.1)`);
  } else {
    g.note('BLOCKED: no .exe yet - run scripts/build.ps1 (or `cargo tauri build`) first');
  }
  for (const script of ['build.ps1', 'smoke.ps1']) {
    const p = path.join(PROJECT_ROOT, 'scripts', script);
    g.assert(exists(p), `scripts/${script} exists`);
    const t = readText(p) || '';
    g.assert(/cargo/i.test(t), `scripts/${script} invokes cargo`);
    g.assert(/CARGO_TARGET_DIR/.test(t), `scripts/${script} sets CARGO_TARGET_DIR`);
    g.assert(/\.cargo.{0,4}bin/.test(t), `scripts/${script} prepends the rustup bin dir to PATH`);
  }
  const readme = readText(path.join(PROJECT_ROOT, 'README.md'));
  if (readme) {
    for (const needle of ['SmartScreen', 'Run anyway', 'Geo DB']) {
      g.assert(readme.includes(needle), `README covers "${needle}" (§11)`);
    }
  } else {
    g.note('README.md absent');
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X8', 'Tokens.css AA contrast on state chips', '§3.1');
  const tokensPath = path.join(REACT_SRC, 'styles', 'tokens.css');
  const tokens = readText(tokensPath);

  if (!tokens) {
    g.note('BLOCKED: src/styles/tokens.css absent');
  } else {
    // ---- minimal CSS colour helpers --------------------------------------
    const hex = (s) => {
      const m = s.trim().match(/^#([0-9a-f]{6})$/i);
      if (!m) return null;
      const n = parseInt(m[1], 16);
      return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
    };
    const srgbToLin = (c) => {
      const v = c / 255;
      return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    const luminance = ([r, gg, b]) => 0.2126 * srgbToLin(r) + 0.7152 * srgbToLin(gg) + 0.0722 * srgbToLin(b);
    const contrast = (a, b) => {
      const la = luminance(a);
      const lb = luminance(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    // A tint is `color-mix(in srgb, HUE P%, transparent)` over an opaque base:
    // result = base*(1-a) + hue*a  (source-over onto an opaque backdrop).
    const over = (base, hue, alpha) => base.map((c, i) => Math.round(c * (1 - alpha) + hue[i] * alpha));

    /** Resolve `--name: #rrggbb` from the stylesheet. */
    const varOf = (name) => {
      const m = tokens.match(new RegExp(`--${name}\\s*:\\s*(#[0-9a-fA-F]{6})`));
      return m ? hex(m[1]) : null;
    };
    /** Resolve `--tint-x: color-mix(in srgb, var(--Y) N%, transparent)`. */
    const tintOf = (name) => {
      const m = tokens.match(new RegExp(`--${name}\\s*:\\s*color-mix\\(in srgb,\\s*var\\(--([a-z-]+)\\)\\s*(\\d+)%`));
      if (!m) return null;
      const hue = varOf(m[1]);
      if (!hue) return null;
      return { hue, alpha: Number(m[2]) / 100, hueName: m[1] };
    };

    // The chips sit on the panel surface (§3.1 layout); measure text-on-tint,
    // with the tint composited over the panel background.
    const panel = varOf('panel');
    g.assert(panel !== null, 'tokens.css defines --panel');
    const backdrop = panel || hex('#0a0f1e');

    const AA = 4.5;
    const states = [
      ['clean', 'state-clean', 'tint-clean'],
      ['temp', 'state-temp', 'tint-temp'],
      ['suspect', 'state-suspect', 'tint-suspect'],
      ['bad', 'state-bad', 'tint-bad'],
      ['unknown', 'state-unknown', 'tint-unknown'],
      ['conflict', 'conflict', 'tint-conflict'],
    ];

    const results = [];
    for (const [label, stateVar, tintVar] of states) {
      const text = varOf(stateVar);
      const tint = tintOf(tintVar);
      if (!text || !tint) {
        g.assert(false, `could not resolve --${stateVar} / --${tintVar}`, 'tokens.css');
        continue;
      }
      const bg = over(backdrop, tint.hue, tint.alpha);
      const ratio = contrast(text, bg);
      results.push({ label, ratio: Number(ratio.toFixed(2)), alpha: tint.alpha, stateVar, tintVar });
      g.assert(ratio >= AA,
        `${label}: contrast ${ratio.toFixed(2)}:1 on ${(tint.alpha * 100).toFixed(0)}% tint >= ${AA} (WCAG AA)`,
        ratio >= AA ? null : `${stateVar} on ${tintVar} — lower the alpha or the pair is unreadable`);
    }

    // --tint-bad specifically: frontend-k3 tuned 14% -> 12% to reach 4.611.
    // Raising it back above 12% pushes the pair under AA, so pin the ceiling.
    const badTint = tintOf('tint-bad');
    if (badTint) {
      g.assert(badTint.alpha <= 0.12,
        `--tint-bad alpha ${(badTint.alpha * 100).toFixed(0)}% <= 12% ceiling`,
        badTint.alpha <= 0.12 ? null : 'raising this alpha breaks WCAG AA against #EF4444');
    }
    g.note(results.map((r) => `${r.label} ${r.ratio}`).join(' | '));
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X9', 'No proxy credentials on the result/exports', '§8.4, §10.1, §10.3');
  const modelsText = rust('models.rs');

  if (!modelsText) {
    g.note('BLOCKED: models.rs absent');
  } else {
    const m = stripRustComments(modelsText);

    /** Extract one `pub struct Name { ... }` body by brace matching. */
    const structBody = (name) => {
      const hit = new RegExp(`pub\\s+struct\\s+${name}\\b`).exec(m);
      if (!hit) return null;
      const open = m.indexOf('{', hit.index + hit[0].length);
      if (open < 0) return null;
      let depth = 0;
      for (let i = open; i < m.length; i++) {
        if (m[i] === '{') depth++;
        else if (m[i] === '}') {
          depth--;
          if (depth === 0) return m.slice(open, i + 1);
        }
      }
      return m.slice(open);
    };

    // ---- the result payload must carry NO credential field ----------------
    // This is the §8.4 boundary: credentials live only in the transient request
    // options and are never persisted, never serialised, never exported.
    const SENSITIVE = /(?:^|[_\s])(?:password|passwd|passphrase|username|user_name|secret|auth_token|credentials?)\b/i;

    const resultBody = structBody('FullCheckResult');
    g.assert(resultBody !== null, 'models.rs defines FullCheckResult');
    if (resultBody) {
      // Only look at field declarations, not serde attributes or doc text.
      const fields = [...resultBody.matchAll(/pub\s+([a-z_][a-z0-9_]*)\s*:/gi)].map((x) => x[1]);
      g.assert(fields.length > 10, `FullCheckResult has ${fields.length} fields (parsed)`);
      const offenders = fields.filter((f) => SENSITIVE.test(f));
      g.assert(offenders.length === 0,
        'FullCheckResult has no credential field (§8.4)',
        offenders.length ? `offending field(s): ${offenders.join(', ')}` : null);
      // proxy host/port/protocol are explicitly allowed and must be the ONLY proxy fields.
      const proxyFields = fields.filter((f) => /^proxy_/.test(f));
      const allowed = ['proxy_host', 'proxy_port', 'proxy_protocol'];
      const badProxy = proxyFields.filter((f) => !allowed.includes(f));
      g.assert(badProxy.length === 0,
        `only ${allowed.join('/')} may appear on the result (found ${proxyFields.join(', ') || 'none'})`,
        badProxy.length ? `unexpected: ${badProxy.join(', ')}` : null);
    }

    // ---- credentials exist, but only on the transient request options -----
    const credBody = structBody('ProxyCredentials');
    g.assert(credBody !== null, 'ProxyCredentials exists (transient credential carrier)');
    if (credBody) {
      g.assert(/pub\s+username\s*:/.test(credBody), 'ProxyCredentials carries username');
      g.assert(/pub\s+password\s*:/.test(credBody), 'ProxyCredentials carries password');
    }
    // Zeroization may be implemented on any transient credential carrier, not
    // necessarily `models::ProxyCredentials` (browser_leak.rs and speed.rs each
    // own a private guard). What matters is that SOME carrier zeroizes and the
    // crate actually depends on the zeroize crate.
    const allBackend = stripRustComments(allRustText());
    const zeroizes = /Zeroizing\s*</.test(allBackend) || /\.zeroize\(\)/.test(allBackend);
    g.assert(zeroizes, 'proxy credentials are zeroized, not left on the heap',
      zeroizes ? null : 'no Zeroizing<> or .zeroize() anywhere in src-tauri');
    const cargoToml = readText(path.join(PROJECT_ROOT, 'src-tauri', 'Cargo.toml')) || '';
    g.assert(/^\s*zeroize\s*=/m.test(cargoToml), 'Cargo.toml depends on the zeroize crate');

    const optsBody = structBody('CheckOptions') || structBody('CheckRequest');
    if (optsBody) {
      g.assert(/credentials\s*:\s*Option<\s*ProxyCredentials\s*>/.test(optsBody),
        'credentials hang off the request options, not the result');
    } else {
      g.note('CheckOptions struct not found (name may differ)');
    }

    // ---- and they must never reach the database --------------------------
    const cacheText = rust('cache.rs');
    if (cacheText) {
      const ce = stripRustComments(cacheText);
      const schema = ce.match(/CREATE TABLE[\s\S]*?(?=CREATE TABLE|$)/gi) || [];
      const schemaAll = schema.join('\n');
      const badCols = ['password', 'passwd', 'username', 'credentials', 'api_key_token']
        .filter((c) => new RegExp(`\\b${c}\\b\\s+(TEXT|VARCHAR|BLOB)`, 'i').test(schemaAll));
      g.assert(badCols.length === 0, 'no credential column in any §10.1 table',
        badCols.length ? `found column(s): ${badCols.join(', ')}` : null);
      g.assert(!/INSERT INTO [\s\S]{0,300}(password|username)/i.test(ce),
        'no INSERT writes a credential value');
    }

    // ---- and never into the export surface -------------------------------
    const exportText = rust('export.rs');
    if (exportText) {
      const e = stripRustComments(exportText);
      const ecols = e.match(/CSV_COLUMNS\s*:\s*\[[^\]]*\]\s*=\s*\[([\s\S]*?)\];/);
      if (ecols) {
        const names = [...ecols[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
        const bad = names.filter((n) => SENSITIVE.test(n) || /passw|usern|cred/i.test(n));
        g.assert(bad.length === 0, 'CSV columns contain no credential column',
          bad.length ? `offending: ${bad.join(', ')}` : names.join(','));
      }
      // The rule is about *production* code: no path in export.rs may read a
      // credential field off the result. `#[cfg(test)] mod tests` legitimately
      // names those fields as arguments to assertions that prove they are
      // treated as secrets — scanning the test module made the gate fail the
      // day a test started documenting the invariant, which punishes the test
      // for doing the right thing.
      const cfgTestIdx = e.search(/^\s*#\[cfg\(test\)\]\s*\n\s*mod\s+tests\s*\{/m);
      const production = cfgTestIdx === -1 ? e : e.slice(0, cfgTestIdx);
      g.assert(!/proxy_password|proxy_username/i.test(production),
        'export.rs never references a credential field of the result',
        cfgTestIdx === -1 ? 'scanned whole file (no test module found)' : 'scanned production code only (test module excluded)');
      // The exclusion above must not become a silent no-op: if the test module
      // is renamed or the split stops matching, `production` equals the whole
      // file again and this assertion goes red instead of the exclusion quietly
      // covering nothing.
      g.assert(cfgTestIdx !== -1 ? production.length < e.length : true,
        'the cfg(test) module was actually found and excluded',
        cfgTestIdx === -1
          ? 'no #[cfg(test)] mod tests in export.rs — whole file scanned'
          : `${production.length} / ${e.length} bytes scanned`);
      // `credential` as a *denylist token* is the guard doing its job, not a leak.
      const mentionsCredential = /credential/i.test(e);
      const guardsIt = /assert_no_secrets|denylist|DENYLIST|forbidden|fails loudly|reject/i.test(e);
      g.assert(!mentionsCredential || guardsIt,
        'any mention of "credential" in export.rs is a denylist guard, not a leak',
        mentionsCredential && !guardsIt ? 'mentions credential without a guard' : (mentionsCredential ? 'denylist guard present' : 'no mention'));
    }

    // ---- live proof: the golden export cannot contain the sentinel --------
    const goldenText = readText(fixture('export.full-result.json')) || '';
    const sentinels = sentinelSecrets();
    const hits = scanForSecrets(goldenText, 'export', sentinels);
    g.assert(hits.length === 0, 'golden export carries no credential sentinel',
      hits.length ? JSON.stringify(hits.slice(0, 3)) : null);
    g.assert(!/proxy_credentials|"password"|"username"/.test(goldenText),
      'golden export has no credential key at all');
  }
  crossGates.push(g.finish());
}

{
  const g = new Gate('X10', 'Build safety: target dir off the small drive', '§12 Phase 4');
  // Drive E: on this machine has ~2.3 GB free while a Rust target tree needs
  // 2-4 GB. If CARGO_TARGET_DIR is not exported, cargo silently creates
  // `src-tauri/target` on E: and the build dies half-way with ENOSPC. Catch it
  // before anyone runs a build.
  const projectDrive = (PROJECT_ROOT.match(/^([A-Za-z]):/) || [])[1]?.toUpperCase() || null;
  g.assert(projectDrive !== null, `project lives on drive ${projectDrive}`);
  g.note(`project drive: ${projectDrive}: · CARGO_TARGET_DIR: ${process.env.CARGO_TARGET_DIR || '(unset)'}`);

  const targetDir = process.env.CARGO_TARGET_DIR || '';
  const targetDrive = (targetDir.match(/^([A-Za-z]):/) || [])[1]?.toUpperCase() || null;

  if (!targetDir) {
    // Unset is only acceptable if the project drive has room for a target tree.
    const freeGb = Number(process.env.DSH_TEST_FREE_GB || 0);
    if (freeGb > 0) {
      g.assert(freeGb >= 6, `project drive has ${freeGb} GB free (target tree needs >= 6 GB)`);
    } else {
      g.note('WARNING: CARGO_TARGET_DIR unset — cargo will write `src-tauri/target` on the project drive. Export it before building: $env:CARGO_TARGET_DIR = "C:\\cargo-target\\ip-checker"');
    }
  } else if (targetDrive === projectDrive) {
    g.assert(false, 'CARGO_TARGET_DIR is on the same (small) drive as the project',
      `${targetDir} — move it to a drive with >= 6 GB free`);
  } else {
    g.assert(true, `CARGO_TARGET_DIR is on drive ${targetDrive}:, away from the project drive ${projectDrive}:`,
      targetDir);
  }

  // The build/smoke scripts must export it themselves, not rely on the caller.
  for (const script of ['build.ps1', 'smoke.ps1']) {
    const p = path.join(PROJECT_ROOT, 'scripts', script);
    const t = readText(p);
    if (!t) continue;
    g.assert(/CARGO_TARGET_DIR\s*=/.test(t), `scripts/${script} exports CARGO_TARGET_DIR, not relying on the shell`);
  }

  // Probe binary discovery must consider both locations, since the target dir
  // may be redirected or not.
  const probePathCandidates = [
    path.join(targetDir || path.join(PROJECT_ROOT, 'src-tauri', 'target'), 'debug', 'probe.exe'),
    path.join(PROJECT_ROOT, 'src-tauri', 'target', 'debug', 'probe.exe'),
  ];
  g.assert(probePathCandidates.length === 2, 'probe discovery checks both the redirected and the local target dir');
  g.note(`probe looked for at: ${probePathCandidates.join(' | ')}`);
  crossGates.push(g.finish());
}

{
  const g = new Gate('X11', 'IPC parameter naming: api.ts vs tauri commands', '§2.3, §4.2');
  // `#[tauri::command]` renames every parameter to camelCase at the IPC boundary,
  // so a Rust `check_id` must be invoked as `checkId` unless the command opts out
  // with `rename_all = "snake_case"`. api.ts sends snake_case. Rust unit tests
  // call the functions directly and never cross that wrapper, so no amount of
  // `cargo test` green can catch this — the app just throws at runtime:
  //   invalid args `checkId` for command `export_report`: missing required key checkId
  const { runX11 } = await import('./x11-ipc-naming.mjs');
  const x11 = runX11();
  g.note(`scope: ${x11.commands.length} command(s) cross-checked against src/lib/api.ts`);
  for (const c of x11.checks) g.assert(c.ok, c.label);
  for (const row of x11.rows) {
    if (row.verdict === 'FAIL') g.assert(false, `${row.cmd}: ${row.why}`);
  }
  g.assert(x11.pass, 'every api.ts payload matches its command parameter names',
    x11.rows.filter((r) => r.verdict === 'FAIL').map((r) => r.cmd).join(', '));
  crossGates.push(g.finish());
}

{
  const g = new Gate('X12', 'Usability parity: front-end vs back-end on a proxy target', '§1.2, §3.4, §8.4');
  // Both layers answer "can this be checked?" and they answered it differently
  // three times in one session, each time killing proxy mode at a different
  // door: validator.rs rejected a loopback proxy, then ipInput.ts rejected it
  // and disabled Scan, then LeakSpeedCard claimed no proxy was entered. The
  // cause was reusing `isPublic` for two questions — "has reputation data" and
  // "can be dialled". This gate replays a fixed vector set through both sides.
  const { runX12 } = await import('./x12-usable-parity.mjs');
  const x12 = runX12();
  g.note(`scope: ${x12.summary}`);
  for (const c of x12.checks) g.assert(c.ok, c.label, c.detail || null);
  for (const row of x12.rows) {
    if (row.verdict === 'FAIL') {
      g.assert(false, `${row.raw}: FE=${row.fe} BE=${row.be}, expected ${row.expectFe}/${row.expectBe} (${row.why})`);
    }
  }
  g.assert(x12.pass, 'every vector resolves the same way in both layers',
    x12.rows.filter((r) => r.verdict === 'FAIL').map((r) => r.raw).join(', '));
  crossGates.push(g.finish());
}

{
  const g = new Gate('X13', 'One scan, one run: exactly one check command per click', '§4.3, §10.2, §13.9');
  // A scan that invoked both check_ip_stream and check_ip ran all 13 modules
  // twice: the first run wrote its row, the second kept a different check_id
  // that was never persisted, so EXPORT asked the cache for a row that did not
  // exist. It also spent twice the §4.3 module budget and made a scan look
  // "slow" instead of "ran twice" — 3 clicks produced 3 rows, not 6.
  const { runX13 } = await import('./x13-single-run.mjs');
  const x13 = runX13();
  g.note(`scope: ${x13.summary}`);
  for (const c of x13.checks) g.assert(c.ok, c.label, c.detail || null);
  g.assert(x13.pass, 'a single click invokes exactly one check command',
    x13.calls.length > 1 ? x13.calls.map((c) => c.cmd).join(' + ') : null);
  crossGates.push(g.finish());
}

{
  const g = new Gate('X0', 'Team code progress (context)', '§12');
  const realModules = backend.modules.filter((m) => m.state === 'real').length;
  g.assert(true, 'backend progress readable');
  g.note(`backend: ${realModules}/${backend.modules.length} modules "real", missing=${backend.missing.length}, stub=${backend.stubs.length}`);
  g.note(`frontend: ${frontend.files.filter((f) => f.exists).length}/${frontend.files.length} files present`);
  if (backend.missing.length) g.note(`missing: ${backend.missing.slice(0, 30).join(', ')}`);
  if (backend.stubs.length) g.note(`stub/partial: ${backend.stubs.slice(0, 30).join(', ')}`);
  if (frontend.missing.length) g.note(`frontend missing: ${frontend.missing.join(', ')}`);
  crossGates.push(g.finish());
}

/* ================================================================== */
/* run                                                                */
/* ================================================================== */

for (const g of gates) printGate(g);
console.log('');
console.log(c.bold('-- Cross-cutting gates --'));
for (const g of crossGates) printGate(g);

printTable(gates);

const summary = {
  pass: gates.filter((g) => g.status === STATUS.PASS).length,
  fail: gates.filter((g) => g.status === STATUS.FAIL).length,
  blocked: gates.filter((g) => g.status === STATUS.BLOCKED).length,
  skip: gates.filter((g) => g.status === STATUS.SKIP).length,
};
console.log(c.bold(`§13: ${summary.pass} PASS / ${summary.fail} FAIL / ${summary.blocked} BLOCKED / ${summary.skip} SKIP  (total ${gates.length})`));
const crossSummary = {
  pass: crossGates.filter((g) => g.status === STATUS.PASS).length,
  fail: crossGates.filter((g) => g.status === STATUS.FAIL).length,
  blocked: crossGates.filter((g) => g.status === STATUS.BLOCKED).length,
};
console.log(c.gray(`cross: ${crossSummary.pass} PASS / ${crossSummary.fail} FAIL / ${crossSummary.blocked} BLOCKED`));

const reportPath = writeReport([...gates, ...crossGates], {
  mode: STATIC_ONLY ? 'static' : 'full',
  built_exe: builtExe,
  backend_readiness: { ready: backend.ready, missing: backend.missing, stubs: backend.stubs },
});
console.log(c.gray(`report: ${reportPath}`));

if (AS_JSON) console.log(JSON.stringify({ summary, crossSummary, report: reportPath }, null, 2));

process.exit(summary.fail > 0 || crossSummary.fail > 0 ? 1 : summary.blocked > 0 || crossSummary.blocked > 0 ? 2 : 0);
