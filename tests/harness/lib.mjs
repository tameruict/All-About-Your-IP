#!/usr/bin/env node
/**
 * IP Checker \u2014 shared harness utilities (spec \u00A713).
 *
 * No external dependencies on purpose: the harness must run on a clean Windows
 * box with nothing but Node, before `npm i` has even happened.
 *
 * Provides: fixture loading, project introspection, a uniform gate/result model,
 * a secret scanner (\u00A713.10), and small ANSI reporting helpers.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const HARNESS_DIR = path.dirname(fileURLToPath(import.meta.url));
export const TESTS_DIR = path.dirname(HARNESS_DIR);
export const PROJECT_ROOT = path.dirname(TESTS_DIR);
export const FIXTURES_DIR = path.join(TESTS_DIR, 'fixtures');
export const TAURI_SRC = path.join(PROJECT_ROOT, 'src-tauri', 'src');
export const REACT_SRC = path.join(PROJECT_ROOT, 'src');
export const ARTIFACT_MANIFEST = path.join(PROJECT_ROOT, 'scripts', 'build-artifacts.json');

/* ------------------------------------------------------------------ */
/* colours                                                             */
/* ------------------------------------------------------------------ */

const NO_COLOR = process.env.NO_COLOR === '1' || !process.stdout.isTTY;
const wrap = (code) => (s) => (NO_COLOR ? String(s) : `\u001b[${code}m${s}\u001b[0m`);
export const c = {
  red: wrap('31'),
  green: wrap('32'),
  yellow: wrap('33'),
  blue: wrap('34'),
  magenta: wrap('35'),
  cyan: wrap('36'),
  gray: wrap('90'),
  bold: wrap('1'),
};

/* ------------------------------------------------------------------ */
/* status model                                                        */
/* ------------------------------------------------------------------ */

/** \u00A713 statuses. BLOCKED is a first-class outcome \u2014 never silently upgraded to PASS. */
export const STATUS = Object.freeze({
  PASS: 'PASS',
  FAIL: 'FAIL',
  BLOCKED: 'BLOCKED',
  SKIP: 'SKIP',
});

export class Gate {
  constructor(id, title, specRef) {
    this.id = id;
    this.title = title;
    this.specRef = specRef;
    this.status = STATUS.BLOCKED;
    this.evidence = [];
    this.details = [];
    this.startedAt = new Date().toISOString();
    this.finishedAt = null;
    this.live = false;
  }

  /** Record an assertion. Returns the boolean so call sites can branch. */
  assert(condition, message, detail) {
    if (condition) {
      this.evidence.push({ ok: true, message, detail: detail ?? null });
    } else {
      this.evidence.push({ ok: false, message, detail: detail ?? null });
    }
    return !!condition;
  }

  note(message) {
    this.details.push(message);
    return this;
  }

  /** Mark the gate as needing live app execution (network / built binary). */
  markLive(reason) {
    this.live = true;
    this.note(`live: ${reason}`);
    return this;
  }

  /** Derive final status: any failed assertion wins; otherwise blocked if nothing was asserted. */
  finish() {
    this.finishedAt = new Date().toISOString();
    const failed = this.evidence.filter((e) => !e.ok);
    if (failed.length > 0) {
      this.status = STATUS.FAIL;
    } else if (this.evidence.length === 0) {
      this.status = STATUS.BLOCKED;
      if (this.details.length === 0) this.details.push('no assertion executed');
    } else {
      this.status = STATUS.PASS;
    }
    return this;
  }

  /** Short single-line evidence string for the final table. */
  summary() {
    const okCount = this.evidence.filter((e) => e.ok).length;
    const bad = this.evidence.filter((e) => !e.ok);
    if (this.status === STATUS.FAIL && bad.length) {
      const first = bad[0];
      const more = bad.length > 1 ? ` (+${bad.length - 1} n\u1EEFa)` : '';
      return `${first.message}${first.detail ? ` \u2014 ${truncate(String(first.detail), 220)}` : ''}${more}`;
    }
    if (this.status === STATUS.BLOCKED) {
      return this.details.slice(-1)[0] ?? 'blocked';
    }
    const detailTail = this.details.length ? ` | ${truncate(this.details.join('; '), 180)}` : '';
    return `${okCount}/${this.evidence.length} assertion(s) ok${detailTail}`;
  }

  toJSON() {
    return {
      id: this.id,
      title: this.title,
      specRef: this.specRef,
      status: this.status,
      live: this.live,
      summary: this.summary(),
      evidence: this.evidence,
      details: this.details,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
    };
  }
}

export function truncate(s, n) {
  const str = String(s);
  return str.length <= n ? str : `${str.slice(0, n - 1)}\u2026`;
}

/* ------------------------------------------------------------------ */
/* filesystem helpers                                                  */
/* ------------------------------------------------------------------ */

/**
 * Decode a text file, detecting the encoding from its BOM.
 *
 * PowerShell's `>` redirection writes UTF-16LE with a BOM on Windows, so a build
 * log can be one of several encodings depending on who produced it. Reading a
 * UTF-16 file as UTF-8 "succeeds" and yields NUL-interleaved garbage, which then
 * fails every regex and looks like an empty/unreadable file — a silent trap.
 */
export function decodeText(buf) {
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    return buf.slice(3).toString('utf8');
  }
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    return buf.slice(2).toString('utf16le');
  }
  if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    // UTF-16BE: swap byte pairs, then decode as LE.
    const swapped = Buffer.alloc(buf.length - 2);
    for (let i = 2; i + 1 < buf.length; i += 2) {
      swapped[i - 2] = buf[i + 1];
      swapped[i - 1] = buf[i];
    }
    return swapped.toString('utf16le');
  }
  // No BOM: NUL-heavy heads are UTF-16LE written by Windows tooling.
  if (buf.length >= 2 && buf[0] !== 0 && buf[1] === 0) {
    return buf.toString('utf16le');
  }
  return buf.toString('utf8');
}

export function readText(p) {
  try {
    return decodeText(fs.readFileSync(p)).replace(/^\uFEFF/, '');
  } catch {
    return null;
  }
}

/**
 * Like readText, but THROWS when the file cannot be read.
 *
 * Use this where a null would be indistinguishable from "empty file" — e.g.
 * scanning build logs that another process may be writing, where a silent null
 * makes the gate quietly fall back to an older artefact and report a stale
 * result.
 */
export function readTextStrict(p) {
  return decodeText(fs.readFileSync(p)).replace(/^\uFEFF/, '');
}

export function readJson(p) {
  const t = readText(p);
  if (t === null) return null;
  try {
    return JSON.parse(t);
  } catch (err) {
    throw new Error(`invalid JSON in ${p}: ${err.message}`);
  }
}

export function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

export function fixture(...parts) {
  return path.join(FIXTURES_DIR, ...parts);
}

export function loadFixture(...parts) {
  const p = fixture(...parts);
  const data = readJson(p);
  if (data === null) throw new Error(`fixture missing: ${p}`);
  return data;
}

/** Recursively list files under a directory, skipping heavyweight build dirs. */
export function walk(dir, opts = {}) {
  const {
    skipDirs = new Set(['node_modules', 'target', 'dist', '.git', '.vite', 'gen']),
    filter = null,
    limit = 20000,
  } = opts;
  const out = [];
  if (!exists(dir)) return out;

  const stack = [dir];
  while (stack.length && out.length < limit) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        if (!filter || filter(full)) out.push(full);
      }
    }
  }
  return out;
}

/** Read every .rs/.ts/.tsx file in the project sources (bounded). */
export function sourceFiles() {
  const rs = walk(TAURI_SRC, { filter: (f) => f.endsWith('.rs') });
  const ts = walk(REACT_SRC, { filter: (f) => f.endsWith('.ts') || f.endsWith('.tsx') });
  return [...rs, ...ts];
}

/* ------------------------------------------------------------------ */
/* project introspection                                               */
/* ------------------------------------------------------------------ */

export const RUST_MODULES_TIMELINE = [
  'main.rs', 'lib.rs', 'validator.rs', 'scoring.rs', 'cache.rs', 'export.rs',
  'orchestrator.rs', 'commands.rs', 'config.rs', 'dnsbl.rs', 'asn.rs',
  'location.rs', 'network.rs', 'browser_leak.rs', 'speed.rs', 'geo_db.rs',
  'providers/mod.rs', 'providers/registry.rs',
];

export const PROVIDER_ADAPTERS = [
  'ip_api.rs', 'ipwho.rs', 'ipinfo.rs', 'ipqs.rs', 'proxycheck.rs',
  'scamalytics.rs', 'abuseipdb.rs', 'greynoise.rs', 'ripestat.rs',
  'bgpview.rs', 'team_cymru.rs',
];

/** Count non-comment, non-blank lines \u2014 used to tell "stub" from "real code". */
export function codeLineCount(text) {
  if (!text) return 0;
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('//') && !l.startsWith('/*') && !l.startsWith('*'))
    .length;
}

/**
 * Classify a Rust source file: missing | stub | partial | real.
 * "stub" = the scaffold state (unimplemented!/todo!("")/Owned-by-someone-else placeholders).
 */
export function classifyRustFile(p) {
  const text = readText(p);
  if (text === null) return { state: 'missing', lines: 0, path: p };
  const lines = codeLineCount(text);
  const stubbed =
    /\bunimplemented!\s*\(/.test(text) ||
    /\btodo!\s*\(/.test(text) ||
    /not yet implemented/i.test(text) ||
    /^\/\/\s*STUB/im.test(text);
  let state;
  if (lines < 12) state = 'stub';
  else if (stubbed) state = 'partial';
  else state = 'real';
  return { state, lines, path: p, stubbed };
}

/** True when every required Rust module exists and none is still a stub. */
export function backendReadiness() {
  const modules = RUST_MODULES_TIMELINE.map((rel) => {
    const p = path.join(TAURI_SRC, rel);
    return { rel, ...classifyRustFile(p) };
  });
  const adapters = PROVIDER_ADAPTERS.map((rel) => {
    const p = path.join(TAURI_SRC, 'providers', rel);
    return { rel: `providers/${rel}`, ...classifyRustFile(p) };
  });
  const all = [...modules, ...adapters];
  const missing = all.filter((m) => m.state === 'missing').map((m) => m.rel);
  const stubs = all.filter((m) => m.state === 'stub' || m.state === 'partial').map((m) => m.rel);
  const ready = missing.length === 0 && stubs.length === 0;
  return { ready, modules, adapters, missing, stubs };
}

export const REACT_COMPONENTS = [
  'App.tsx', 'main.tsx',
  'components/InputConsole.tsx', 'components/VerdictHUD.tsx', 'components/ScanProgress.tsx',
  'components/GeoMapCard.tsx', 'components/ReputationCard.tsx', 'components/BlacklistTable.tsx',
  'components/NetworkCard.tsx', 'components/LeakSpeedCard.tsx', 'components/EvidenceTable.tsx',
  'components/HistoryPanel.tsx', 'components/SettingsPanel.tsx',
  'lib/api.ts',
];

export function frontendReadiness() {
  const files = REACT_COMPONENTS.map((rel) => {
    const p = path.join(REACT_SRC, rel);
    const text = readText(p);
    return { rel, exists: text !== null, lines: codeLineCount(text) };
  });
  const missing = files.filter((f) => !f.exists).map((f) => f.rel);
  const thin = files.filter((f) => f.exists && f.lines < 8).map((f) => f.rel);
  return { ready: missing.length === 0 && thin.length === 0, files, missing, thin };
}

/** Locate any built artifact (portable exe / installer). */
export function findBuiltExe() {
  const manifest = readJson(ARTIFACT_MANIFEST) || readJson(path.join(PROJECT_ROOT, 'scripts', 'build-artifacts.json'));
  if (manifest) {
    const list = Array.isArray(manifest) ? manifest : [manifest];
    const hit = list.find((a) => a && a.Path && exists(a.Path));
    if (hit) return hit.Path;
  }
  const targetRoot = process.env.CARGO_TARGET_DIR || 'C:\\cargo-target\\ip-checker';
  for (const dir of [path.join(targetRoot, 'release'), path.join(PROJECT_ROOT, 'src-tauri', 'target', 'release')]) {
    if (!exists(dir)) continue;
    try {
      const candidates = fs.readdirSync(dir).filter((f) => f.toLowerCase().endsWith('.exe') && !/uninstall|build-script/i.test(f));
      if (candidates.length) return path.join(dir, candidates[0]);
    } catch {
      /* ignore */
    }
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* secret scanner (\u00A713.10)                                             */
/* ------------------------------------------------------------------ */

/** Sentinel secrets taken from the fixtures \u2014 they must never appear anywhere near output. */
export function sentinelSecrets() {
  const cfg = loadFixture('cache-export.json');
  const keys = cfg.secrets_that_must_never_leak.api_keys;
  const creds = cfg.secrets_that_must_never_leak.proxy_credentials;
  return {
    keys,
    usernames: creds.map((x) => x.username),
    passwords: creds.map((x) => x.password),
    forbiddenSubstrings: cfg.secrets_that_must_never_leak.also_forbidden_substrings,
  };
}

/**
 * Scan one blob of text for secrets.
 * `mode` controls how aggressive the generic pattern sweep is:
 *   - 'export' : scans exported JSON/CSV \u2014 flags credentials, keys, tokens, key= params
 *   - 'log'    : scans log files \u2014 additionally flags URL-embedded userinfo and auth headers
 *   - 'source' : scans source code \u2014 flags only literal hardcoded keys (not identifiers)
 */
export function scanForSecrets(text, mode = 'export', secrets = sentinelSecrets()) {
  const hits = [];
  if (!text) return hits;

  // For source scans, `#[cfg(test)] mod tests { ... }` blocks may legitimately hold
  // obviously-fake fixture credentials (they never reach the shipped binary).
  // Strip them before sweeping so we do not raise false alarms.
  let haystack = text;
  if (mode === 'source') {
    haystack = text.replace(/#\[cfg\(test\)\][\s\S]*$/m, '\n/* <test module elided for secret scan> */\n');
    // Also drop `#[cfg(test)]`-gated helper fns declared before their module.
    haystack = haystack.replace(/#\[cfg\(test\)\][\s\S]*?(?=\n(?!#\[|\s))/g, '');
  }

  for (const k of secrets.keys) {
    if (haystack.includes(k)) hits.push({ rule: 'sentinel-api-key', match: k });
  }
  for (const u of secrets.usernames) {
    if (haystack.includes(u)) hits.push({ rule: 'sentinel-proxy-username', match: u });
  }
  for (const p of secrets.passwords) {
    if (haystack.includes(p)) hits.push({ rule: 'sentinel-proxy-password', match: p });
  }

  const patterns = [];
  if (mode === 'export') {
    patterns.push(
      { rule: 'credential-field', re: /"(proxy_)?(password|passwd|pass|credential|credentials)"\s*:\s*"(?!\[REDACTED\]|)(?<val>[^"\\]{3,})"/gi },
      { rule: 'api-key-inline', re: /\b(api[_-]?key|apikey|token|secret)\b\s*[=:]\s*["']?(?<val>[A-Za-z0-9_\-]{12,})["']?/gi },
      { rule: 'key-in-url', re: /[?&](?:key|token|api_?key|apikey)=[A-Za-z0-9_\-]{8,}/gi },
    );
  } else if (mode === 'log') {
    patterns.push(
      { rule: 'url-userinfo', re: /\b[a-z0-9+.-]+:\/\/[^/\s:@]+:[^/\s@]+@/gi },
      { rule: 'auth-header', re: /\b(authorization|apikey|x-api-key)\s*[:=]\s*(?!\[REDACTED\])(?<val>[^\s]{8,})/gi },
      { rule: 'key-in-url', re: /[?&](?:key|token|api_?key|apikey)=[A-Za-z0-9_\-]{8,}/gi },
    );
  } else {
    // source: only long literal assignments that look like real keys, never identifiers
    patterns.push(
      { rule: 'hardcoded-secret-literal', re: /\b(?:let|const|static)\s+(?:mut\s+)?[A-Za-z0-9_]*(?:key|token|secret|password|passwd)[A-Za-z0-9_]*\s*(?::\s*&?(?:'static\s+)?str\s*)?=\s*(?<val>"[A-Za-z0-9_\-]{20,}")/gi },
      { rule: 'hardcoded-secret-in-format', re: /(?:\?|\&)(?:key|token|apikey)=(?<val>[A-Za-z0-9_\-]{20,})(?:&|")/gi },
    );
  }

  for (const { rule, re } of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(haystack)) !== null) {
      const matched = m.groups?.val ?? m[0];
      // Ignore obvious placeholders / already-redacted / env lookups / test dummies.
      if (/REDACTED|PLACEHOLDER|YOUR[_-]?KEY|xxxx|\.\.\.|<[^>]+>/i.test(matched)) continue;
      if (/^(std::env|env::var|process\.env|\$\{)/i.test(matched)) continue;
      if (/^"?test[-_]|test-token|test-key|dummy|fake|mock|sample|example|fixture/i.test(matched.replace(/^"/, ''))) continue;
      hits.push({ rule, match: truncate(matched, 80) });
      if (hits.length > 200) return hits;
    }
  }
  return hits;
}

/* ------------------------------------------------------------------ */
/* reporting                                                           */
/* ------------------------------------------------------------------ */

export function printHeader(title, subtitle) {
  console.log('');
  console.log(c.magenta(c.bold(`\u2550\u2550 ${title} ${'\u2550'.repeat(Math.max(0, 62 - title.length))}`)));
  if (subtitle) console.log(c.gray(subtitle));
  console.log('');
}

export function printGate(gate) {
  const badge =
    gate.status === STATUS.PASS ? c.green('[PASS]   ')
    : gate.status === STATUS.FAIL ? c.red('[FAIL]   ')
    : gate.status === STATUS.BLOCKED ? c.yellow('[BLOCKED]')
    : c.gray('[SKIP]   ');
  console.log(`${badge} ${c.bold(gate.id)} ${gate.title} ${c.gray(`(${gate.specRef})`)}`);
  for (const e of gate.evidence) {
    const mark = e.ok ? c.green('  \u2713') : c.red('  \u2717');
    console.log(`${mark} ${e.message}${e.detail ? c.gray(` \u2014 ${truncate(e.detail, 300)}`) : ''}`);
  }
  if (gate.status === STATUS.BLOCKED || gate.status === STATUS.SKIP) {
    for (const d of gate.details) console.log(c.gray(`  \u00B7 ${d}`));
  }
}

/** Render the \u00A713.1\u2026\u00A713.10 table. */
export function printTable(gates) {
  const rows = gates.map((g) => ({
    id: g.id,
    title: g.title,
    status: g.status,
    evidence: g.summary(),
  }));
  const idW = Math.max(6, ...rows.map((r) => r.id.length));
  const titleW = Math.max(11, ...rows.map((r) => r.title.length));
  const statusW = 7;
  const line = (l, m, r) => `${l}${'\u2500'.repeat(idW + 2)}${m}${'\u2500'.repeat(titleW + 2)}${m}${'\u2500'.repeat(statusW + 2)}${m}`;

  console.log('');
  console.log(c.bold('\u00A713 \u2014 B\u1EA2NG K\u1EBET QU\u1EA2 TEST B\u1EAET BU\u1ED8C'));
  console.log(line('\u250C', '\u252C', '\u2510'));
  console.log(`\u2502 ${'ID'.padEnd(idW)} \u2502 ${'Test'.padEnd(titleW)} \u2502 ${'Status'.padEnd(statusW)} \u2502`);
  console.log(line('\u251C', '\u253C', '\u2524'));
  for (const r of rows) {
    const colour = r.status === STATUS.PASS ? c.green : r.status === STATUS.FAIL ? c.red : c.yellow;
    console.log(`\u2502 ${r.id.padEnd(idW)} \u2502 ${r.title.padEnd(titleW)} \u2502 ${colour(r.status.padEnd(statusW))} \u2502`);
  }
  console.log(line('\u2514', '\u2534', '\u2518'));
  console.log('');
  console.log(c.bold('B\u1EB1ng ch\u1EE9ng (1 d\u00F2ng / test):'));
  for (const r of rows) console.log(`${r.id.padEnd(idW)}  ${c.gray(truncate(r.evidence, 260))}`);
  console.log('');
}

export function writeReport(gates, extra = {}) {
  const outPath = path.join(TESTS_DIR, 'spec13-report.json');
  const payload = {
    generated_at: new Date().toISOString(),
    node: process.version,
    project_root: PROJECT_ROOT,
    summary: {
      pass: gates.filter((g) => g.status === STATUS.PASS).length,
      fail: gates.filter((g) => g.status === STATUS.FAIL).length,
      blocked: gates.filter((g) => g.status === STATUS.BLOCKED).length,
      skip: gates.filter((g) => g.status === STATUS.SKIP).length,
      total: gates.length,
    },
    gates: gates.map((g) => g.toJSON()),
    ...extra,
  };
  fs.writeFileSync(outPath, JSON.stringify(payload, null, 2), 'utf8');
  return outPath;
}
