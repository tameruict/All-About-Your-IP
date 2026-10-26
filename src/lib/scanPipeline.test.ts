/**
 * Static guards for the scan pipeline.
 *
 * `startCheck` must drive exactly one orchestrator run per click. It used to
 * call `check_ip_stream` and then `check_ip` "to get the session" — but the
 * second call re-ran all 13 modules with a brand-new `check_id` and
 * `save_to_history: false`, so:
 *
 *   * `session.check_id` pointed at a row the cache had never written, and
 *     `export_report` failed with "Không có dữ liệu để xuất cho check_id …";
 *   * the history entry showed a different id than the result panel;
 *   * one click cost twice the module budget (~60 s instead of ~30 s).
 *
 * A unit test cannot see this: the duplicate call is correct-looking code that
 * type-checks, and the pipeline it calls does real network I/O. The invariant is
 * structural, so the guard reads the source. That is deliberate — the same
 * reason `commands.rs` has `every_snake_case_command_declares_rename_all`.
 *
 * Run with: node --test --experimental-strip-types src/lib/scanPipeline.test.ts
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * Resolve repo paths from this file, not from `process.cwd()`.
 *
 * `node --test` keeps the shell's working directory, which is the workspace
 * root (`E:\auto-reg\check-ip`) rather than the app root — reading "src/App.tsx"
 * relative to cwd silently found nothing and the guards failed open.
 */
const HERE = dirname(fileURLToPath(import.meta.url));
const APP_PATH = join(HERE, "..", "App.tsx");
const API_PATH = join(HERE, "api.ts");

function readApp(): string {
  return readFileSync(APP_PATH, "utf8");
}

/** Body of `const startCheck = useCallback(...)`, up to its dependency array. */
function startCheckBody(source: string): string {
  // Normalise line endings first: this file is checked out with LF, but any
  // tool that rewrites it (PowerShell `Copy-Item`, an editor on Windows) can
  // flip it to CRLF. Matching raw "\n" then failed and every guard below
  // failed for the wrong reason — the guard must depend on structure, not on
  // which line ending the file happens to have today.
  const text = source.replace(/\r\n/g, "\n");
  const start = text.indexOf("const startCheck = useCallback(");
  assert.notEqual(start, -1, "startCheck must exist in App.tsx");
  // The callback's own dependency array is the line that follows the `},` at
  // the same indentation as the opening `useCallback(` — matching "\n    }, ["
  // naively hit the *next* callback's deps and truncated the body to nothing.
  const end = text.indexOf("\n    },\n    [", start);
  assert.notEqual(end, -1, "startCheck callback must end with a dependency array");
  return text.slice(start, end);
}

test("startCheck runs the pipeline exactly once", () => {
  const body = startCheckBody(readApp());
  const streamCalls = body.match(/api\.checkIpStream\(/g) ?? [];
  const plainCalls = body.match(/api\.checkIp\(/g) ?? [];
  assert.equal(
    streamCalls.length + plainCalls.length,
    1,
    `startCheck must invoke exactly one check command, found ${streamCalls.length} checkIpStream + ${plainCalls.length} checkIp`,
  );
  assert.equal(streamCalls.length, 1, "the one call must be the streaming variant");
});

test("startCheck never discards the session it just produced", () => {
  // The regression looked like `await api.checkIpStream(...)` with no binding:
  // the value was thrown away, which is *why* a second call was added.
  const body = startCheckBody(readApp());
  assert.match(
    body,
    /const\s+session\s*:\s*CheckSession\s*=\s*await\s+api\.checkIpStream\(/,
    "the streaming call's CheckSession must be bound and typed",
  );
});

test("startCheck reports the id the cache actually stored", () => {
  const body = startCheckBody(readApp());
  assert.match(
    body,
    /checkId:\s*session\.check_id/,
    "checkId must come from the session the stream returned, not a second run",
  );
});

test("api.checkIpStream is typed to return CheckSession", () => {
  const api = readFileSync(API_PATH, "utf8");
  assert.match(
    api,
    /export function checkIpStream\([\s\S]*?\)\s*:\s*Promise<CheckSession>/,
    "checkIpStream must resolve with CheckSession; Promise<void> is what forced the double run",
  );
});

test("export uses the same id the panel shows", () => {
  // Export is wired from `ui.result.check_id`; if `ui.checkId` and the result
  // id could disagree, export would look up the wrong row. The id is passed as
  // a camelCase JS local, so assert the binding it is derived from instead.
  const app = readApp();
  const idx = app.indexOf("api.exportReport(");
  assert.notEqual(idx, -1, "App.tsx must wire api.exportReport");
  const before = app.slice(Math.max(0, idx - 700), idx);
  assert.match(
    before,
    /check_id/,
    "the id handed to exportReport must derive from a result's check_id",
  );
});
