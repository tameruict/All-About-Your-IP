/**
 * Mutation test for X9's `#[cfg(test)] mod tests` exclusion.
 *
 * X9 asserts that production code in `export.rs` never reads a credential field
 * off the result. That check now skips the test module, because tests name those
 * fields on purpose. An exclusion like that is indistinguishable from a
 * disabled gate unless something proves it still catches the real thing.
 *
 * This script plants `result.proxy_username` **in production code**, runs the
 * harness against a patched copy, and requires X9 to FAIL. If X9 still passes,
 * the exclusion opened a hole and this script exits non-zero.
 *
 * Usage: node tests/harness/mutation-x9.mjs
 */

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = new URL("../../", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const EXPORT_RS = join(ROOT, "src-tauri", "src", "export.rs");
const HARNESS = join(ROOT, "tests", "harness", "spec13.test.mjs");

function runHarness() {
  try {
    const out = execFileSync(process.execPath, [HARNESS], {
      cwd: ROOT,
      encoding: "utf8",
      env: { ...process.env, CARGO_TARGET_DIR: process.env.CARGO_TARGET_DIR || "C:\\cargo-target\\ip-build-v5" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

function x9Verdict(out) {
  const line = out.split(/\r?\n/).find((l) => /\[(PASS|FAIL)\]\s+X9\b/.test(l));
  return line ? (/\[FAIL\]/.test(line) ? "FAIL" : "PASS") : "MISSING";
}

const work = mkdtempSync(join(tmpdir(), "x9-mutation-"));
const backup = join(work, "export.rs.orig");
copyFileSync(EXPORT_RS, backup);

let exitCode = 0;
try {
  // 1. Baseline: unmutated source must pass.
  const baseline = runHarness();
  const before = x9Verdict(baseline.out);
  console.log(`baseline X9: ${before}`);
  if (before !== "PASS") {
    console.log("BASELINE NOT CLEAN — fix X9 before trusting the mutation result");
    exitCode = 1;
  }

  // 2. Plant a real leak in production code: a function above the test module.
  const original = readFileSync(EXPORT_RS, "utf8");
  const anchor = "/// Build the CSV header line.";
  if (!original.includes(anchor)) {
    console.log(`ANCHOR NOT FOUND (${anchor}) — cannot mutate`);
    exitCode = 1;
  } else {
    const mutated = original.replace(
      anchor,
      "/// leaked credential (mutation test)\nfn leaked(result: &FullCheckResult) -> Option<String> {\n    result.proxy_username.clone()\n}\n\n" + anchor,
    );
    writeFileSync(EXPORT_RS, mutated, "utf8");

    const after = runHarness();
    const mutation = x9Verdict(after.out);
    console.log(`mutated  X9: ${mutation}`);
    if (mutation === "FAIL") {
      console.log("PASS — X9 caught a real credential read in production code");
    } else {
      console.log("FAIL — X9 did NOT catch result.proxy_username in production code; the exclusion is a hole");
      exitCode = 1;
    }
  }
} finally {
  copyFileSync(backup, EXPORT_RS);
  rmSync(work, { recursive: true, force: true });
  const restored = readFileSync(EXPORT_RS, "utf8");
  console.log(`restored export.rs (${restored.length} bytes, proxy_username in production: ${/result\.proxy_username/.test(restored)})`);
}

process.exit(exitCode);
