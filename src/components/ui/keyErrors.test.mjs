/**
 * Unit tests for the key-command error classifier.
 *
 * Runs on the Node test runner that ships with Node 18+ — no vitest, no jest,
 * no new dependency, nothing to add to package.json:
 *
 *   node --test src/components/ui/
 *
 * Why these tests exist: `describeKeyError` decides whether the user is told
 * "your key is bad", "the backend forgot to register the command" or "the
 * argument names don't match". All three reach the UI as an opaque
 * `kind: "internal"` rejection, and two of them are indistinguishable without a
 * deliberately ordered regex chain. A silent regression here sends the next
 * developer hunting a key bug that does not exist. The messages below are copied
 * from real Tauri v2 rejections.
 *
 * The module under test is `.ts`, so the test file is `.mjs` and relies on
 * Node's built-in type stripping (Node 22+/25, enabled by default in 23+).
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  classifyKeyError,
  describeKeyError,
  KEY_ERROR_ARG_MISMATCH,
  KEY_ERROR_NOT_REGISTERED,
  KEY_ERROR_NO_IPC,
} from "./keyErrors.ts";

/* ------------------------------------------------------------------ */
/* Branch 1 — argument name mismatch (the dangerous one)                */
/* ------------------------------------------------------------------ */

test("arg mismatch: Tauri 'missing required key' message", () => {
  const err = {
    kind: "internal",
    message:
      "invalid args `provider` for command `save_provider_key`: command missing required key provider",
  };

  assert.equal(classifyKeyError(err), "arg_mismatch");

  const text = describeKeyError(err);
  assert.ok(
    text.startsWith(KEY_ERROR_ARG_MISMATCH),
    "phải nói rõ là lỗi tham số, không phải lỗi key",
  );
  // The offending parameter name must survive into the message — that is the
  // whole point, it tells the dev what to rename in commands.rs.
  assert.ok(text.includes("provider"), "phải giữ tên tham số lỗi trong chi tiết");
});

test("arg mismatch: camelCase variant", () => {
  const err = {
    kind: "internal",
    message: "invalid args `providerId` for command `clear_provider_key`: invalid type: null",
  };
  assert.equal(classifyKeyError(err), "arg_mismatch");
});

test("arg mismatch: 'missing required field' wording", () => {
  assert.equal(
    classifyKeyError({ kind: "internal", message: "missing required field `key`" }),
    "arg_mismatch",
  );
});

test("arg mismatch wins over a message that also says 'not found'", () => {
  // Regression guard for the exact bug that was fixed: Tauri's argument
  // rejection is kind "internal" too, so a combined regex would classify this
  // as "not_registered" and report the wrong cause.
  const err = {
    kind: "internal",
    message: "invalid args for command `save_provider_key`: command not found in args",
  };
  assert.equal(classifyKeyError(err), "arg_mismatch");
});

/* ------------------------------------------------------------------ */
/* Branch 2 — command never registered in generate_handler!            */
/* ------------------------------------------------------------------ */

test("not registered: command not found", () => {
  const err = { kind: "internal", message: "Command save_provider_key not found" };
  assert.equal(classifyKeyError(err), "not_registered");
  assert.equal(describeKeyError(err), KEY_ERROR_NOT_REGISTERED);
});

test("not registered: unknown command", () => {
  assert.equal(
    classifyKeyError({ kind: "internal", message: "unknown command get_geo_db_versions" }),
    "not_registered",
  );
});

test("'not found' with a non-internal kind is NOT treated as unregistered", () => {
  // A 404 from a provider is a different story and must fall through verbatim.
  const err = { kind: "http", message: "resource not found" };
  assert.equal(classifyKeyError(err), "other");
  assert.equal(describeKeyError(err), "Không lưu được key: resource not found");
});

/* ------------------------------------------------------------------ */
/* Branch 3 — no IPC bridge                                            */
/* ------------------------------------------------------------------ */

test("no ipc: network kind", () => {
  const err = {
    kind: "network",
    message: "Không có kết nối tới Tauri core. Hãy chạy app bằng `npm run tauri:dev`…",
  };
  assert.equal(classifyKeyError(err), "no_ipc");
  assert.equal(describeKeyError(err), KEY_ERROR_NO_IPC);
});

/* ------------------------------------------------------------------ */
/* Branch 4 — genuine failures keep their original message             */
/* ------------------------------------------------------------------ */

test("other: keyring write failure is reported verbatim", () => {
  const err = {
    kind: "internal",
    message: "Credential Manager: access denied (0x80070005)",
  };
  assert.equal(classifyKeyError(err), "other");
  assert.ok(
    describeKeyError(err).includes("access denied"),
    "message gốc phải còn nguyên để còn debug được",
  );
});

test("other: empty and null inputs do not throw", () => {
  assert.equal(classifyKeyError(null), "other");
  assert.equal(classifyKeyError(undefined), "other");
  assert.equal(classifyKeyError({}), "other");
  assert.equal(classifyKeyError({ message: "" }), "other");
  assert.equal(describeKeyError(null), "Không lưu được key: ");
});

test("classifier never returns two branches for one input", () => {
  // Exhaustive-ish sweep: every sample must land in exactly one branch, and the
  // four messages must all be distinct so the banner can never be ambiguous.
  const samples = [
    { kind: "internal", message: "invalid args `provider` for command `x`" },
    { kind: "internal", message: "Command x not found" },
    { kind: "network", message: "no bridge" },
    { kind: "internal", message: "keyring exploded" },
  ];

  const branches = samples.map(classifyKeyError);
  assert.deepEqual(branches, ["arg_mismatch", "not_registered", "no_ipc", "other"]);

  const messages = samples.map(describeKeyError);
  assert.equal(new Set(messages).size, messages.length, "4 nhánh phải cho 4 câu khác nhau");
});
