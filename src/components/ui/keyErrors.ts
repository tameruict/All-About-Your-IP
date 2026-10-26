/**
 * Key-command error translation, kept in its own module so it can be unit
 * tested with plain `node --test` (no jsdom, no vitest, no Tauri).
 *
 * Why this lives outside App.tsx: the classifier is pure string logic, but a
 * wrong branch costs hours of debugging. A test must be able to import it
 * without dragging in React, `@tauri-apps/api` or a WebView, otherwise it can
 * never run in CI or on a machine without a display.
 *
 * The three failure families look almost identical as raw strings but need
 * completely different user actions, so the branch order is the contract:
 *
 * 1. ARG MISMATCH (Tauri v2 classic) — the JS side sends `{ provider_id }` while
 *    the Rust command declares `provider: String`. Tauri rejects with
 *    `invalid args `provider` for command `save_provider_key`: command missing
 *    required key provider`. This is a wiring bug between api.ts and commands.rs;
 *    telling the user their key is wrong would send them chasing a ghost.
 * 2. COMMAND NOT REGISTERED — the thunk exists in api.ts but is absent from
 *    `generate_handler!` ⇒ "not found" / "unknown command". Also not a key error.
 * 3. Anything else (keyring write failure, permissions, no IPC) — reported
 *    verbatim so the real message survives.
 *
 * NOTE the ordering trap: `invalid args` must be matched BEFORE the
 * not-registered branch. Tauri's unknown-command rejection and its bad-argument
 * rejection are both `kind: "internal"`, so a single combined regex would label
 * an argument typo as "backend chưa sẵn sàng" and hide the actual bug.
 */

/** Minimal shape this module needs; `IpcError` from api.ts satisfies it. */
export interface KeyErrorLike {
  kind?: string | null;
  message?: string | null;
}

export const KEY_ERROR_ARG_MISMATCH =
  "Lỗi tham số, KHÔNG phải lỗi key: backend khai báo sai tên tham số (snake_case vs camelCase).";

export const KEY_ERROR_NOT_REGISTERED =
  "Chưa hỗ trợ — backend chưa sẵn sàng (command lưu key chưa được đăng ký trong Tauri). Key chưa được lưu.";

export const KEY_ERROR_NO_IPC = "Không kết nối được tới core nên không lưu được key.";

/** Which branch a rejection lands in — exported so tests assert intent, not prose. */
export type KeyErrorBranch = "arg_mismatch" | "not_registered" | "no_ipc" | "other";

/**
 * Tauri v2 argument-name rejection.
 * Examples seen in the wild:
 *   invalid args `provider` for command `save_provider_key`: command missing required key provider
 *   invalid args `providerId` for command `clear_provider_key`: invalid type: null
 */
const ARG_MISMATCH_PATTERNS: RegExp[] = [
  /invalid args/i,
  /missing required key/i,
  /missing required (?:field|argument|parameter)/i,
  /command .* missing required/i,
];

/** The command exists but was never added to `generate_handler!`. */
const NOT_REGISTERED_PATTERNS: RegExp[] = [
  /not found/i,
  /unknown command/i,
  /not registered/i,
  /no command/i,
  /command .* does not exist/i,
];

function matchesAny(patterns: RegExp[], message: string): boolean {
  return patterns.some((pattern) => pattern.test(message));
}

/** Classifies a rejection into exactly one branch. */
export function classifyKeyError(err: KeyErrorLike | null | undefined): KeyErrorBranch {
  const message = err?.message ?? "";

  // Arg mismatch is checked first — see the ordering note above.
  if (matchesAny(ARG_MISMATCH_PATTERNS, message)) return "arg_mismatch";

  if ((err?.kind ?? null) === "internal" && matchesAny(NOT_REGISTERED_PATTERNS, message)) {
    return "not_registered";
  }

  if ((err?.kind ?? null) === "network") return "no_ipc";

  return "other";
}

/** Vietnamese message for the Settings panel banner. */
export function describeKeyError(err: KeyErrorLike | null | undefined): string {
  const message = err?.message ?? "";

  switch (classifyKeyError(err)) {
    case "arg_mismatch":
      // The underlying message is included: it names the offending parameter,
      // which is the fastest route to the fix in commands.rs.
      return `${KEY_ERROR_ARG_MISMATCH} Chi tiết: ${message}`;

    case "not_registered":
      return KEY_ERROR_NOT_REGISTERED;

    case "no_ipc":
      return KEY_ERROR_NO_IPC;

    default:
      return `Không lưu được key: ${message}`;
  }
}
