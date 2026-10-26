/**
 * IP Checker — typed wrappers over Tauri v2 `invoke()`.
 *
 * Every Tauri command from spec §4.2 is exposed here as a typed function.
 * The front-end must go through this module instead of calling `invoke`
 * directly, so command renames and arg-shape changes stay in one place.
 *
 * Rust arg naming: Tauri v2 camelCases command argument names by DEFAULT
 * (`tauri-macros` `rename_all` defaults to "camelCase"). Commands whose args
 * are multi-word must therefore opt in with
 * `#[tauri::command(rename_all = "snake_case")]` for the snake_case payloads
 * below (`check_id`, `provider_id`) to match. Single-word args (`input`,
 * `options`, `limit`) are unaffected either way, which is why this stayed
 * invisible until a two-word argument appeared.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

import type {
  CheckLogLine,
  CheckOptions,
  CheckProgressEvent,
  CheckSession,
  CheckSummary,
  CommandError,
  CommandMap,
  CommandName,
  ExportFormat,
  FullCheckResult,
  GeoDbVersion,
  ProviderHealth,
  Settings,
} from "./types";
import { CHECK_PROGRESS_EVENT } from "./types";

/* ------------------------------------------------------------------ */
/* Runtime detection + error normalisation                             */
/* ------------------------------------------------------------------ */

/**
 * True when running inside the Tauri WebView. `vite dev` in a plain browser
 * has no `__TAURI_INTERNALS__`, and every invoke would throw.
 */
export function isTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ !== "undefined"
  );
}

/** Stable error class for everything that crosses the IPC boundary. */
export class IpcError extends Error {
  readonly kind: string;
  readonly detail?: string | null;
  readonly command?: string;

  constructor(err: CommandError, command?: string) {
    super(err?.message ?? "Unknown IPC error");
    this.name = "IpcError";
    this.kind = err?.kind ?? "internal";
    this.detail = err?.detail ?? null;
    this.command = command;
  }
}

/** Normalises anything thrown by `invoke` into an `IpcError`. */
export function toIpcError(raw: unknown, command?: string): IpcError {
  if (raw instanceof IpcError) return raw;

  if (typeof raw === "string") {
    // Rust commands may return a plain string via Err(String).
    const looksJson = raw.trim().startsWith("{");
    if (looksJson) {
      try {
        const parsed = JSON.parse(raw) as CommandError;
        if (parsed && typeof parsed.message === "string") {
          return new IpcError(parsed, command);
        }
      } catch {
        /* fall through: plain message */
      }
    }
    return new IpcError({ kind: "internal", message: raw }, command);
  }

  if (raw && typeof raw === "object") {
    const maybe = raw as Partial<CommandError> & { message?: string };
    if (typeof maybe.message === "string") {
      return new IpcError(
        { kind: maybe.kind ?? "internal", message: maybe.message, detail: maybe.detail ?? null },
        command,
      );
    }
  }

  return new IpcError({ kind: "internal", message: String(raw) }, command);
}

/**
 * Single funnel for every command call.
 * Without Tauri (plain browser dev), throws a clear IpcError instead of a
 * cryptic "__TAURI_INTERNALS__ is undefined".
 */
async function call<K extends CommandName>(
  command: K,
  args?: CommandMap[K]["args"],
): Promise<CommandMap[K]["result"]> {
  if (!isTauri()) {
    throw new IpcError(
      {
        kind: "network",
        message:
          "Không có kết nối tới Tauri core. Hãy chạy app bằng `npm run tauri:dev` thay vì mở trong trình duyệt.",
      },
      command,
    );
  }
  try {
    // Tauri v2 expects the argument object to be passed directly.
    return (await invoke(command, (args ?? {}) as Record<string, unknown>)) as CommandMap[K]["result"];
  } catch (raw) {
    throw toIpcError(raw, command);
  }
}

/* ------------------------------------------------------------------ */
/* Commands (§4.2)                                                     */
/* ------------------------------------------------------------------ */

/**
 * Full check, resolves once every module finished.
 *
 * @param input "1.2.3.4" or "1.2.3.4:8080"
 * @param options proxy protocol / credentials / cache flags — credentials are
 *                transient and never persisted by the core.
 */
export function checkIp(input: string, options?: CheckOptions | null): Promise<CheckSession> {
  return call("check_ip", { input, options: options ?? null });
}

/**
 * Streaming check. Resolves with the finished session so the caller never has
 * to re-run the pipeline to learn what was stored.
 *
 * Per-module results still arrive on the `check-progress` event — subscribe
 * BEFORE calling this, otherwise early events are lost.
 *
 * Previously this resolved `void`, which forced `startCheck` to call `check_ip`
 * a second time: two orchestrator runs per click, two fresh `check_id`s, and a
 * front-end id that the cache never contained — so export looked up a row that
 * did not exist (`"Không có dữ liệu để xuất cho check_id ..."`) and one scan
 * cost twice the module budget. The old doc comment claimed it "returns as soon
 * as the job is registered", which was also wrong: it awaits completion.
 */
export function checkIpStream(
  input: string,
  options?: CheckOptions | null,
): Promise<CheckSession> {
  return call("check_ip_stream", { input, options: options ?? null });
}

/** Recent checks, newest first (§10.1 `checks`). */
export function getHistory(limit = 50): Promise<CheckSummary[]> {
  return call("get_history", { limit });
}

/**
 * Open an http(s) URL in the OS browser.
 *
 * The packaged webview has no implicit `<a target="_blank">` handler, so every
 * external source link is inert unless it comes through here. Outside Tauri
 * (plain `vite dev` in a browser) the anchor's own behaviour is enough.
 */
export async function openExternal(url: string): Promise<boolean> {
  if (!/^https?:\/\//i.test(url)) return false;
  if (!isTauri()) return false;
  try {
    await call("open_external", { url });
    return true;
  } catch (error) {
    console.warn("open_external failed:", toIpcError(error, "open_external").message);
    return false;
  }
}

/** Cached/full detail of one check, including every evidence row. */
export function getCheckDetail(checkId: string): Promise<FullCheckResult> {
  return call("get_check_detail", { check_id: checkId });
}

/** Writes an export file and resolves with the absolute path written (§10.3). */
export function exportReport(checkId: string, format: ExportFormat): Promise<string> {
  return call("export_report", { check_id: checkId, format });
}

/** Health snapshot of every provider (§5.5). */
export function getProviderHealth(): Promise<ProviderHealth[]> {
  return call("get_provider_health");
}

/** Persist settings. API keys inside `providers` are handled via Credential Manager. */
export function saveSettings(settings: Settings): Promise<void> {
  return call("save_settings", { settings });
}

/** Read settings; missing rows fall back to defaults in Rust. */
export function getSettings(): Promise<Settings> {
  return call("get_settings");
}

/* ------------------------------------------------------------------ */
/* Settings-panel extensions (§3.3, §7.3)                               */
/* ------------------------------------------------------------------ */

/**
 * Store one provider's API key in Windows Credential Manager.
 *
 * Wrapper for `save_provider_key` (§2.1, §3.3). The key never appears in the
 * settings JSON, in SQLite or in logs — see spec §11.
 */
export function saveProviderKey(providerId: string, key: string): Promise<void> {
  return call("save_provider_key", { provider_id: providerId, key });
}

/** Delete a provider's API key from Credential Manager. */
export function clearProviderKey(providerId: string): Promise<void> {
  return call("clear_provider_key", { provider_id: providerId });
}

/**
 * Version + date of each local geo database, for the Settings panel (§7.3, §3.3).
 * `stale` is true when the DB is older than 60 days.
 */
export function getGeoDbVersions(): Promise<GeoDbVersion[]> {
  return call("get_geo_db_versions");
}

/* ------------------------------------------------------------------ */
/* Streaming subscription (§4.2 `check-progress`)                      */
/* ------------------------------------------------------------------ */

export type ProgressHandler = (event: CheckProgressEvent) => void;
export type LogHandler = (line: CheckLogLine) => void;

/**
 * Subscribe to `check-progress`. Resolves with an unlisten function.
 *
 * ```ts
 * const unlisten = await onCheckProgress((e) => setModules(e.modules));
 * await checkIpStream("8.8.8.8");
 * // later: unlisten();
 * ```
 */
export function onCheckProgress(handler: ProgressHandler): Promise<UnlistenFn> {
  return listen<CheckProgressEvent>(CHECK_PROGRESS_EVENT, (event) => handler(event.payload));
}

/**
 * Subscribe only to events of one check id. Returns an unlisten function.
 * Useful because a stale check may still emit after the user starts a new one.
 */
export async function onCheckProgressFor(
  checkId: string,
  handler: ProgressHandler,
): Promise<UnlistenFn> {
  const unlisten = await onCheckProgress((event) => {
    if (event.check_id === checkId) handler(event);
  });
  return unlisten;
}

/**
 * Subscribe to `check-progress` while also collecting a human-readable log
 * (used by ScanProgress). One unlisten tears down both bindings.
 */
export async function onCheckStream(
  onProgress: ProgressHandler,
  onLog?: LogHandler,
): Promise<UnlistenFn> {
  const unlistenProgress = await onCheckProgress((event) => {
    onProgress(event);
    onLog?.({
      check_id: event.check_id,
      at: new Date().toISOString(),
      module: event.module,
      level: event.status === "error" ? "error" : event.status === "done" ? "success" : "info",
      message: event.message,
    });
  });
  return unlistenProgress;
}

/* ------------------------------------------------------------------ */
/* Small helpers used by the UI                                        */
/* ------------------------------------------------------------------ */

/** Ask the OS for a folder to export into (dialog plugin, capability `dialog:allow-open`). */
export async function pickExportDirectory(defaultPath?: string): Promise<string | null> {
  if (!isTauri()) return null;
  const picked = await open({
    directory: true,
    multiple: false,
    defaultPath: defaultPath && defaultPath.length > 0 ? defaultPath : undefined,
    title: "Chọn thư mục xuất báo cáo",
  });
  return typeof picked === "string" ? picked : null;
}

/** Reveal a written export file with the OS default handler. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Aggregate view: every evidence row fail/unknown, for the "thiếu dữ liệu" banner. */
export function missingEvidenceCount(result: FullCheckResult | null): number {
  if (!result) return 0;
  return result.evidence.filter((e) => e.signal === "Unknown").length;
}

/** True when the check was served from cache and the UI must show the old timestamp. */
export function isCached(result: FullCheckResult | null): boolean {
  return Boolean(result?.from_cache);
}

/* ------------------------------------------------------------------ */
/* Namespace export (convenient for components)                        */
/* ------------------------------------------------------------------ */

export const api = {
  checkIp,
  checkIpStream,
  getHistory,
  getCheckDetail,
  exportReport,
  getProviderHealth,
  saveSettings,
  getSettings,
  saveProviderKey,
  clearProviderKey,
  getGeoDbVersions,
  openExternal,
  onCheckProgress,
  onCheckProgressFor,
  onCheckStream,
  pickExportDirectory,
  isTauri,
} as const;

export type Api = typeof api;
