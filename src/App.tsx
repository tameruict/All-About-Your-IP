/**
 * App — the single-screen layout of §3.2.
 *
 *   HEADER
 *   INPUT CONSOLE
 *   VERDICT HUD
 *   SCAN PROGRESS   (streaming `check-progress`)
 *   ┌ TỔNG QUAN ┬ LOCATION MAP ┬ REPUTATION ┐
 *   ├ BLACKLIST ┬ MẠNG ───────┬ LEAK+TỐC ĐỘ ┤
 *   └ BẰNG CHỨNG (full width) ──────────────┘
 *   LỊCH SỬ + [Xuất JSON] [Xuất CSV] [Copy báo cáo]
 *
 * Everything arrives through the `check-progress` event (§3.3: render as it
 * arrives, never wait for the slowest module). Scoring is NOT computed here
 * (§4.1) — the UI only renders `clean_score` / `confidence_score` / `verdict`
 * sent by the backend.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  api,
  copyText,
  getCheckDetail,
  IpcError,
  isTauri,
  toIpcError,
} from "./lib/api";
import type {
  CheckLogLine,
  CheckProgressEvent,
  CheckSession,
  CheckSummary,
  FullCheckResult,
  GeoDbVersion,
  ModuleId,
  ModuleState,
  ProviderHealth,
  Settings,
} from "./lib/types";

import AppHeader from "./components/AppHeader";
import InputConsole, { type ScanRequest } from "./components/InputConsole";
import VerdictHUD from "./components/VerdictHUD";
import ScanProgress from "./components/ScanProgress";
import OverviewCard from "./components/OverviewCard";
import GeoMapCard from "./components/GeoMapCard";
import ReputationCard, { reputationQuotaNotice } from "./components/ReputationCard";
import BlacklistTable from "./components/BlacklistTable";
import NetworkCard from "./components/NetworkCard";
import LeakSpeedCard from "./components/LeakSpeedCard";
import EvidenceTable from "./components/EvidenceTable";
import HistoryPanel from "./components/HistoryPanel";
import SettingsPanel from "./components/SettingsPanel";
import { Banner } from "./components/ui/parts";
import { describeKeyError } from "./components/ui/keyErrors";
import { isScannable } from "./components/ui/ipInput";
import {
  cacheNote,
  cx,
  DASH,
  fmtTime,
  getLocalizedCacheNote,
  getLocalizedInputMessage,
  getLocalizedIpTypeLabel,
  getLocalizedSignalMeta,
  getLocalizedVerdictMeta,
  getLocalizedVerdictReason,
  MODULE_ORDER,
  normalizeLanguage,
} from "./components/ui/meta";
import {
  useI18n,
  type Language,
  DICTIONARY,
  tLang,
  STORAGE_LOCALE_KEY,
  VI_DICTIONARY,
  EN_DICTIONARY,
  ZH_DICTIONARY,
} from "./lib/i18n";

/* ------------------------------------------------------------------ */
/* Local state shape                                                   */
/* ------------------------------------------------------------------ */

interface UiState {
  /** Latest module states, keyed by module id, merged incrementally. */
  modules: ModuleState[];
  /** Console lines from the stream. */
  log: CheckLogLine[];
  /** Merged result while streaming (partial) and after completion (final). */
  result: FullCheckResult | null;
  checking: boolean;
  checkId: string | null;
  startedAt: string | null;
}

/**
 * Banner notice for export/copy outcomes — tone matters, a failure is not "info".
 */
interface ExportNotice {
  tone: "info" | "success" | "error";
  text: string;
  path?: string | null;
}

const EMPTY_STATE: UiState = {
  modules: [],
  log: [],
  result: null,
  checking: false,
  checkId: null,
  startedAt: null,
};

const LOG_LIMIT = 80;

/**
 * Titles this component sets for an input that cannot be scanned.
 *
 * Used only to decide whether a *new* parsed value should clear the previous
 * banner. Matching on a list beats matching on `/private|reserved/` because the
 * reason is no longer always about reserved ranges — `0.0.0.0:1080` is refused
 * for being undialable, and an invented regex would silently keep that banner
 * stuck on screen after the user fixed the input.
 */
const INPUT_BANNER_TITLES = [
  VI_DICTIONARY.banners.input_not_scannable,
  EN_DICTIONARY.banners.input_not_scannable,
  ZH_DICTIONARY.banners.input_not_scannable,
  VI_DICTIONARY.banners.private_ip_stopped,
  EN_DICTIONARY.banners.private_ip_stopped,
  ZH_DICTIONARY.banners.private_ip_stopped,
  VI_DICTIONARY.banners.private_no_api,
  EN_DICTIONARY.banners.private_no_api,
  ZH_DICTIONARY.banners.private_no_api,
  "Không check được input này",
  "Cannot check this input",
  "无法检测此输入",
  "IP private / reserved — chưa gửi lên provider nào",
  "Private / reserved IP — no provider contacted",
  "私有 / 保留 IP — 未请求任何接口",
  "IP private / reserved — đã dừng",
  "Private / reserved IP — stopped",
  "IP private / reserved — không gọi API",
  "Private / reserved IP — no API called",
];

function isInputBanner(title: string): boolean {
  return INPUT_BANNER_TITLES.includes(title);
}

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export function App() {
  const { lang, setLang, t } = useI18n();
  const [ui, setUi] = useState<UiState>(EMPTY_STATE);
  const [history, setHistory] = useState<CheckSummary[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [health, setHealth] = useState<ProviderHealth[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [savingSettings, setSavingSettings] = useState(false);

  const [banner, setBanner] = useState<{ tone: "info" | "warn" | "error" | "conflict" | "muted"; title: string; detail?: string } | null>(null);
  const [offline, setOffline] = useState<boolean>(!navigator.onLine);
  const [bridgeMissing, setBridgeMissing] = useState<boolean>(!isTauri());
  const [exportNotice, setExportNotice] = useState<ExportNotice | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  /** Geo DB versions load at mount so Settings is useful before any check (§3.3, §7.3). */
  const [geoDbVersions, setGeoDbVersions] = useState<GeoDbVersion[]>([]);

  const unlistenRef = useRef<(() => void) | null>(null);
  const runTokenRef = useRef(0);
  const settingsRef = useRef<HTMLDivElement | null>(null);

  /* ---------------- bootstrap ---------------- */

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const rows = await api.getHistory(50);
      setHistory(rows);
      /* A completed IPC round-trip proves the core is reachable. Without this
         the offline banner could only be cleared by a browser `online` event,
         so one transient failure pinned "Không có mạng" on screen forever. */
      setOffline(false);
    } catch (error) {
      const err = toIpcError(error, "get_history");
      if (err.kind === "network") setOffline(true);
      setHistoryError(err.message);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadHealth = useCallback(async () => {
    try {
      setHealth(await api.getProviderHealth());
    } catch {
      /* health is advisory; a failure must not block the UI */
    }
  }, []);

  const loadSettings = useCallback(async () => {
    try {
      const loaded = await api.getSettings();
      setSettings(loaded);
      setSettingsError(null);
      // In loadSettings, if localStorage has no stored locale, sync setLang with settings.ui_language if valid
      if (typeof window !== "undefined" && window.localStorage) {
        const stored = window.localStorage.getItem(STORAGE_LOCALE_KEY);
        if (!stored && loaded.ui_language) {
          const norm = normalizeLanguage(loaded.ui_language);
          if (norm === "vi" || norm === "en" || norm === "zh") {
            setLang(norm);
          }
        }
      }
    } catch (error) {
      const err = toIpcError(error, "get_settings");
      setSettingsError(err.message);
    }
  }, [setLang]);

  /**
   * Geo DB metadata. Read once at mount (so Settings shows version + date before
   * the first check) and again after a check, in case the backend refreshed it.
   * A missing command degrades to the versions embedded in the last result.
   */
  const loadGeoDbVersions = useCallback(async () => {
    try {
      setGeoDbVersions(await api.getGeoDbVersions());
    } catch {
      /* fall back to result.geo_db_versions when the command is not registered */
    }
  }, []);

  useEffect(() => {
    setBridgeMissing(!isTauri());
    void loadHistory();
    void loadHealth();
    void loadSettings();
    void loadGeoDbVersions();
  }, [loadHistory, loadHealth, loadSettings, loadGeoDbVersions]);

  // Network state → offline banner (§3.4 "Không có mạng → banner rõ ràng").
  useEffect(() => {
    const onOnline = () => setOffline(false);
    const onOffline = () => setOffline(true);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, []);

  // Tear the event subscription down with the app.
  useEffect(
    () => () => {
      unlistenRef.current?.();
      unlistenRef.current = null;
    },
    [],
  );

  /**
   * Settings drawer: Escape closes it and focus moves inside, so it behaves like
   * the modal it visually is instead of a div the keyboard can walk out of.
   */
  useEffect(() => {
    if (!settingsOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSettingsOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    settingsRef.current?.focus();
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [settingsOpen]);

  /* ---------------- streaming ---------------- */

  const applyProgress = useCallback((event: CheckProgressEvent) => {
    setUi((current) => {
      if (current.checkId && event.check_id !== current.checkId) return current;

      const merged = new Map<ModuleId, ModuleState>();
      for (const module of current.modules) merged.set(module.module, module);
      for (const module of event.modules ?? []) merged.set(module.module, module);

      // Event-level status wins for the module it describes.
      const previous = merged.get(event.module);
      const evModule = event.modules?.find((m) => m.module === event.module);
      merged.set(event.module, {
        module: event.module,
        status: event.status,
        progress: event.progress,
        started_at: previous?.started_at ?? event.started_at ?? null,
        finished_at:
          event.status === "done" || event.status === "error" || event.status === "skipped"
            ? new Date().toISOString()
            : null,
        providers_done: evModule?.providers_done ?? previous?.providers_done ?? 0,
        providers_total: evModule?.providers_total ?? previous?.providers_total ?? 0,
        skip_reason: evModule?.skip_reason ?? previous?.skip_reason ?? null,
        message: event.message,
        error: evModule?.error ?? previous?.error ?? null,
      });

      let result: FullCheckResult | null = current.result;
      if (event.partial) {
        const partial = event.partial as Record<string, unknown>;
        result = {
          ...(current.result ?? ({} as FullCheckResult)),
          ...partial,
        };
        if (event.module === "scoring") {
          if (partial.confidence_score !== undefined && partial.confidence === undefined) {
            result.confidence_score = partial.confidence_score as number;
          } else if (partial.confidence !== undefined) {
            result.confidence_score = partial.confidence as number;
          }
          if (partial.verdict_reason !== undefined) {
            result.verdict_reason = partial.verdict_reason as string;
          }
          if (partial.clean_score !== undefined) {
            result.clean_score = partial.clean_score as number | null;
          }
          if (partial.clean_score_provisional !== undefined) {
            result.clean_score_provisional = Boolean(partial.clean_score_provisional);
          }
          if (partial.verdict !== undefined) {
            result.verdict = partial.verdict as any;
          }
        }
      }

      const log: CheckLogLine[] = event.message
        ? [
            ...current.log,
            {
              check_id: event.check_id,
              at: new Date().toISOString(),
              module: event.module,
              level: event.status === "error" ? "error" : event.status === "done" ? "success" : "info",
              message: event.message,
            } satisfies CheckLogLine,
          ].slice(-LOG_LIMIT)
        : current.log;

      return {
        ...current,
        checkId: event.check_id,
        startedAt: event.started_at ?? current.startedAt,
        modules: [...merged.values()],
        result,
        log,
      };
    });
  }, []);

  /**
   * Starts a streamed check. Per §4.2 the subscriber is registered BEFORE the
   * command runs, otherwise early events are lost.
   */
  const startCheck = useCallback(
    async (request: ScanRequest, forceFresh: boolean) => {
      const token = runTokenRef.current + 1;
      runTokenRef.current = token;

      setBanner(null);
      setExportNotice(null);
      setUi({ ...EMPTY_STATE, checking: true });

      unlistenRef.current?.();
      unlistenRef.current = null;

      try {
        const unlisten = await api.onCheckProgress((event) => {
          if (runTokenRef.current !== token) return;
          applyProgress(event);
        });
        unlistenRef.current = unlisten;

        const session: CheckSession = await api.checkIpStream(request.input, {
          protocol: request.protocol,
          credentials: request.credentials,
          save_to_history: request.saveToHistory,
          use_cache: !forceFresh,
          run_leak_check: settings?.leak_check_enabled,
          run_speed_check: settings?.speed_check_enabled,
          timeout_ms: settings?.default_timeout_ms,
        });
        // The second `check_ip` call is gone: it re-ran all 13 modules with a
        // fresh `check_id` and `save_to_history: false`, so `session.check_id`
        // pointed at a row the cache had never written — export then failed
        // with "Không có dữ liệu để xuất", the history entry showed a different
        // id than the panel, and one click cost twice the module budget.
        // One click is one run.

        if (runTokenRef.current !== token) return;

        /* The stream came back, so the bridge and the network are alive. */
        setOffline(false);

        setUi((current) => ({
          ...current,
          checking: false,
          checkId: session.check_id ?? current.checkId,
          modules: session.modules?.length ? session.modules : current.modules,
          result: session.result ?? current.result,
        }));

        if (session.result?.from_cache) {
          setBanner({
            tone: "muted",
            title: t("banners.cache_note_title", {
              time: fmtTime(session.result.checked_at),
            }),
            detail: t("banners.cache_note_hint"),
          });
        }

        if (request.saveToHistory) void loadHistory();
        void loadHealth();
      } catch (error) {
        if (runTokenRef.current !== token) return;
        const err = toIpcError(error, "check_ip_stream");
        setUi((current) => ({ ...current, checking: false }));

        if (err.kind === "private_ip") {
          // §3.4: private / reserved stops immediately, no API calls were made.
          setBanner({
            tone: "error",
            title: t("banners.private_ip_stopped"),
            detail: err.detail ?? err.message,
          });
        } else if (err.kind === "network") {
          setOffline(true);
          setBanner({
            tone: "error",
            title: t("banners.no_core_connection"),
            detail: err.message,
          });
        } else {
          setBanner({
            tone: "error",
            title: t("banners.check_failed"),
            detail: err.message,
          });
        }
      } finally {
        // §3.3 — the console must never stay locked. This runs on success, on
        // error, AND on the early-return paths above (the `runTokenRef` guard
        // at line 275 exits `try` without reaching either the success block or
        // `catch`, which used to leave `checking` stuck `true` forever: the
        // "Đang quét" chip stayed up and the input stayed disabled). Only the
        // current run may clear the flag, so a superseded run cannot unlock a
        // newer one. The identity check inside the updater avoids allocating a
        // new state object — and a re-render — when nothing changed.
        if (runTokenRef.current === token) {
          setUi((current) => (current.checking ? { ...current, checking: false } : current));
        }
        unlistenRef.current?.();
        unlistenRef.current = null;
      }
    },
    [applyProgress, loadHealth, loadHistory, t],
  );

  const onSubmit = useCallback(
    (request: ScanRequest) => {
      if (!request.input.trim()) return;
      void startCheck(request, false);
    },
    [startCheck],
  );

  /* ---------------- history / cache ---------------- */

  const openFromCache = useCallback(async (summary: CheckSummary) => {
    /* Opening a cached row while a live run is streaming used to leave two
       writers on `ui.result`: progress events were dropped (checkId mismatch)
       but the in-flight `checkIpStream` still overwrote the row on resolve.
       Cancel the run first — one owner at a time. */
    runTokenRef.current += 1;
    unlistenRef.current?.();
    unlistenRef.current = null;
    setUi((current) => ({ ...current, checking: false }));
    try {
      const detail = await getCheckDetail(summary.check_id);
      setUi((current) => ({
        ...current,
        result: detail,
        checkId: detail.check_id ?? summary.check_id,
        startedAt: detail.checked_at ?? current.startedAt,
        modules: detail.modules ?? [],
        log: [],
      }));
      setBanner({
        tone: "muted",
        title: t("banners.cache_detail_title", {
          time: fmtTime(detail.checked_at ?? summary.checked_at),
        }),
        detail: t("banners.cache_detail_hint"),
      });
    } catch (error) {
      const err = toIpcError(error, "get_check_detail");
      setBanner({
        tone: "error",
        title: t("banners.cannot_read_cache"),
        detail: err.message,
      });
    }
  }, [t]);

  const recheckFromHistory = useCallback(
    (summary: CheckSummary) => {
      const input = summary.proxy_host
        ? `${summary.proxy_host}${summary.proxy_port ? `:${summary.proxy_port}` : ""}`
        : summary.ip;
      void startCheck(
        {
          input,
          mode: summary.mode === "proxy" ? "proxy" : "ip_only",
          protocol: summary.proxy_protocol ?? "http",
          credentials: null,
          saveToHistory: true,
        },
        true,
      );
    },
    [startCheck],
  );

  /* ---------------- export (§10.3) ---------------- */

  const doExport = useCallback(
    async (format: "json" | "csv") => {
      const checkId = ui.checking ? null : ui.result?.check_id;
      if (!checkId) {
        setExportNotice({
          tone: "info",
          text: ui.checking
            ? t("banners.scanning_wait_export")
            : t("banners.no_result_to_export"),
        });
        return;
      }
      try {
        const path = await api.exportReport(checkId, format);
        setExportNotice({
          tone: "success",
          text: t("banners.exported_file", {
            format: format.toUpperCase(),
            file: baseName(path),
          }),
          path,
        });
      } catch (error) {
        const err = toIpcError(error, "export_report");
        setExportNotice({
          tone: "error",
          text: t("banners.export_file_error", {
            format: format.toUpperCase(),
            error: err.message,
          }),
        });
      }
    },
    [ui.checking, ui.result?.check_id, t],
  );

  const copySummary = useCallback(async () => {
    const result = ui.result;
    if (!result) {
      setExportNotice({
        tone: "info",
        text: t("banners.no_result_to_copy"),
      });
      return;
    }
    const lines = formatSummaryReport(result, lang);
    const ok = await copyText(lines);
    if (ok) {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 1600);
    }
    setExportNotice(
      ok
        ? {
            tone: "success",
            text: t("banners.copied_summary"),
          }
        : {
            tone: "error",
            text: t("banners.clipboard_blocked"),
          },
    );
  }, [ui.result, lang, t]);

  /* ---------------- settings ---------------- */

  const saveSettings = useCallback(async (next: Settings) => {
    setSavingSettings(true);
    setSettingsError(null);
    try {
      await api.saveSettings(next);
      setSettings(next);
      void loadHealth();
    } catch (error) {
      const err = toIpcError(error, "save_settings");
      setSettingsError(err.message);
    } finally {
      setSavingSettings(false);
    }
  }, [loadHealth]);

  const pickExportDir = useCallback(async () => {
    try {
      return await api.pickExportDirectory(settings?.export_dir);
    } catch {
      return null;
    }
  }, [settings?.export_dir]);

  /**
   * Key storage. The secret goes straight to `save_provider_key`, which is the
   * only path that reaches Windows Credential Manager (§2.1). Nothing is written
   * into settings: `has_key` is read-only state owned by the backend.
   *
   * The Rust thunk for these three commands may not be registered yet, so a
   * missing command is reported as "backend chưa sẵn sàng" instead of crashing
   * the panel.
   */
  const saveKey = useCallback(
    async (provider: string, secret: string) => {
      try {
        await api.saveProviderKey(provider, secret);
        await loadSettings();
        await loadHealth();
        setSettingsError(null);
      } catch (error) {
        setSettingsError(describeKeyError(toIpcError(error, "save_provider_key")));
      }
    },
    [loadHealth, loadSettings],
  );

  const clearKey = useCallback(
    async (provider: string) => {
      try {
        await api.clearProviderKey(provider);
        await loadSettings();
        await loadHealth();
        setSettingsError(null);
      } catch (error) {
        setSettingsError(describeKeyError(toIpcError(error, "clear_provider_key")));
      }
    },
    [loadHealth, loadSettings],
  );

  /* ---------------- derived values ---------------- */

  const result = ui.result;

  const modules = ui.modules;
  const doneCount = modules.filter(
    (module) => module.status === "done" || module.status === "error" || module.status === "skipped",
  ).length;
  /* While streaming the denominator is every module the run can cover, not the
     number of events received so far — the header used to read "1/1 module"
     next to a progress strip showing thirteen chips. */
  const totalCount = ui.checking ? Math.max(modules.length, MODULE_ORDER.length) : modules.length;

  const quotaNotice = useMemo(
    () => (result ? reputationQuotaNotice(result.evidence ?? [], lang) : null),
    [result, lang],
  );

  const privateBanner =
    result?.is_private === true
      ? {
          tone: "error" as const,
          title: t("banners.private_no_api"),
          detail: result.validation_error ?? t("banners.private_no_api_hint"),
        }
      : null;

  const cachedAt = result?.from_cache ? fmtTime(result.checked_at) : null;

  const mode = result?.mode ?? "unknown";

  /* Prefer the standalone command; fall back to whatever the last check reported
     so the panel is never empty when only the result path is wired. */
  const shownGeoDbs: GeoDbVersion[] =
    geoDbVersions.length > 0 ? geoDbVersions : result?.geo_db_versions ?? [];

  const canRetry = !ui.checking && !bridgeMissing;

  /* ---------------- render ---------------- */

  return (
    <div className="app">
      <div className="app__top">
        <AppHeader
          health={health}
          appVersion={result?.app_version ?? null}
          scanning={ui.checking}
          bridgeMissing={bridgeMissing}
          settingsOpen={settingsOpen}
          onToggleSettings={() => setSettingsOpen((open) => !open)}
        />

        <InputConsole
          scanning={ui.checking}
          disabled={bridgeMissing}
          onSubmit={onSubmit}
          initialValue={result?.ip ?? ""}
          onParsedChange={(parsed) => {
            if (parsed.kind === "invalid" || parsed.kind === "empty") return;
            // One question, one source of truth: `isScannable` decides whether
            // the Scan button is live, so it also decides whether a banner is
            // owed. Deriving this from `isPublic` alone left `0.0.0.0:1080`
            // (a proxy target the backend refuses as undialable) with a dead
            // Scan button and no explanation.
            if (!isScannable(parsed)) {
              setBanner({
                tone: "error",
                title: t("banners.input_not_scannable"),
                detail: getLocalizedInputMessage(parsed, lang),
              });
            } else if (banner?.tone === "error" && isInputBanner(banner.title)) {
              setBanner(null);
            }
          }}
        />

        <VerdictHUD
          ip={result?.ip ?? null}
          verdict={result?.verdict ?? null}
          verdictReason={result?.verdict_reason ?? null}
          cleanScore={result?.clean_score ?? null}
          cleanScoreProvisional={Boolean(
            result?.clean_score_provisional ||
            (result?.verdict === "Chưa đủ dữ liệu" && result?.clean_score != null)
          )}
          confidenceScore={result?.confidence_score ?? null}
          scoring={result?.scoring ?? null}
          live={ui.checking}
          fromCache={Boolean(result?.from_cache)}
          cachedAt={cachedAt}
          durationMs={result?.duration_ms ?? null}
          quorumMissing={(result?.scoring?.quorum ?? [])
            .filter((item) => !item.met)
            .map((item) => item.aspect)}
        />

        <ScanProgress
          modules={modules}
          log={ui.log}
          active={ui.checking}
          doneCount={doneCount}
          totalCount={totalCount}
          canRetry={canRetry}
          onRetryModule={(module) => {
            if (!result?.ip) return;
            /* `CheckOptions.modules` exists in the wire type but the Rust
               orchestrator never reads it, so a per-module re-run is not
               supported yet. Say so instead of pretending: the old handler
               silently re-ran all thirteen modules while the UI implied one. */
            setBanner({
              tone: "muted",
              title: t("banners.rerun_whole_suite", { module }),
              detail: t("banners.rerun_whole_suite_hint"),
            });
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />

        {/* ---- global banners (§3.4) ---- */}
        <div className="app__truthband">
          {bridgeMissing ? (
            <Banner
              tone="warn"
              title={t("banners.running_no_ipc")}
              detail={t("banners.running_no_ipc_hint")}
            />
          ) : null}

          {offline ? (
            <Banner
              tone="error"
              title={t("banners.no_network")}
              detail={t("banners.no_network_hint")}
              actions={
                <button type="button" className="btn btn--sm btn--ghost" onClick={() => void loadHistory()}>
                  ↻ {t("banners.reload_history")}
                </button>
              }
            />
          ) : null}

          {privateBanner ? <Banner tone={privateBanner.tone} title={privateBanner.title} detail={privateBanner.detail} /> : null}

          {quotaNotice ? (
            <Banner
              tone="warn"
              title={t("banners.quota_exhausted_penalty")}
              detail={t("banners.quota_penalty_hint", { notice: quotaNotice })}
            />
          ) : null}

          {banner ? <Banner tone={banner.tone} title={banner.title} detail={banner.detail} /> : null}

          {result?.scoring?.conflicts?.some((item) => item.severity === "hard") ? (
            <Banner
              tone="conflict"
              title={t("banners.hard_conflict")}
              detail={result.scoring.conflicts.find((item) => item.severity === "hard")?.message}
            />
          ) : null}

          {exportNotice ? (
            <Banner
              tone={exportNotice.tone === "error" ? "error" : "info"}
              title={exportNotice.text}
              detail={
                exportNotice.path ? (
                  <span className="mono tiny" title={exportNotice.path}>
                    {exportNotice.path}
                  </span>
                ) : undefined
              }
              actions={
                <button
                  type="button"
                  className="btn btn--sm btn--ghost"
                  aria-label={t("export.close_notice")}
                  onClick={() => setExportNotice(null)}
                >
                  ✕
                </button>
              }
            />
          ) : null}
        </div>
      </div>

      {/* ---- grid 3 x 2 (§3.2) ---- */}
      <div className="app__grid">
        <OverviewCard
          ip={result?.ip ?? null}
          mode={mode}
          ipVersion={result?.ip_version ?? null}
          asn={result?.asn ?? null}
          network={result?.network ?? null}
          country={result?.location?.country ?? null}
          loading={ui.checking}
          canRetry={canRetry}
          onRetry={() => {
            if (!result?.ip) return;
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />

        <GeoMapCard
          location={result?.location ?? null}
          checkedAt={cachedAt ?? (result?.checked_at ? fmtTime(result.checked_at) : null)}
          loading={ui.checking}
          canRetry={canRetry}
          offline={offline || bridgeMissing}
          onRetry={() => {
            if (!result?.ip) return;
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />

        <ReputationCard
          evidence={result?.evidence ?? []}
          loading={ui.checking}
          canRetry={canRetry}
          onRetryProvider={(providerId) => {
            void api.saveProviderKey(providerId, "").catch(() => {});
            if (!result?.ip) return;
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />

        <BlacklistTable
          dnsbl={result?.dnsbl ?? null}
          loading={ui.checking}
          canRetry={canRetry}
          onRetry={() => {
            if (!result?.ip) return;
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />

        <NetworkCard
          network={result?.network ?? null}
          loading={ui.checking}
          canRetry={canRetry}
          mode={mode}
          onRetry={() => {
            if (!result?.ip) return;
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />

        <LeakSpeedCard
          mode={mode}
          leak={result?.leak ?? null}
          speed={result?.speed ?? null}
          exitIp={result?.exit_ip ?? null}
          inputIp={result?.ip ?? null}
          loading={ui.checking}
          canRetry={canRetry}
          onRetry={() => {
            if (!result?.ip) return;
            const targetInput =
              result.mode === "proxy" && result.proxy_host
                ? `${result.proxy_host}${result.proxy_port ? `:${result.proxy_port}` : ""}`
                : result.ip;
            void startCheck(
              {
                input: targetInput,
                mode: result.mode === "proxy" ? "proxy" : "ip_only",
                protocol: result.proxy_protocol ?? "http",
                credentials: null,
                saveToHistory: false,
              },
              true,
            );
          }}
        />
      </div>

      {/* ---- evidence table (§3.2) ---- */}
      <div className="app__evidence">
        <EvidenceTable evidence={result?.evidence ?? []} loading={ui.checking} />
      </div>

      {/* ---- footer: history + export (§3.2) ---- */}
      <div className="foot">
        <HistoryPanel
          history={history}
          activeCheckId={ui.checkId}
          loading={historyLoading}
          error={historyError}
          onRetry={() => void loadHistory()}
          onOpen={(summary) => void openFromCache(summary)}
          onRecheck={recheckFromHistory}
          scanning={ui.checking}
          offline={offline || bridgeMissing}
        />

        <div className="foot__actions">
          <div className="foot__actionrow">
            <button
              type="button"
              className="btn btn--sm"
              onClick={() => void doExport("json")}
              disabled={!result?.check_id || ui.checking || bridgeMissing}
              title={t("export.export_json_tooltip")}
            >
              {t("history.export_json")}
            </button>
            <button
              type="button"
              className="btn btn--sm"
              onClick={() => void doExport("csv")}
              disabled={!result?.check_id || ui.checking || bridgeMissing}
              title={t("export.export_csv_tooltip")}
            >
              {t("history.export_csv")}
            </button>
          </div>
          <div className="foot__actionrow">
            <button
              type="button"
              className={cx("btn btn--sm btn--ghost", copiedReport && "btn--primary")}
              onClick={() => void copySummary()}
              disabled={!result || ui.checking}
              title={t("export.copy_summary_tooltip")}
            >
              {copiedReport ? t("common.copied") : t("history.copy_report")}
            </button>
            <button
              type="button"
              className="btn btn--sm btn--ghost"
              onClick={() => void loadHealth()}
              disabled={bridgeMissing}
              title={t("export.refresh_health_tooltip")}
            >
              {t("history.health_btn")}
            </button>
          </div>
          <span className="tiny muted nowrap">
            {result
              ? `${t("report.checked_at_label")} ${fmtTime(result.checked_at)}`
              : DASH}
          </span>
        </div>
      </div>

      {/* ---- settings drawer (§3.3) ---- */}
      {settingsOpen ? (
        <>
          <div
            className="settings-backdrop"
            onClick={() => setSettingsOpen(false)}
            aria-hidden="true"
          />
          <div
            ref={settingsRef}
            className="panel settings-drawer"
            role="dialog"
            aria-modal="true"
            aria-label={t("settings.title")}
            tabIndex={-1}
          >
            <SettingsPanel
              settings={settings}
              health={health}
              geoDbVersions={shownGeoDbs}
              appVersion={result?.app_version ?? null}
              onSave={saveSettings}
              onPickExportDir={pickExportDir}
              onSaveKey={saveKey}
              onClearKey={clearKey}
              onClose={() => setSettingsOpen(false)}
              saving={savingSettings}
              error={settingsError}
            />
          </div>
        </>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Error text for the key commands                                     */
/* ------------------------------------------------------------------ */

/* Classifier lives in ui/keyErrors.ts so it can be unit tested with plain
   `node --test` (see src/components/ui/keyErrors.test.mjs). */

/* ------------------------------------------------------------------ */
/* Summary text for the "Copy báo cáo" button (§10.3)                  */
/* ------------------------------------------------------------------ */

/** Windows and POSIX separators; the export path is whatever the backend wrote. */
function baseName(path: string): string {
  const parts = path.split(/[\\/]+/).filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : path;
}

export function formatSummaryReport(result: FullCheckResult, lang: Language = "vi"): string {
  const norm = normalizeLanguage(lang);
  const dict = DICTIONARY[norm];
  const location = result.location;
  const asn = result.asn;
  const listedCount = result.dnsbl?.total_listed ?? 0;
  const mainEvidence = (result.evidence ?? [])
    .filter((row) => row.signal !== "Unknown" && row.category === "fraud")
    .slice(0, 3)
    .map(
      (row) =>
        `${row.provider}: ${getLocalizedSignalMeta(row.signal, norm).label}${row.raw_score !== null ? ` (${row.raw_score})` : ""}`,
    );

  const modeLabel =
    result.mode === "proxy"
      ? norm === "zh"
        ? "代理检测"
        : "proxy-check"
      : norm === "zh"
      ? "仅 IP"
      : "IP-only";

  const verdictLabel = getLocalizedVerdictMeta(result.verdict, norm).displayLabel;
  const cleanLabel =
    result.clean_score !== null && result.clean_score !== undefined
      ? `${result.clean_score}/100${
          result.clean_score_provisional || result.verdict === "Chưa đủ dữ liệu"
            ? " [tạm tính]"
            : ""
        }`
      : DASH;
  const locStr =
    [location?.city, location?.region, location?.country].filter(Boolean).join(", ") || DASH;
  const asnStr = `${asn?.asn !== null && asn?.asn !== undefined ? `AS${asn.asn}` : DASH} · ${asn?.isp ?? asn?.organisation ?? DASH}`;
  const ipTypeStr = getLocalizedIpTypeLabel(asn?.ip_type, norm);

  const blacklistStr =
    listedCount > 0
      ? tLang(norm, "report.blacklist_hits", { count: listedCount })
      : dict.report.blacklist_clean;
  const fromCacheStr = result.from_cache ? dict.report.from_cache_note : "";
  const localizedReason = getLocalizedVerdictReason(result.verdict_reason, norm);

  const lines: string[] = [
    `=== ${dict.report.summary_title} ===`,
    `IP: ${result.ip} (${modeLabel})`,
    `${dict.report.verdict_label}: ${verdictLabel} — Clean ${cleanLabel}, Confidence ${result.confidence_score}%`,
    `${dict.report.reason_label}: ${localizedReason}`,
    `${dict.report.location_label}: ${locStr}`,
    `${dict.report.asn_label}: ${asnStr}`,
    `${dict.report.ip_type_label}: ${ipTypeStr}`,
    `${dict.report.blacklist_label}: ${blacklistStr}`,
  ];

  if (mainEvidence.length > 0) {
    const fraudLabel = norm === "zh" ? "欺诈" : "Fraud";
    lines.push(`${fraudLabel}: ${mainEvidence.join(" | ")}`);
  }

  lines.push(
    `${dict.report.checked_at_label}: ${fmtTime(result.checked_at)}${fromCacheStr}`,
  );

  const links = (result.evidence ?? [])
    .map((row) => row.source_url)
    .filter((url, index, all) => Boolean(url) && all.indexOf(url) === index)
    .slice(0, 3);
  if (links.length > 0) {
    lines.push(`${dict.report.sources_label}: ${links.join(" , ")}`);
  }

  return lines.join("\n");
}

export const buildSummaryText = formatSummaryReport;

export default App;
