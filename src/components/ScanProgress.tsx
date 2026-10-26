/**
 * ScanProgress — §3.2 row 4 + §3.3.
 *
 * Every module renders one of the five states pending / running / done / error /
 * skipped, and a skipped module must say WHY in Vietnamese: missing key,
 * needs proxy, quota exhausted (§3.3). Results are rendered as they arrive —
 * the parent feeds this component from the `check-progress` stream, so nothing
 * waits for the slowest module (§4.3 partial results).
 */

import { useEffect, useRef, useState } from "react";

import type { CheckLogLine, FullCheckResult, ModuleId, ModuleState } from "../lib/types";
import { useI18n, type Language, DICTIONARY } from "../lib/i18n";
import {
  cx,
  DASH,
  getLocalizedModuleLabel,
  getLocalizedProgressMessage,
  getLocalizedSkipReasonLabel,
  getLocalizedStatusLabel,
  MODULE_LABELS,
  MODULE_ORDER,
  NOT_MEASURED_PROXY,
  skipReasonLabel,
  STATUS_GLYPH,
  STATUS_LABELS,
} from "./ui/meta";

export interface ScanProgressProps {
  modules: ModuleState[];
  /** Console lines derived from the stream, newest last. */
  log: CheckLogLine[];
  /** True while a check is streaming. */
  active: boolean;
  /** Completed or partial check result, used to synthesize states when modules are absent (e.g. history). */
  result?: FullCheckResult | null;
  /** Overall done/total for the header hint. */
  doneCount: number;
  totalCount: number;
  /** Retry a whole module where the backend supports it (§3.4). */
  onRetryModule?: (module: ModuleId) => void;
  canRetry?: boolean;
}

function moduleOrderIndex(module: ModuleId): number {
  const index = MODULE_ORDER.indexOf(module);
  return index === -1 ? MODULE_ORDER.length : index;
}

/** Right-hand annotation for one module chip. */
function noteFor(state: ModuleState, lang: Language = "vi"): { text: string; cls: string } {
  switch (state.status) {
    case "running":
      return {
        text: state.providers_total > 0 ? `${state.providers_done}/${state.providers_total}` : `${state.progress}%`,
        cls: "",
      };
    case "skipped":
      return { text: getLocalizedSkipReasonLabel(state.skip_reason, lang), cls: "prog__note--skipped" };
    case "error":
      return {
        text: state.error?.kind ? localizedLageKind(state.error.kind, lang) : getLocalizedStatusLabel("error", lang),
        cls: "prog__note--error",
      };
    case "done":
      return {
        text: state.providers_total > 0 ? `${state.providers_done}/${state.providers_total}` : "✓",
        cls: "",
      };
    default:
      return { text: getLocalizedStatusLabel("pending", lang), cls: "" };
  }
}

/** Very short error tag for the 126px chip. */
function localizedLageKind(kind: string, lang: Language): string {
  const dict = DICTIONARY[lang].error_kinds;
  const key = kind as keyof typeof dict;
  return dict[key] ?? kind;
}

export function ScanProgress({
  modules,
  log,
  active,
  result,
  doneCount,
  totalCount,
  onRetryModule,
  canRetry,
}: ScanProgressProps) {
  const { lang, t } = useI18n();
  const scanning = active;
  // Guarantee every known module is visible even before the stream reaches it.
  const ordered = [...modules].sort((a, b) => moduleOrderIndex(a.module) - moduleOrderIndex(b.module));
  const known = new Set(ordered.map((item) => item.module));
  const synthesizeModule = (id: ModuleId, existing?: ModuleState): ModuleState => {
    const isProxyOnly = id === "exit_ip" || id === "leak" || id === "speed";
    if (isProxyOnly && (result?.mode === "ip_only" || existing?.skip_reason === "requires_proxy")) {
      return {
        module: id,
        status: "skipped",
        progress: 100,
        started_at: existing?.started_at ?? null,
        finished_at: existing?.finished_at ?? result?.checked_at ?? null,
        providers_done: existing?.providers_done ?? 0,
        providers_total: existing?.providers_total ?? 0,
        skip_reason: "requires_proxy",
        message: NOT_MEASURED_PROXY,
        error: null,
      };
    }
    if (!scanning && result) {
      return {
        module: id,
        status: "done",
        progress: 100,
        started_at: existing?.started_at ?? null,
        finished_at: existing?.finished_at ?? result.checked_at ?? null,
        providers_done: existing?.providers_done ?? 0,
        providers_total: existing?.providers_total ?? 0,
        skip_reason: null,
        message: existing?.message ?? "",
        error: null,
      };
    }
    return (
      existing ?? {
        module: id,
        status: "pending",
        progress: 0,
        started_at: null,
        finished_at: null,
        providers_done: 0,
        providers_total: 0,
        skip_reason: null,
        message: "",
        error: null,
      }
    );
  };
  const normalizedOrdered = ordered.map((item) =>
    !scanning && result && item.status === "pending"
      ? synthesizeModule(item.module, item)
      : item,
  );
  const placeholders: ModuleState[] = MODULE_ORDER.filter((module) => !known.has(module)).map(
    (module) => synthesizeModule(module),
  );
  const all = [...normalizedOrdered, ...placeholders].sort(
    (a, b) => moduleOrderIndex(a.module) - moduleOrderIndex(b.module),
  );

  const effectiveDoneCount =
    !scanning && result
      ? all.filter((s) => s.status === "done" || s.status === "error" || s.status === "skipped").length
      : doneCount;
  const effectiveTotalCount = !scanning && result ? all.length : totalCount;

  const shownLog = log.slice(-12);
  const failedCount = all.filter((state) => state.status === "error").length;
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (active) setCollapsed(false);
  }, [active]);

  /* The console used to render the OLDEST visible lines: the box is a fixed
     74px scroller that was never scrolled, so new lines appended below the fold
     and the user read stale output. Follow the tail instead. */
  const logRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const node = logRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [log.length, shownLog.length]);

  /* Exactly one polite announcement, made when a run ends. Announcing every
     progress tick would drown a screen reader. */
  const announcement =
    !active && effectiveDoneCount > 0
      ? lang === "en"
        ? `Completed scan of ${effectiveDoneCount}/${effectiveTotalCount || effectiveDoneCount} modules${
            failedCount > 0 ? `, ${failedCount} module(s) failed` : ""
          }.`
        : lang === "zh"
        ? `已完成扫描 ${effectiveDoneCount}/${effectiveTotalCount || effectiveDoneCount} 个模块${
            failedCount > 0 ? `，${failedCount} 个模块发生错误` : ""
          }。`
        : `Đã quét xong ${effectiveDoneCount}/${effectiveTotalCount || effectiveDoneCount} module${
            failedCount > 0 ? `, ${failedCount} module lỗi` : ""
          }.`
      : "";

  return (
    <section className="panel panel--flush" aria-label={t("progress.title")}>
      <header className="panel__head">
        <h2 className="panel__title">{t("progress.title")}</h2>
        <div className="row">
          <div className="panel__hint">
            {effectiveTotalCount > 0
              ? t("progress.modules_count", { done: effectiveDoneCount, total: effectiveTotalCount })
              : t("verdict.not_checked")}
            {active ? " · streaming" : ""}
          </div>
          <button
            type="button"
            className="scan__toggle"
            onClick={() => setCollapsed((v) => !v)}
            aria-expanded={!collapsed}
            title={
              collapsed
                ? lang === "en"
                  ? "Expand progress details & logs"
                  : lang === "zh"
                  ? "展开进度详情与日志"
                  : "Mở rộng chi tiết tiến trình & log"
                : lang === "en"
                ? "Collapse progress to expand cards area"
                : lang === "zh"
                ? "收起进度以扩大卡片区域"
                : "Thu gọn tiến trình để mở rộng vùng thẻ kết quả"
            }
          >
            {collapsed
              ? lang === "en"
                ? "▾ Expand"
                : lang === "zh"
                ? "▾ 展开"
                : "▾ Mở rộng"
              : lang === "en"
              ? "▴ Collapse"
              : lang === "zh"
              ? "▴ 收起"
              : "▴ Thu gọn"}
          </button>
        </div>
      </header>

      {!collapsed ? (
        <div className="panel__body panel__body--tight">
        <div className="prog">
          {all.map((state) => {
            const note = noteFor(state, lang);
            const moduleName = getLocalizedModuleLabel(state.module, lang);
            const statusLabel = getLocalizedStatusLabel(state.status, lang);
            const retryable =
              state.status === "error" && typeof onRetryModule === "function" && canRetry;
            return (
              <div
                key={state.module}
                className={cx("prog__item", `prog__item--${state.status}`)}
                title={
                  getLocalizedProgressMessage(state.message, lang) ||
                  `${moduleName} — ${statusLabel}${
                    state.skip_reason ? ` (${getLocalizedSkipReasonLabel(state.skip_reason, lang)})` : ""
                  }`
                }
              >
                <span className={cx("prog__glyph", `prog__glyph--${state.status}`)} aria-hidden="true">
                  {STATUS_GLYPH[state.status]}
                </span>
                <span className={cx("prog__name", `prog__name--${state.status}`)}>
                  {moduleName}
                </span>
                <span className="sr-only">{statusLabel}</span>
                <span className={cx("prog__note", note.cls)}>{note.text}</span>
                {retryable ? (
                  <button
                    type="button"
                    className="btn btn--icon btn--ghost"
                    onClick={() => onRetryModule?.(state.module)}
                    title={t("progress.retry_module", { module: moduleName })}
                    aria-label={t("progress.retry_module", { module: moduleName })}
                  >
                    ↻
                  </button>
                ) : null}
                {state.status === "running" ? (
                  <div
                    className="prog__bar"
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={state.progress}
                  >
                    <div className="prog__barfill" style={{ width: `${Math.max(4, state.progress)}%` }} />
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>

        {/* Live log tail. Kept small so the layout stays one screen (§3.2). */}
        <div className="prog__console" ref={logRef} aria-live="off">
          {shownLog.length === 0 ? (
            <div className="prog__line">
              <span className="prog__time">{DASH}</span>
              <span className="prog__text">{t("progress.logs")} — {t("verdict.no_verdict_hint")}</span>
            </div>
          ) : (
            shownLog.map((line, index) => (
              <div
                key={`${line.at}-${line.module}-${line.level}-${index}`}
                className={cx("prog__line", line.level !== "info" && `prog__line--${line.level}`)}
              >
                <span className="prog__time">{line.at ? line.at.slice(11, 19) : DASH}</span>
                <span className="prog__text" title={getLocalizedProgressMessage(line.message, lang)}>
                  {getLocalizedModuleLabel(line.module, lang)}: {getLocalizedProgressMessage(line.message, lang)}
                </span>
              </div>
            ))
          )}
        </div>

        {/* One polite status line: the graph and the chips are invisible to AT. */}
        <span className="sr-only" role="status" aria-live="polite">
          {announcement}
        </span>
      </div>
      ) : (
        <span className="sr-only" role="status" aria-live="polite">
          {announcement}
        </span>
      )}
    </section>
  );
}

export default ScanProgress;
