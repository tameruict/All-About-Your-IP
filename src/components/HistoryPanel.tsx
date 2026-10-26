/**
 * HistoryPanel — §3.2 footer ("LỊCH SỬ") + §3.3 HistoryPanel requirements.
 *
 * Rules:
 * - clicking a row loads that check FROM CACHE and the UI must state
 *   "từ cache, check lúc HH:MM DD/MM" (§3.3, §3.4, §10.2);
 * - a separate "Check lại" button always forces a fresh request (§10.2);
 * - when there is no network the panel stays usable, because cached history is
 *   exactly what the offline banner points at (§3.4).
 */

import { useMemo, useState } from "react";
import type { CheckSummary } from "../lib/types";
import { Empty, Panel } from "./ui/parts";
import {
  cx,
  DASH,
  fmtInt,
  fmtTime,
  getLocalizedVerdictMeta,
  protocolLabel,
  valueOrDash,
} from "./ui/meta";
import { useI18n } from "../lib/i18n";

export interface HistoryPanelProps {
  history: CheckSummary[];
  /** Currently displayed check id, highlighted in the list. */
  activeCheckId?: string | null;
  loading?: boolean;
  /** Message from a failed history read; distinct from "the DB is empty". */
  error?: string | null;
  /** Retry the history read (rendered inside the panel on error). */
  onRetry?: () => void;
  /** Load from cache (§3.3). */
  onOpen: (summary: CheckSummary) => void;
  /** Force a fresh check, bypassing the cache (§10.2). */
  onRecheck: (summary: CheckSummary) => void;
  /** True while a scan is running, so "Check lại" can be disabled. */
  scanning?: boolean;
  /** Shown when IPC is unavailable offline but cache exists. */
  offline?: boolean;
}

export function HistoryPanel({
  history,
  activeCheckId,
  loading,
  error,
  onRetry,
  onOpen,
  onRecheck,
  scanning,
  offline,
}: HistoryPanelProps) {
  const { lang, t } = useI18n();
  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return history
      .filter((row) => {
        if (verdictFilter !== "all" && (row.verdict ?? "Chưa đủ dữ liệu") !== verdictFilter) {
          return false;
        }
        if (!q) return true;
        const target = row.proxy_host
          ? `${row.proxy_host}${row.proxy_port ? `:${row.proxy_port}` : ""}`
          : row.ip;
        return (
          target.toLowerCase().includes(q) ||
          row.ip.toLowerCase().includes(q) ||
          (row.verdict ?? "").toLowerCase().includes(q)
        );
      })
      .slice(0, 40);
  }, [history, query, verdictFilter]);

  return (
    <Panel
      title={t("history.title")}
      hint={
        <span className="hist__toolbar">
          <input
            type="search"
            className="hist__search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("history.search_placeholder")}
            aria-label={t("history.search_aria_label")}
          />
          <select
            className="hist__search"
            style={{ width: "auto" }}
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            aria-label={t("history.filter_verdict")}
          >
            <option value="all">
              {t("common.all")} ({history.length})
            </option>
            <option value="Sạch">{getLocalizedVerdictMeta("Sạch", lang).displayLabel}</option>
            <option value="Tạm">{getLocalizedVerdictMeta("Tạm", lang).displayLabel}</option>
            <option value="Nghi ngờ">{getLocalizedVerdictMeta("Nghi ngờ", lang).displayLabel}</option>
            <option value="Bẩn">{getLocalizedVerdictMeta("Bẩn", lang).displayLabel}</option>
            <option value="Chưa đủ dữ liệu">{getLocalizedVerdictMeta("Chưa đủ dữ liệu", lang).displayLabel}</option>
          </select>
        </span>
      }
      footer={
        <>
          <span>
            {offline ? t("cards.offline_viewing_cache") : t("cards.click_to_view_cache")}
          </span>
          <span className="mono">{t("cards.sqlite_local")}</span>
        </>
      }
      bodyClassName="panel__body--tight"
      className="foot__hist"
    >
      {rows.length === 0 ? (
        error ? (
          <Empty>
            <span>{t("history.cannot_read_history", { error })}</span>
            {onRetry ? (
              <button type="button" className="btn btn--sm btn--ghost" onClick={onRetry}>
                ↻ {t("common.retry")}
              </button>
            ) : null}
          </Empty>
        ) : (
          <Empty icon="📜">
            {loading ? t("history.reading_history") : t("history.no_history")}
          </Empty>
        )
      ) : (
        <div className="hist" role="list">
          {rows.map((row) => {
            const meta = getLocalizedVerdictMeta(row.verdict, lang);
            const active = row.check_id === activeCheckId;
            const target = row.proxy_host
              ? `${row.proxy_host}${row.proxy_port ? `:${row.proxy_port}` : ""}`
              : row.ip;
            const cleanStr = row.clean_score === null ? DASH : fmtInt(row.clean_score);
            const confStr = row.confidence_score === null ? DASH : fmtInt(row.confidence_score);
            const modeStr =
              row.mode === "proxy"
                ? `proxy ${protocolLabel(row.proxy_protocol)}`
                : lang === "zh"
                ? "纯IP"
                : "IP-only";
            const rowAria = t("history.row_aria_label", {
              target: valueOrDash(target),
              verdict: meta.displayLabel,
              clean: cleanStr,
              confidence: confStr,
              mode: modeStr,
              time: fmtTime(row.checked_at),
            });
            /* A row is a <div role="listitem"> holding two SIBLING buttons.
               Nesting a button (or role="button") inside another button is
               invalid HTML and breaks keyboard/screen-reader semantics, so the
               "open" action lives on its own real button. */
            return (
              <div
                key={row.check_id}
                role="listitem"
                className={cx("hist__row", active && "hist__row--active")}
              >
                <button
                  type="button"
                  className="hist__open"
                  onClick={() => onOpen(row)}
                  title={t("history.load_cache_tooltip")}
                  aria-current={active ? "true" : undefined}
                  aria-label={rowAria}
                >
                  <span className="row" style={{ minWidth: 0, gap: 8 }}>
                    <span className="hist__ip">{valueOrDash(target)}</span>
                    <span className={cx("chip", `chip--${meta.cls}`)}>
                      {meta.displayLabel}
                    </span>
                    <span className="tiny muted nowrap">
                      {row.mode === "proxy"
                        ? `proxy · ${protocolLabel(row.proxy_protocol)}`
                        : lang === "en"
                          ? "IP-only"
                          : lang === "zh"
                            ? "单IP"
                            : "IP-only"}
                    </span>
                  </span>

                  <span className="hist__meta mono">
                    {row.clean_score === null ? DASH : fmtInt(row.clean_score)}
                    <span className="muted">/</span>
                    {row.confidence_score === null ? DASH : fmtInt(row.confidence_score)}%
                  </span>

                  <span className="hist__meta">{fmtTime(row.checked_at)}</span>
                </button>

                <button
                  type="button"
                  className="btn btn--sm btn--ghost"
                  onClick={() => onRecheck(row)}
                  disabled={scanning}
                  title={t("history.recheck_tooltip")}
                >
                  ↻ {t("history.recheck")}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

export default HistoryPanel;
