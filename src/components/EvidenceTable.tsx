/**
 * EvidenceTable — §3.2 bottom band: "BẰNG CHỨNG: bảng tất cả provider, ai đồng ý /
 * lệch / thiếu".
 *
 * Every instrumented provider appears, including failures, because the whole
 * point is traceability (§15.4: verdict → score → each evidence → source link).
 * Filtering and sorting keep the panel usable when 30+ providers answered.
 */

import { Fragment, useMemo, useState } from "react";

import type { Category, ProviderEvidence, Signal } from "../lib/types";
import { Empty, Panel, SkeletonTable, SourceLink } from "./ui/parts";
import {
  clampText,
  cx,
  DASH,
  fmtNum,
  fmtTime,
  getLocalizedCategoryLabel,
  getLocalizedErrorKindLabel,
  getLocalizedProviderReason,
  getLocalizedSignalMeta,
} from "./ui/meta";
import { useI18n } from "../lib/i18n";

export interface EvidenceTableProps {
  evidence: ProviderEvidence[];
  /** Upstreams that produced at least one non-Unknown vote (§6.2). */
  upstreamCount?: number;
  loading?: boolean;
}

type FilterKey = "all" | "clean" | "suspect" | "bad" | "unknown";
type SortCol = "provider" | "category" | "upstream" | "signal" | "score" | "latency" | "time";
type SortDir = "asc" | "desc";

function matchesFilter(row: ProviderEvidence, filter: FilterKey): boolean {
  if (filter === "all") return true;
  if (filter === "clean") return row.signal === "Clean";
  if (filter === "suspect") return row.signal === "Suspicious";
  if (filter === "bad") return row.signal === "Bad";
  return row.signal === "Unknown";
}

export function EvidenceTable({ evidence, upstreamCount, loading }: EvidenceTableProps) {
  const { lang, t } = useI18n();
  const [filter, setFilter] = useState<FilterKey>("all");
  const [search, setSearch] = useState("");
  const [sortCol, setSortCol] = useState<SortCol | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const filterLabels: Record<FilterKey, string> = useMemo(
    () => ({
      all: t("evidence.all"),
      clean: t("evidence.agree_clean"),
      suspect: t("evidence.divergent"),
      bad: t("evidence.reported_bad"),
      unknown: t("evidence.missing"),
    }),
    [t],
  );

  const counts = useMemo(() => {
    const base: Record<FilterKey, number> = { all: evidence.length, clean: 0, suspect: 0, bad: 0, unknown: 0 };
    for (const row of evidence) {
      if (row.signal === "Clean") base.clean += 1;
      else if (row.signal === "Suspicious") base.suspect += 1;
      else if (row.signal === "Bad") base.bad += 1;
      else base.unknown += 1;
    }
    return base;
  }, [evidence]);

  const toggleSort = (col: SortCol) => {
    if (sortCol === col) {
      if (sortDir === "asc") {
        setSortDir("desc");
      } else {
        setSortCol(null);
        setSortDir("asc");
      }
    } else {
      setSortCol(col);
      setSortDir("asc");
    }
  };

  const rows = useMemo(() => {
    let list = evidence.filter((row) => matchesFilter(row, filter));
    const s = search.trim().toLowerCase();
    if (s) {
      list = list.filter(
        (row) =>
          row.provider.toLowerCase().includes(s) ||
          row.upstream.toLowerCase().includes(s) ||
          row.category.toLowerCase().includes(s) ||
          (row.reason ?? "").toLowerCase().includes(s) ||
          (row.error?.message ?? "").toLowerCase().includes(s),
      );
    }
    if (!sortCol) return list;

    const mult = sortDir === "asc" ? 1 : -1;
    return [...list].sort((a, b) => {
      let va: string | number = "";
      let vb: string | number = "";
      switch (sortCol) {
        case "provider":
          va = a.provider.toLowerCase();
          vb = b.provider.toLowerCase();
          break;
        case "category":
          va = a.category.toLowerCase();
          vb = b.category.toLowerCase();
          break;
        case "upstream":
          va = a.upstream.toLowerCase();
          vb = b.upstream.toLowerCase();
          break;
        case "signal": {
          const rank: Record<Signal, number> = { Clean: 0, Suspicious: 1, Bad: 2, Unknown: 3 };
          va = rank[a.signal];
          vb = rank[b.signal];
          break;
        }
        case "score":
          va = a.raw_score ?? -999;
          vb = b.raw_score ?? -999;
          break;
        case "latency":
          va = a.latency_ms ?? -1;
          vb = b.latency_ms ?? -1;
          break;
        case "time":
          va = a.checked_at ?? "";
          vb = b.checked_at ?? "";
          break;
      }
      if (va < vb) return -1 * mult;
      if (va > vb) return 1 * mult;
      return 0;
    });
  }, [evidence, filter, search, sortCol, sortDir]);

  const uniqueUpstreams = useMemo(() => {
    if (typeof upstreamCount === "number") return upstreamCount;
    return new Set(evidence.map((row) => row.upstream || row.provider)).size;
  }, [evidence, upstreamCount]);

  const handleCopyRaw = async (rowKey: string, payload: unknown) => {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
        setCopiedKey(rowKey);
        setTimeout(() => setCopiedKey((cur) => (cur === rowKey ? null : cur)), 1500);
      }
    } catch (err) {
      console.warn("Copy failed:", err);
    }
  };

  const renderSortIndicator = (col: SortCol) => {
    if (sortCol !== col) return <span className="tbl__sort-icon">↕</span>;
    return <span className="tbl__sort-icon tbl__sort-icon--active">{sortDir === "asc" ? "▲" : "▼"}</span>;
  };

  return (
    <Panel
      title={t("evidence.title")}
      hint={
        <div
          className="ev__controls"
          role="group"
          aria-label={
            lang === "en"
              ? "Filter and search evidence"
              : lang === "zh"
              ? "筛选与搜索证据"
              : "Lọc và tìm kiếm bằng chứng"
          }
        >
          <input
            type="search"
            className="ev__search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("evidence.search_placeholder")}
            aria-label={lang === "en" ? "Filter provider or upstream" : lang === "zh" ? "过滤服务商或上游" : "Tìm provider hoặc upstream"}
          />
          <span className="row" style={{ gap: 4 }}>
            {(Object.keys(filterLabels) as FilterKey[]).map((key) => (
              <button
                key={key}
                type="button"
                className={cx("btn btn--sm", filter === key ? "btn--primary" : "btn--ghost")}
                onClick={() => setFilter(key)}
                aria-pressed={filter === key}
                title={`${filterLabels[key]} (${counts[key]})`}
              >
                {filterLabels[key]} {counts[key]}
              </button>
            ))}
          </span>
        </div>
      }
      footer={
        <>
          <span>
            {rows.length}/{evidence.length} {lang === "en" ? "rows" : lang === "zh" ? "条" : "dòng"} ·{" "}
            {uniqueUpstreams}{" "}
            {lang === "en"
              ? "votes after upstream dedup (§6.2)"
              : lang === "zh"
                ? "票 (上游去重后 §6.2)"
                : "phiếu sau khi gộp upstream (§6.2)"}
          </span>
          <span className="mono">
            {lang === "en"
              ? "click header to sort · click row for raw JSON"
              : lang === "zh"
                ? "点击表头排序 · 点击行查看原始JSON"
                : "bấm cột để sắp xếp · bấm dòng xem raw JSON"}
          </span>
        </>
      }
      bodyClassName="panel__body--nopad"
    >
      {evidence.length === 0 ? (
        loading ? (
          <div style={{ padding: "8px 12px" }}>
            <SkeletonTable rows={5} cols={9} />
          </div>
        ) : (
          <div style={{ padding: "8px 12px" }}>
            <Empty icon="📋">{t("evidence.no_evidence")}</Empty>
          </div>
        )
      ) : rows.length === 0 ? (
        /* A stale filter must not read as "this check found nothing". */
        <Empty icon="🔍">
          <span>
            {lang === "en"
              ? `No rows match filter “${filterLabels[filter]}”${search ? ` and keyword “${search}”` : ""} (${counts[filter]}/${evidence.length} rows).`
              : lang === "zh"
                ? `无匹配筛选 “${filterLabels[filter]}”${search ? ` 及关键词 “${search}”` : ""} 的条目 (${counts[filter]}/${evidence.length} 行)。`
                : `Không có dòng nào khớp bộ lọc “${filterLabels[filter]}”${search ? ` và từ khoá “${search}”` : ""} (${counts[filter]}/${evidence.length} dòng).`}
          </span>
          <div className="row" style={{ gap: 8, marginTop: 4 }}>
            {search ? (
              <button type="button" className="btn btn--sm btn--ghost" onClick={() => setSearch("")}>
                {t("common.clear")}
              </button>
            ) : null}
            {filter !== "all" ? (
              <button type="button" className="btn btn--sm btn--ghost" onClick={() => setFilter("all")}>
                {lang === "en" ? "Clear filter" : lang === "zh" ? "重置筛选" : "Bỏ bộ lọc"}
              </button>
            ) : null}
          </div>
        </Empty>
      ) : (
        <div className="tblwrap" style={{ maxHeight: "100%" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th className="tbl__th--sortable" onClick={() => toggleSort("provider")}>
                  {t("evidence.provider")} {renderSortIndicator("provider")}
                </th>
                <th className="tbl__th--sortable" onClick={() => toggleSort("category")}>
                  {t("evidence.category")} {renderSortIndicator("category")}
                </th>
                <th className="tbl__th--sortable" onClick={() => toggleSort("upstream")}>
                  {t("evidence.upstream")} {renderSortIndicator("upstream")}
                </th>
                <th className="tbl__th--sortable" onClick={() => toggleSort("signal")}>
                  {t("evidence.signal")} {renderSortIndicator("signal")}
                </th>
                <th className="tbl__num tbl__th--sortable" onClick={() => toggleSort("score")}>
                  {t("evidence.score")} {renderSortIndicator("score")}
                </th>
                <th className="tbl__num tbl__th--sortable" onClick={() => toggleSort("latency")}>
                  {t("evidence.latency")} {renderSortIndicator("latency")}
                </th>
                <th className="tbl__th--sortable" onClick={() => toggleSort("time")}>
                  {t("evidence.timestamp")} {renderSortIndicator("time")}
                </th>
                <th>{lang === "en" ? "Reason / Error" : lang === "zh" ? "原因 / 错误" : "Lý do / lỗi"}</th>
                <th>{lang === "en" ? "Source" : lang === "zh" ? "来源" : "Nguồn"}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => {
                const signal = getLocalizedSignalMeta(row.signal, lang);
                const errorKind = row.error?.kind;
                const rowKey = `${row.provider}-${row.category}-${index}`;
                const isExpanded = expandedKey === rowKey;
                const hasDetail = Boolean(row.raw || row.error?.message || row.reason);
                return (
                  <Fragment key={rowKey}>
                    <tr
                      className={cx(
                        hasDetail && "ev__row--clickable",
                        row.error && "tbl__row--error",
                        !row.error && row.signal === "Bad" && "tbl__row--bad",
                        !row.error && row.signal === "Suspicious" && "tbl__row--warn",
                      )}
                      onClick={() => {
                        if (hasDetail) {
                          setExpandedKey((cur) => (cur === rowKey ? null : rowKey));
                        }
                      }}
                      title={
                        hasDetail
                          ? lang === "en"
                            ? "Click to view/hide raw JSON details"
                            : lang === "zh"
                              ? "点击查看/折叠原始JSON详情"
                              : "Bấm để xem/ẩn chi tiết JSON gốc"
                          : undefined
                      }
                    >
                      <td className="tbl__name" title={row.provider}>
                        {hasDetail ? <span className="muted tiny">{isExpanded ? "▾ " : "▸ "}</span> : null}
                        {row.provider}
                      </td>
                      <td className="tbl__muted">
                        <span className="chip chip--ghost chip--dense">
                          {getLocalizedCategoryLabel(row.category, lang)}
                        </span>
                      </td>
                      <td className="tbl__muted truncate" title={row.upstream}>
                        {row.upstream || DASH}
                      </td>
                      <td>
                        <span className={cx("chip", `chip--${signal.cls}`)}>{signal.label}</span>
                      </td>
                      <td className="tbl__num mono">
                        {row.raw_score === null || row.raw_score === undefined
                          ? DASH
                          : fmtNum(row.raw_score, Number.isInteger(row.raw_score) ? 0 : 1)}
                      </td>
                      <td className="tbl__num mono">
                        {row.latency_ms === null || row.latency_ms === undefined ? DASH : `${row.latency_ms}`}
                      </td>
                      <td className="tbl__muted tiny nowrap">{fmtTime(row.checked_at)}</td>
                      <td className="tbl__reason" title={row.error?.message ?? row.reason ?? undefined}>
                        {row.error ? (
                          <span className="text-bad">
                            {getLocalizedErrorKindLabel(errorKind, lang)}
                            {row.error.status ? ` ${row.error.status}` : ""}
                            {row.error.message ? `: ${clampText(row.error.message, 60)}` : ""}
                          </span>
                        ) : row.reason ? (
                          clampText(getLocalizedProviderReason(row.reason, lang), 60)
                        ) : (
                          DASH
                        )}
                      </td>
                      <td>
                        <SourceLink href={row.source_url} lang={lang} />
                      </td>
                    </tr>
                    {isExpanded ? (
                      <tr className="ev__detail-row">
                        <td colSpan={9}>
                          <div className="ev__detail-body">
                            <div className="ev__detail-header">
                              <span className="mono tiny bold">
                                {row.provider} · {getLocalizedCategoryLabel(row.category, lang)} ·{" "}
                                {t("evidence.raw_data")}
                              </span>
                              <button
                                type="button"
                                className="btn btn--sm btn--ghost"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  void handleCopyRaw(rowKey, row.raw ?? row);
                                }}
                              >
                                {copiedKey === rowKey ? t("common.copied") : t("common.copy")}
                              </button>
                            </div>
                            {row.error ? (
                              <div className="ev__detail-error">
                                <span className="bold">{lang === "en" ? "Error:" : lang === "zh" ? "错误:" : "Lỗi:"}</span>{" "}
                                {getLocalizedErrorKindLabel(row.error.kind, lang)}
                                {row.error.status ? ` (HTTP ${row.error.status})` : ""}:{" "}
                                {row.error.message || (lang === "en" ? "No error message" : lang === "zh" ? "无错误信息" : "Không có thông báo lỗi")}
                              </div>
                            ) : null}
                            {row.reason ? (
                              <div className="ev__detail-reason">
                                <span className="bold">{lang === "en" ? "Reason:" : lang === "zh" ? "原因:" : "Lý do:"}</span>{" "}
                                {getLocalizedProviderReason(row.reason, lang)}
                              </div>
                            ) : null}
                            <pre className="ev__detail-json">
                              {JSON.stringify(row.raw ?? { provider: row.provider, signal: row.signal }, null, 2)}
                            </pre>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

export default EvidenceTable;
