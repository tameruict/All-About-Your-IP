/**
 * BlacklistTable — the "BLACKLIST" cell of §3.2 (§5.3, §3.3).
 *
 * Shows every DNSBL group with a listed/not-listed answer, the number of zones
 * that answered, and per-zone detail on hover/expand. A group is ONE vote
 * (§5.3), which is why the group row is the primary line and the zones are
 * nested underneath.
 */

import { useMemo, useState } from "react";
import type { DnsblEntry, DnsblGroupResult, DnsblResult } from "../lib/types";
import { Empty, Panel, SkeletonTable, SourceLink } from "./ui/parts";
import {
  cx,
  DASH,
  fmtTime,
  getLocalizedDnsblGroupLabel,
  getLocalizedProviderReason,
  getLocalizedShortError,
} from "./ui/meta";
import { useI18n, type Language } from "../lib/i18n";

export interface BlacklistTableProps {
  dnsbl: DnsblResult | null | undefined;
  /** True while the dnsbl module still runs. */
  loading?: boolean;
  /** App-level retry for the whole blacklist module (§3.4). */
  onRetry?: () => void;
  canRetry?: boolean;
}

function groupTone(group: DnsblGroupResult): string {
  if (!group.answered) return "chip--unknown";
  if (group.listed === 0) return "chip--clean";
  return group.signal === "Bad" ? "chip--bad" : "chip--suspect";
}

function groupLabelText(group: DnsblGroupResult, lang: Language): string {
  if (!group.answered) return lang === "en" ? "no response" : lang === "zh" ? "无响应" : "không trả lời";
  if (group.listed === 0) return lang === "en" ? "clean" : lang === "zh" ? "未命中" : "không dính";
  return `${group.listed}/${group.checked} ${lang === "en" ? "listed" : lang === "zh" ? "命中" : "list dính"}`;
}

export function BlacklistTable({ dnsbl, loading, onRetry, canRetry }: BlacklistTableProps) {
  const { lang, t } = useI18n();
  const [search, setSearch] = useState("");
  const [onlyListed, setOnlyListed] = useState(false);

  const rawGroups = dnsbl?.groups ?? [];
  const totalChecked = rawGroups.reduce((sum, group) => sum + group.checked, 0);

  const filteredGroups = useMemo(() => {
    let list = rawGroups;
    if (onlyListed) {
      list = list.filter((g) => g.listed > 0 || !g.answered);
    }
    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter((g) => {
        const label = (getLocalizedDnsblGroupLabel(g.group, lang) || g.label).toLowerCase();
        if (label.includes(q)) return true;
        return g.entries.some((e) => e.zone.toLowerCase().includes(q) || (e.reason ?? "").toLowerCase().includes(q));
      });
    }
    return list;
  }, [rawGroups, onlyListed, search, lang]);

  const footer = dnsbl ? (
    <>
      <span>
        {dnsbl.groups_answered}/{rawGroups.length}{" "}
        {lang === "en" ? "groups responded" : lang === "zh" ? "个分组响应" : "nhóm trả lời"}
        {dnsbl.groups_answered < 3
          ? lang === "en"
            ? " · missing quorum (<3)"
            : lang === "zh"
              ? " · 缺少法定数量 (<3)"
              : " · thiếu quorum (<3)"
          : ""}
      </span>
      <span className={cx(dnsbl.total_listed > 0 ? "text-bad" : "text-clean")}>
        {dnsbl.total_listed > 0
          ? lang === "en"
            ? `${dnsbl.total_listed} list(s) flagged`
            : lang === "zh"
              ? `命中 ${dnsbl.total_listed} 项黑名单`
              : `${dnsbl.total_listed} list dính`
          : lang === "en"
            ? "clean on all lists"
            : lang === "zh"
              ? "未命中任何黑名单"
              : "không dính list nào"}
      </span>
    </>
  ) : (
    <span>
      {loading
        ? lang === "en"
          ? "querying DNSBL…"
          : lang === "zh"
            ? "正在查询DNS黑名单…"
            : "đang query DNSBL…"
        : lang === "en"
          ? "no data"
          : lang === "zh"
            ? "暂无数据"
            : "chưa có dữ liệu"}
    </span>
  );

  return (
    <Panel
      title={t("blacklist.title")}
      hint={
        <div className="row" style={{ gap: 4 }}>
          {rawGroups.length > 0 ? (
            <button
              type="button"
              className={cx("btn btn--sm", onlyListed ? "btn--danger" : "btn--ghost")}
              onClick={() => setOnlyListed((v) => !v)}
              title={
                onlyListed
                  ? lang === "en"
                    ? "Show all groups"
                    : lang === "zh"
                      ? "展示所有分组"
                      : "Hiển thị tất cả các nhóm"
                  : lang === "en"
                    ? "Filter listed groups only"
                    : lang === "zh"
                      ? "仅展示命中的分组"
                      : "Chỉ lọc các nhóm có list dính"
              }
            >
              {onlyListed
                ? lang === "en"
                  ? "● Listed only"
                  : lang === "zh"
                    ? "● 仅命中"
                    : "● Chỉ dính"
                : lang === "en"
                  ? "All groups"
                  : lang === "zh"
                    ? "所有分组"
                    : "Tất cả nhóm"}
            </button>
          ) : null}
          <span className="mono tiny muted">
            {totalChecked > 0 ? `${totalChecked} ${lang === "en" ? "lists" : lang === "zh" ? "项" : "list"}` : "DNSBL"}
          </span>
        </div>
      }
      footer={footer}
    >
      {rawGroups.length === 0 ? (
        loading ? (
          <SkeletonTable rows={4} cols={4} />
        ) : (
          <Empty icon="🛡">{t("blacklist.no_hits")}</Empty>
        )
      ) : (
        <div className="tblwrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>{lang === "en" ? "Group" : lang === "zh" ? "分组" : "Nhóm"}</th>
                <th>{t("blacklist.status")}</th>
                <th>{t("blacklist.zone")}</th>
                <th>{t("blacklist.reason")}</th>
                <th>{t("blacklist.checked_at")}</th>
              </tr>
            </thead>
            <tbody>
              {filteredGroups.map((group) => {
                const groupName = getLocalizedDnsblGroupLabel(group.group, lang) || group.label;
                const hasListed = group.entries.some((entry) => entry.listed);

                return (
                  <tr
                    key={group.group}
                    className={cx(
                      !group.answered
                        ? "tbl__row--warn"
                        : group.listed > 0
                          ? "tbl__row--bad"
                          : undefined,
                    )}
                  >
                    <td className="tbl__name">
                      <span className="bold">{groupName}</span>
                      <span className="tiny muted">
                        {" "}
                        ({group.checked} {lang === "en" ? "zones" : lang === "zh" ? "个域" : "zone"})
                      </span>
                    </td>

                    <td>
                      <span className={cx("chip", groupTone(group))}>{groupLabelText(group, lang)}</span>
                    </td>

                    <td className="tbl__muted">
                      {hasListed ? (
                        <span className="text-bad">
                          {group.entries
                            .filter((entry) => entry.listed)
                            .map((entry) => entry.zone)
                            .join(", ")}
                        </span>
                      ) : (
                        <span className="muted">{lang === "en" ? "all clean" : lang === "zh" ? "全部纯净" : "tất cả sạch"}</span>
                      )}
                    </td>

                    <td className="tiny">
                      {group.entries
                        .filter((entry: DnsblEntry) => entry.error)
                        .map((entry: DnsblEntry) => `${entry.zone}: ${getLocalizedShortError(entry.error, lang)}`)
                        .join(" · ") ||
                        group.entries
                          .filter((entry: DnsblEntry) => entry.reason)
                          .map((entry: DnsblEntry) => getLocalizedProviderReason(entry.reason, lang))
                          .join(" · ") ||
                        DASH}
                    </td>

                    <td className="tbl__muted tiny nowrap">
                      {group.entries[0]?.checked_at ? fmtTime(group.entries[0].checked_at) : DASH}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {onRetry && canRetry && dnsbl && dnsbl.groups_answered < 3 ? (
        <div style={{ padding: 8 }}>
          <button type="button" className="btn btn--sm btn--ghost" onClick={onRetry}>
            ↻ {t("common.retry")}
          </button>
        </div>
      ) : null}
    </Panel>
  );
}

export default BlacklistTable;
