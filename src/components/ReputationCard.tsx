/**
 * ReputationCard — the "REPUTATION (từng provider)" cell of §3.2 (§3.3).
 *
 * Required per row: provider name, result, an openable source link, check time,
 * and the reason when the provider was missing (timeout / quota / no key).
 * A failed provider shows "Lỗi: <short reason>" plus its OWN retry button and
 * never takes the rest of the check down (§3.4).
 *
 * Only the UI-side labels live here; the weights/signals come from the backend.
 */

import type { Category, ProviderEvidence } from "../lib/types";
import { Banner, Empty, Panel, SkeletonTable, SourceLink } from "./ui/parts";
import {
  CATEGORY_LABELS,
  cx,
  DASH,
  fmtNum,
  fmtTime,
  getLocalizedCategoryLabel,
  getLocalizedProviderReason,
  getLocalizedShortError,
  getLocalizedSignalMeta,
  shortError,
} from "./ui/meta";
import { useI18n, type Language } from "../lib/i18n";

export interface ReputationCardProps {
  evidence: ProviderEvidence[];
  /** Per-provider retry (§3.4 "nút thử lại riêng"). */
  onRetryProvider?: (provider: string) => void;
  canRetry?: boolean;
  /** True while fraud/abuse/threat-intel modules are still running. */
  loading?: boolean;
}

/** Categories shown on this card; blacklist/network have their own. */
const REPUTATION_CATEGORIES: Category[] = ["fraud", "abuse", "threat_intel"];

export function ReputationCard({
  evidence,
  onRetryProvider,
  canRetry,
  loading,
}: ReputationCardProps) {
  const { lang, t } = useI18n();
  const rows = evidence.filter((row) => REPUTATION_CATEGORIES.includes(row.category));

  const answered = rows.filter((row) => row.signal !== "Unknown").length;
  const failed = rows.filter((row) => Boolean(row.error)).length;
  const quotaNotice = reputationQuotaNotice(evidence, lang);

  return (
    <Panel
      title={t("reputation.title")}
      hint={`${answered}/${rows.length} ${lang === "en" ? "votes" : lang === "zh" ? "票" : "phiếu"}`}
      footer={
        <>
          <span>
            {failed > 0
              ? lang === "en"
                ? `${failed} source(s) failed / missing`
                : lang === "zh"
                  ? `${failed} 个来源失败/缺失`
                  : `${failed} nguồn lỗi / thiếu`
              : rows.length > 0
                ? lang === "en"
                  ? "all sources responded"
                  : lang === "zh"
                    ? "所有数据源已响应"
                    : "đủ nguồn phản hồi"
                : DASH}
          </span>
          <span className="mono">{t("reputation.aspects")}</span>
        </>
      }
    >
      {quotaNotice ? (
        <div style={{ marginBottom: 8 }}>
          <Banner tone="warn" title={quotaNotice} />
        </div>
      ) : null}
      {rows.length === 0 ? (
        loading ? (
          <SkeletonTable rows={4} cols={5} />
        ) : (
          <Empty icon="🛡">{t("reputation.no_data")}</Empty>
        )
      ) : (
        <div className="tblwrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Provider</th>
                <th>{lang === "en" ? "Result" : lang === "zh" ? "结果" : "Kết quả"}</th>
                <th className="tbl__num">{lang === "en" ? "Raw Score" : lang === "zh" ? "原始分" : "Score gốc"}</th>
                <th>{lang === "en" ? "Time" : lang === "zh" ? "时间" : "Lúc"}</th>
                <th>{lang === "en" ? "Source" : lang === "zh" ? "来源" : "Nguồn"}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => {
                const signal = getLocalizedSignalMeta(row.signal, lang);
                const failedRow = Boolean(row.error);
                const missingKey =
                  (row.signal === "Unknown" && !row.error && /key|auth/i.test(row.reason ?? "")) ||
                  /auth|no_key/i.test(row.error?.kind ?? "");

                return (
                  <tr
                    key={`${row.provider}-${index}`}
                    className={cx(failedRow && "tbl__row--error")}
                  >
                    <td
                      className="tbl__name"
                      title={`${row.provider} · upstream: ${row.upstream} · ${getLocalizedCategoryLabel(row.category, lang)}`}
                    >
                      {row.provider}
                      <span className="tiny muted"> · {getLocalizedCategoryLabel(row.category, lang)}</span>
                    </td>

                    <td>
                      {failedRow ? (
                        <span className="row">
                          <span className="text-bad" title={row.error?.message ?? undefined}>
                            {`${lang === "en" ? "Error: " : lang === "zh" ? "错误: " : "Lỗi: "}${getLocalizedShortError(row.error, lang)}`}
                          </span>
                          {onRetryProvider ? (
                            <button
                              type="button"
                              className="btn btn--icon btn--ghost"
                              onClick={() => onRetryProvider(row.provider)}
                              disabled={!canRetry}
                              title={
                                lang === "en"
                                  ? `Retry ${row.provider}`
                                  : lang === "zh"
                                    ? `重试 ${row.provider}`
                                    : `Thử lại riêng ${row.provider}`
                              }
                            >
                              ↻
                            </button>
                          ) : null}
                        </span>
                      ) : (
                        <span className="row">
                          <span className={cx("chip", `chip--${signal.cls}`)}>{signal.label}</span>
                          {missingKey ? (
                            <span className="tiny text-temp">
                              {lang === "en" ? "missing key" : lang === "zh" ? "缺少密钥" : "thiếu key"}
                            </span>
                          ) : null}
                          {row.reason ? (
                            <span className="tiny muted truncate" title={getLocalizedProviderReason(row.reason, lang)}>
                              {getLocalizedProviderReason(row.reason, lang)}
                            </span>
                          ) : null}
                        </span>
                      )}
                    </td>

                    <td className="tbl__num">
                      {row.raw_score === null || row.raw_score === undefined
                        ? DASH
                        : fmtNum(row.raw_score, Number.isInteger(row.raw_score) ? 0 : 1)}
                    </td>

                    <td className="tbl__muted tiny nowrap">
                      {fmtTime(row.checked_at)}
                      {row.from_cache ? (
                        <span title={lang === "en" ? "from cache" : lang === "zh" ? "来自缓存" : "từ cache"}>
                          {" "}
                          ⧉
                        </span>
                      ) : null}
                    </td>

                    <td>
                      <SourceLink href={row.source_url} lang={lang} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/**
 * Surfaces the quota / missing-key situation as ONE banner instead of leaving it
 * buried in a long table (§3.4 "Hết quota → hiện Hết quota free, check lại sau /
 * nhập key").
 */
export function reputationQuotaNotice(
  evidence: ProviderEvidence[],
  lang: Language = "vi",
): string | null {
  const rows = evidence.filter((row) => REPUTATION_CATEGORIES.includes(row.category));
  const quota = rows.find((row) => row.error && /quota/i.test(row.error.kind ?? ""));
  if (quota) {
    if (lang === "en") {
      return `Free quota exhausted at ${quota.provider} — check back later or add API key in Settings. Confidence penalized.`;
    }
    if (lang === "zh") {
      return `${quota.provider} 免费配额已耗尽 — 请稍后重试或在设置中配置API密钥。置信度已被扣减。`;
    }
    return `Hết quota free ở ${quota.provider} — check lại sau hoặc nhập API key trong Cài đặt. Confidence đã bị trừ.`;
  }
  const auth = rows.find((row) => row.error && /auth|no_key/i.test(row.error.kind ?? ""));
  if (auth) {
    if (lang === "en") {
      return `Missing or invalid API key for ${auth.provider} — configure key in Settings to unlock additional votes.`;
    }
    if (lang === "zh") {
      return `${auth.provider} 缺少或无效API密钥 — 请在设置中配置密钥以获取更多票数。`
    }
    return `Thiếu hoặc sai API key của ${auth.provider} — thêm key trong Cài đặt để có thêm phiếu.`;
  }
  return null;
}

export default ReputationCard;
