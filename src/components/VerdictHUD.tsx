/**
 * VerdictHUD — §3.2 row 3 + §3.3.
 *
 * Hard requirements:
 * - Clean Score (0–100) and Confidence Score (0–100) are shown SEPARATELY,
 *   never merged into one number;
 * - the verdict is exactly one of the five labels of §6.5;
 * - the reason is ONE line ("Lý do chính"), clipped, full text on hover;
 * - conflicts (§6.5) and a single strong piece of evidence are surfaced as
 *   chips instead of silently changing the colour of the score.
 *
 * The HUD is the second of the two places allowed a scanline (§3.1).
 */

import { useCallback, useState } from "react";

import type { ConflictFlag, ScoringResult, Verdict } from "../lib/types";
import {
  useI18n,
  getLocalizedVerdictMeta,
  getLocalizedCacheNote,
  getLocalizedVerdictReason,
  getLocalizedAspectLabel,
} from "../lib/i18n";
import { cx, confidenceTone, scoreTone, DASH, fmtInt } from "./ui/meta";

export interface VerdictHUDProps {
  verdict: Verdict | null;
  verdictReason: string | null;
  cleanScore: number | null;
  confidenceScore: number | null;
  scoring?: ScoringResult | null;
  /** True while the scan is still streaming (drives the scanline state). */
  live: boolean;
  /** True when the shown result came from cache (§3.4). */
  fromCache?: boolean;
  cachedAt?: string | null;
  /** Check duration for the right-hand meta column. */
  durationMs?: number | null;
  /** Shown under the scores when the quorum was not met (§6.3). */
  quorumMissing?: string[];
  /** Checked IP address for quick display and click-to-copy. */
  ip?: string | null;
}

const CONFLICT_LIMIT = 2;

function ScoreDial({
  value,
  tone,
  live,
}: {
  value: number | null | undefined;
  tone: string;
  live?: boolean;
}) {
  const r = 15;
  const c = 2 * Math.PI * r;
  const valid = typeof value === "number" && !Number.isNaN(value);
  const clamped = valid ? Math.min(100, Math.max(0, value)) : 0;
  const offset = c - (c * clamped) / 100;
  const measuring = live && !valid;

  return (
    <svg
      className={cx("score__dial", measuring && "score__dial--measuring")}
      width="34"
      height="34"
      viewBox="0 0 34 34"
      aria-hidden="true"
    >
      <circle
        cx="17"
        cy="17"
        r={r}
        className="score__dial-track"
        fill="none"
        strokeWidth="3"
      />
      <circle
        cx="17"
        cy="17"
        r={r}
        className={cx(
          "score__dial-fill",
          `score__dial-fill--${measuring ? "cyan" : tone}`,
        )}
        fill="none"
        strokeWidth="3"
        strokeDasharray={c}
        strokeDashoffset={measuring ? c * 0.75 : valid ? offset : c}
        transform="rotate(-90 17 17)"
      />
      {valid ? (
        <circle
          cx="17"
          cy="17"
          r="2"
          className={cx("score__dial-dot", `score__dial-dot--${tone}`)}
        />
      ) : null}
    </svg>
  );
}

export function VerdictHUD({
  verdict,
  verdictReason,
  cleanScore,
  confidenceScore,
  scoring,
  live,
  fromCache,
  cachedAt,
  durationMs,
  quorumMissing = [],
  ip,
}: VerdictHUDProps) {
  const { lang, t } = useI18n();
  const [copiedTarget, setCopiedTarget] = useState<"ip" | "verdict" | null>(null);

  const copyToClipboard = useCallback(async (text: string, target: "ip" | "verdict") => {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setCopiedTarget(target);
        setTimeout(() => {
          setCopiedTarget((current) => (current === target ? null : current));
        }, 1600);
      }
    } catch (err) {
      console.warn("Copy to clipboard failed:", err);
    }
  }, []);

  const meta = getLocalizedVerdictMeta(verdict, lang);
  const cleanTone = scoreTone(cleanScore);
  const confTone = confidenceTone(confidenceScore);

  const conflicts: ConflictFlag[] = scoring?.conflicts ?? [];
  const hardConflicts = conflicts.filter((item) => item.severity === "hard");

  const rawReason = verdictReason ?? scoring?.verdict_reason ?? null;
  const reason = getLocalizedVerdictReason(rawReason, lang);

  return (
    <section className={cx("hud", live && "hud--live")} aria-label={meta.displayLabel || t("verdict.clean_score")}>
      <div className="hud__scores">
        {/* Clean Score — never merged with Confidence. */}
        <div className={cx("score", `score--${cleanTone}`)} title={`${t("verdict.clean_score")} (0–100)`}>
          <div className="score__head">
            <div className="score__label">{t("verdict.clean_score")}</div>
            <ScoreDial value={cleanScore} tone={cleanTone} live={live} />
          </div>
          <div className="score__value">
            {cleanScore === null || cleanScore === undefined ? DASH : fmtInt(cleanScore)}
            {cleanScore === null || cleanScore === undefined ? null : <span className="score__unit">/100</span>}
          </div>
          <div
            className="score__meter"
            role="progressbar"
            aria-valuenow={cleanScore ?? 0}
            aria-valuemin={0}
            aria-valuemax={100}
            title={`${t("verdict.clean_score")}: ${cleanScore ?? 0}/100`}
          >
            <div
              className={cx("score__meter-fill", `score__meter-fill--${cleanTone}`)}
              style={{ width: `${Math.min(100, Math.max(0, cleanScore ?? 0))}%` }}
            />
          </div>
          <div className="score__sub">{t("verdict.weighted_avg")}</div>
        </div>

        {/* Confidence Score — separate box on purpose (§3.3). */}
        <div className={cx("score", `score--${confTone}`)} title={`${t("verdict.confidence")} (0–100)`}>
          <div className="score__head">
            <div className="score__label">{t("verdict.confidence")}</div>
            <ScoreDial value={confidenceScore} tone={confTone} live={live} />
          </div>
          <div className="score__value">
            {confidenceScore === null || confidenceScore === undefined ? DASH : fmtInt(confidenceScore)}
            {confidenceScore === null || confidenceScore === undefined ? null : (
              <span className="score__unit">%</span>
            )}
          </div>
          <div
            className="score__meter"
            role="progressbar"
            aria-valuenow={confidenceScore ?? 0}
            aria-valuemin={0}
            aria-valuemax={100}
            title={`${t("verdict.confidence")}: ${confidenceScore ?? 0}%`}
          >
            <div
              className={cx("score__meter-fill", `score__meter-fill--${confTone}`)}
              style={{ width: `${Math.min(100, Math.max(0, confidenceScore ?? 0))}%` }}
            />
          </div>
          <div className="score__sub">{t("verdict.coverage_consensus")}</div>
        </div>
      </div>

      <div className="hud__main">
        <div className="hud__verdictrow">
          {ip ? (
            <button
              type="button"
              className="hud__ip-btn"
              onClick={() => copyToClipboard(ip, "ip")}
              title={t("verdict.copy_ip")}
            >
              <span className="hud__ip-text">{ip}</span>
              <span className="hud__copy-pill">
                {copiedTarget === "ip" ? t("common.copied") : t("common.copy")}
              </span>
            </button>
          ) : null}

          {verdict === null ? (
            /* No verdict yet is NOT a verdict. Rendering the "Chưa đủ dữ liệu"
               label here made a fresh app look like a finished, bad scan. */
            <span className={cx("hud__verdict", "hud__verdict--idle")} title={t("verdict.not_checked")}>
              {t("verdict.not_checked")}
            </span>
          ) : (
            <button
              type="button"
              className={cx("hud__verdict", `hud__verdict--${meta.cls}`, "hud__verdict--btn")}
              onClick={() => copyToClipboard(meta.displayLabel, "verdict")}
              title={t("verdict.copy_verdict")}
            >
              <span>{meta.displayLabel}</span>
              {copiedTarget === "verdict" ? (
                <span className="hud__copied-badge">{t("common.copied")}</span>
              ) : null}
            </button>
          )}

          {fromCache ? (
            <span className="chip chip--muted" title={t("common.from_cache")}>
              {getLocalizedCacheNote(cachedAt, lang)}
            </span>
          ) : null}

          {scoring?.single_source_evidence ? (
            <span className="chip chip--suspect" title={t("verdict.single_evidence")}>
              {t("verdict.single_evidence")}
            </span>
          ) : null}

          {hardConflicts.length > 0 ? (
            <span className="chip chip--conflict" title={getLocalizedVerdictReason(hardConflicts[0]?.message, lang)}>
              {t("verdict.conflict_sources", { count: hardConflicts.length })}
            </span>
          ) : null}

          {quorumMissing.length > 0 ? (
            <span
              className="chip chip--unknown"
              title={`${lang === "en" ? "Missing quorum: " : lang === "zh" ? "缺少法定数据源: " : "Thiếu quorum: "}${quorumMissing.map((q) => getLocalizedAspectLabel(q, lang)).join(", ")}`}
            >
              {t("verdict.missing_quorum")}
            </span>
          ) : null}
        </div>

        {/* One-line reason (§3.3). Full text is in the title tooltip. */}
        <div className="hud__reason" title={reason ?? undefined}>
          {reason && reason.trim().length > 0 ? reason : t("verdict.no_verdict_hint")}
        </div>

        {conflicts.length > 0 ? (
          <div className="hud__flags">
            {conflicts.slice(0, CONFLICT_LIMIT).map((conflict, index) => (
              <span
                key={`${conflict.aspect}-${index}`}
                className={cx("chip", conflict.severity === "hard" ? "chip--conflict" : "chip--temp")}
                title={getLocalizedVerdictReason(conflict.message, lang)}
              >
                {getLocalizedAspectLabel(conflict.aspect, lang)}: {conflict.dissenting.join(", ") || DASH}
              </span>
            ))}
            {conflicts.length > CONFLICT_LIMIT ? (
              <span className="chip chip--muted">+{conflicts.length - CONFLICT_LIMIT}</span>
            ) : null}
          </div>
        ) : null}
      </div>

      <div className="hud__side">
        <span className="mono">{durationMs !== null && durationMs !== undefined ? `${(durationMs / 1000).toFixed(1)} s` : DASH}</span>
        <span>{live ? t("verdict.live_updating") : t("verdict.final_result")}</span>
      </div>
    </section>
  );
}

/** Local mapping kept apart so the HUD owns its own colour scale. */
export default VerdictHUD;
