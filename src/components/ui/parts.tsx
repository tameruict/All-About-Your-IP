/**
 * Reusable primitives used by more than one card: panel chrome, banners,
 * key/value rows, empty states and the small "retry" button that §3.4 asks
 * for ("1 provider lỗi → thẻ đó hiện Lỗi: <lý do ngắn> + nút thử lại riêng").
 *
 * These are helpers, not part of the 11 spec components (§3.3).
 */

import type { ReactNode } from "react";

import { useI18n } from "../../lib/i18n";
import { isTauri, openExternal } from "../../lib/api";
import { cx, errorKindLabel, normalizeLanguage, type Language, type VerdictTone } from "./meta";

/* ------------------------------------------------------------------ */
/* Panel                                                               */
/* ------------------------------------------------------------------ */

export interface PanelProps {
  title: string;
  /** Small right-aligned hint in the header (counts, mode badge, ...). */
  hint?: ReactNode;
  children: ReactNode;
  /** Optional footer content. */
  footer?: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Set false when the card must not scroll its body (map). */
  scroll?: boolean;
}

export function Panel({
  title,
  hint,
  children,
  footer,
  className,
  bodyClassName,
  scroll = true,
}: PanelProps) {
  return (
    <section className={cx("panel", className)} aria-label={title}>
      <header className="panel__head">
        <h2 className="panel__title">{title}</h2>
        {hint ? <div className="panel__hint">{hint}</div> : null}
      </header>
      <div className={cx("panel__body", !scroll && "panel__body--nopad", bodyClassName)}>
        {children}
      </div>
      {footer ? <div className="panel__foot">{footer}</div> : null}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Banner (§3.4 error / edge states)                                   */
/* ------------------------------------------------------------------ */

export type BannerTone = "info" | "warn" | "error" | "conflict" | "muted";

const BANNER_ICON: Record<BannerTone, string> = {
  info: "i",
  warn: "!",
  error: "×",
  conflict: "≠",
  muted: "·",
};

export interface BannerProps {
  tone?: BannerTone;
  title: string;
  detail?: ReactNode;
  actions?: ReactNode;
}

export function Banner({ tone = "info", title, detail, actions }: BannerProps) {
  return (
    <div className={cx("banner", `banner--${tone}`)} role={tone === "error" ? "alert" : "status"}>
      <span className="banner__icon" aria-hidden="true">
        {BANNER_ICON[tone]}
      </span>
      <div className="banner__text">
        <div className="banner__title">{title}</div>
        {detail ? <div className="banner__detail">{detail}</div> : null}
      </div>
      {actions ? <div className="banner__actions">{actions}</div> : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Key / value rows                                                    */
/* ------------------------------------------------------------------ */

export interface KvpProps {
  k: string;
  v: ReactNode;
  /** Colour tone for the value. */
  tone?: VerdictTone | "cyan" | "muted";
  sub?: ReactNode;
  title?: string;
}

export function Kvp({ k, v, tone, sub, title }: KvpProps) {
  const valueClass = cx(
    "kv__v",
    tone === "muted" && "kv__v--muted",
    tone && tone !== "muted" && `kv__v--${tone}`,
  );
  return (
    <>
      <div className="kv__k">{k}</div>
      <div className={valueClass} title={title ?? (typeof v === "string" ? v : undefined)}>
        {v}
      </div>
      {sub ? <div className="kv__sub">{sub}</div> : null}
    </>
  );
}

export interface SectionProps {
  title?: string;
  children: ReactNode;
}

export function Section({ title, children }: SectionProps) {
  return (
    <div className="section">
      {title ? <div className="section__title">{title}</div> : null}
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Empty state                                                         */
/* ------------------------------------------------------------------ */

export function Empty({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty__icon" aria-hidden="true">{icon ?? "∅"}</span>
      <div className="empty__text">{children}</div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Skeleton Loaders (§3.3)                                             */
/* ------------------------------------------------------------------ */

export interface SkeletonProps {
  className?: string;
  width?: string | number;
  height?: string | number;
  rounded?: boolean;
}

export function Skeleton({ className, width, height, rounded }: SkeletonProps) {
  return (
    <div
      className={cx("skeleton", rounded && "skeleton--rounded", className)}
      style={{
        width: width !== undefined ? (typeof width === "number" ? `${width}px` : width) : undefined,
        height: height !== undefined ? (typeof height === "number" ? `${height}px` : height) : undefined,
      }}
      aria-hidden="true"
    />
  );
}

export interface SkeletonWrapProps {
  children: ReactNode;
  ariaLabel?: string;
  lang?: Language;
  className?: string;
}

export function SkeletonWrap({ children, ariaLabel, lang, className }: SkeletonWrapProps) {
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {
    // context not available
  }
  const norm = normalizeLanguage(lang ?? ctxLang);
  const defaultLabel =
    norm === "en" ? "Loading data…" : norm === "zh" ? "正在加载数据…" : "Đang tải dữ liệu…";

  return (
    <div className={cx("skeleton-wrap", className)} aria-label={ariaLabel ?? defaultLabel}>
      {children}
    </div>
  );
}

export function SkeletonKv({
  count = 6,
  lang,
  ariaLabel,
}: {
  count?: number;
  lang?: Language;
  ariaLabel?: string;
} = {}) {
  return (
    <SkeletonWrap lang={lang} ariaLabel={ariaLabel}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton-kv-row">
          <Skeleton width="38%" height={13} />
          <Skeleton width="58%" height={13} />
        </div>
      ))}
    </SkeletonWrap>
  );
}

export function SkeletonTable({
  rows = 5,
  cols = 4,
  lang,
  ariaLabel,
}: {
  rows?: number;
  cols?: number;
  lang?: Language;
  ariaLabel?: string;
} = {}) {
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {}
  const norm = normalizeLanguage(lang ?? ctxLang);
  const defaultTableLabel =
    norm === "en" ? "Loading table…" : norm === "zh" ? "正在加载表格…" : "Đang tải bảng…";

  return (
    <SkeletonWrap lang={norm} ariaLabel={ariaLabel ?? defaultTableLabel}>
      <div className="skeleton-table">
        <div className="skeleton-table-head">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} width="70%" height={12} />
          ))}
        </div>
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="skeleton-table-row">
            {Array.from({ length: cols }).map((_, c) => (
              <Skeleton
                key={c}
                width={c === 0 ? "85%" : c === 1 ? "50%" : c === cols - 1 ? "30%" : "65%"}
                height={12}
              />
            ))}
          </div>
        ))}
      </div>
    </SkeletonWrap>
  );
}

/** Grey, dashed placeholder for a value that was never measured (§1.2). */
export function NotMeasured({ text }: { text: string }) {
  return (
    <div className="notmeasured">
      <span aria-hidden="true">∅</span>
      <span>{text}</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Action / Retry buttons (§3.4)                                      */
/* ------------------------------------------------------------------ */

export interface ActionButtonProps {
  onClick?: () => void;
  disabled?: boolean;
  label?: ReactNode;
  title?: string;
  icon?: ReactNode;
  variant?: "primary" | "ghost" | "danger" | "secondary";
  size?: "sm" | "md" | "lg";
  className?: string;
  lang?: Language;
  children?: ReactNode;
  type?: "button" | "submit" | "reset";
}

export function ActionButton({
  onClick,
  disabled,
  label,
  title,
  icon,
  variant = "ghost",
  size = "sm",
  className,
  lang,
  children,
  type = "button",
}: ActionButtonProps) {
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {}
  const activeLang = normalizeLanguage(lang ?? ctxLang);
  const defaultLabel =
    activeLang === "en" ? "Action" : activeLang === "zh" ? "操作" : "Thao tác";
  const defaultTitle =
    activeLang === "en" ? "Perform action" : activeLang === "zh" ? "执行操作" : "Thực hiện thao tác";

  return (
    <button
      type={type}
      className={cx(
        "btn",
        size === "sm" && "btn--sm",
        size === "lg" && "btn--lg",
        variant === "primary" && "btn--primary",
        variant === "ghost" && "btn--ghost",
        variant === "danger" && "btn--danger",
        className,
      )}
      onClick={onClick}
      disabled={disabled}
      title={title ?? defaultTitle}
    >
      {icon ? <span className="btn__icon" aria-hidden="true">{icon}</span> : null}
      {children ?? label ?? defaultLabel}
    </button>
  );
}

export interface RetryButtonProps {
  onRetry: () => void;
  /** Disabled while a check is already running. */
  disabled?: boolean;
  label?: string;
  title?: string;
  lang?: Language;
}

export function RetryButton({
  onRetry,
  disabled,
  label,
  title,
  lang,
}: RetryButtonProps) {
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {}
  const norm = normalizeLanguage(lang ?? ctxLang);
  const defaultLabel = norm === "en" ? "Retry" : norm === "zh" ? "重试" : "Thử lại";
  const defaultTitle =
    norm === "en"
      ? "Re-run this module individually"
      : norm === "zh"
      ? "单独重试此模块"
      : "Chạy lại riêng module này";
  return (
    <button
      type="button"
      className="btn btn--sm btn--ghost"
      onClick={onRetry}
      disabled={disabled}
      title={title ?? defaultTitle}
    >
      ↻ {label ?? defaultLabel}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Error box & inline error line (§3.4)                               */
/* ------------------------------------------------------------------ */

export interface ErrorBoxProps {
  title?: string;
  message?: ReactNode;
  prefix?: string;
  error?: { kind?: string; message?: string | null } | string | null;
  actions?: ReactNode;
  className?: string;
  lang?: Language;
  children?: ReactNode;
}

export function ErrorBox({
  title,
  message,
  prefix,
  error,
  actions,
  className,
  lang,
  children,
}: ErrorBoxProps) {
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {}
  const activeLang = normalizeLanguage(lang ?? ctxLang);

  const defaultTitle =
    activeLang === "en" ? "Error encountered" : activeLang === "zh" ? "发生错误" : "Đã xảy ra lỗi";
  const defaultPrefix =
    activeLang === "en" ? "Error: " : activeLang === "zh" ? "错误: " : "Lỗi: ";

  let errorDetail: ReactNode = message ?? children;
  if (!errorDetail && error) {
    if (typeof error === "string") {
      errorDetail = error;
    } else {
      const kindStr = error.kind ? errorKindLabel(error.kind, activeLang) : null;
      errorDetail = error.message ?? kindStr;
    }
  }

  const effectivePrefix = prefix !== undefined ? prefix : defaultPrefix;

  return (
    <div className={cx("banner banner--error", className)} role="alert">
      <span className="banner__icon" aria-hidden="true">
        ×
      </span>
      <div className="banner__text">
        <div className="banner__title">{title ?? defaultTitle}</div>
        {errorDetail ? (
          <div className="banner__detail">
            {effectivePrefix && typeof errorDetail === "string" && !errorDetail.startsWith(effectivePrefix) ? (
              <span>{effectivePrefix}{errorDetail}</span>
            ) : (
              errorDetail
            )}
          </div>
        ) : null}
      </div>
      {actions ? <div className="banner__actions">{actions}</div> : null}
    </div>
  );
}

export function ErrorLine({
  error,
  fallback,
  lang,
}: {
  error: { kind?: string; message?: string | null } | null | undefined;
  fallback?: string;
  lang?: Language;
}) {
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {}
  const norm = normalizeLanguage(lang ?? ctxLang);
  const kind = error ? errorKindLabel(error.kind, norm) : null;
  const prefix = norm === "en" ? "Error: " : norm === "zh" ? "错误: " : "Lỗi: ";
  const defaultText = norm === "en" ? "Error" : norm === "zh" ? "错误" : "Lỗi";
  const text = fallback ?? (kind ? `${prefix}${kind}` : defaultText);
  return (
    <span className="text-bad" title={error?.message ?? undefined}>
      {kind ? `${prefix}${kind}` : text}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Health dot (§5.5)                                                   */
/* ------------------------------------------------------------------ */

export function HealthDot({
  state,
  label,
}: {
  state: "green" | "yellow" | "red" | "unknown";
  label?: string;
}) {
  return (
    <span className="dotrow" title={label ?? state}>
      <span className={cx("dot", `dot--${state}`)} aria-hidden="true" />
      {label ? <span className="dotrow__name">{label}</span> : null}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* External source link (§3.3: "link gốc mở được")                     */
/* ------------------------------------------------------------------ */

export function SourceLink({
  href,
  text,
  lang,
}: {
  href: string | null | undefined;
  text?: string;
  lang?: Language;
}) {
  if (!href) return <span className="muted">—</span>;
  let ctxLang: Language | undefined;
  try {
    const ctx = useI18n();
    ctxLang = ctx?.lang;
  } catch {}
  const norm = normalizeLanguage(lang ?? ctxLang);
  const defaultText = norm === "en" ? "open" : norm === "zh" ? "打开" : "mở";
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      title={href}
      onClick={(e) => {
        if (isTauri()) {
          e.preventDefault();
          void openExternal(href);
        }
      }}
    >
      {text ?? defaultText}
    </a>
  );
}
