/**
 * LeakSpeedCard — the "LEAK + TỐC ĐỘ (proxy only)" cell of §3.2 (§8, §8.2, §8.3).
 *
 * THE most important rule in this file (§1.2, §3.3, test §13.3):
 * in IP-only mode the card shows EXACTLY "Chưa đo được — cần nhập proxy".
 * It never renders a 0, never renders a fabricated number.
 *
 * `measured === false` from the backend is treated as "not measured" no matter
 * what else the payload contains, so a half-filled payload can never leak a
 * made-up 0 Mbps / 0 ms into the UI. The two sub-blocks are rendered by small
 * typed sub-components that receive a NON-nullable value, so the compiler
 * proves the narrowing instead of relying on a comment.
 */

import type {
  ExitIpResult,
  LeakResult,
  SpeedEndpoint,
  SpeedResult,
} from "../lib/types";
import { Banner, Empty, Kvp, NotMeasured, Panel, Section } from "./ui/parts";
import {
  cx,
  DASH,
  fmtBytes,
  fmtMbps,
  fmtMs,
  fmtNum,
  fmtTime,
  getLocalizedNotMeasuredProxy,
  getLocalizedProviderReason,
  getLocalizedShortError,
  getLocalizedYesNo,
  NOT_MEASURED_PROXY,
  valueOrDash,
} from "./ui/meta";
import { useI18n, type Language } from "../lib/i18n";

export interface LeakSpeedCardProps {
  mode: "ip_only" | "proxy" | "unknown";
  leak: LeakResult | null | undefined;
  speed: SpeedResult | null | undefined;
  exitIp: ExitIpResult | null | undefined;
  /** IP the user typed, to compare with the real exit IP (§8.1). */
  inputIp?: string | null;
  /** True while leak/speed still run. */
  loading?: boolean;
  onRetry?: () => void;
  canRetry?: boolean;
}

/** `measured === true` guard: anything else means "nothing measured" (§1.2). */
function measuredLeakOf(leak: LeakResult | null | undefined): LeakResult | null {
  return leak && leak.measured ? leak : null;
}

function measuredSpeedOf(speed: SpeedResult | null | undefined): SpeedResult | null {
  return speed && speed.measured ? speed : null;
}

/**
 * Fallback reason for proxy mode when the backend sent no note of its own.
 *
 * §1.2 only permits "Chưa đo được — cần nhập proxy" when there is genuinely no
 * proxy. In proxy mode the user already supplied one, so blaming the missing
 * proxy is a lie; the honest statement is that the measurement could not run.
 */
function getNotMeasuredBrowserText(lang: Language): string {
  if (lang === "en") return "Not measured — browser cannot run through this proxy";
  if (lang === "zh") return "未测量 — 浏览器无法通过此代理运行";
  return "Chưa đo được — trình duyệt không chạy được qua proxy này";
}

/**
 * The single sentence shown for an unmeasured leak/speed block.
 */
function notMeasuredText(
  note: string | null | undefined,
  hasProxy: boolean,
  fallback: string,
  lang: Language = "vi",
): string {
  const trimmed = note?.trim();
  if (trimmed) return getLocalizedProviderReason(trimmed, lang);
  return hasProxy ? getNotMeasuredBrowserText(lang) : fallback;
}

export function LeakSpeedCard({
  mode,
  leak,
  speed,
  exitIp,
  inputIp,
  loading,
  onRetry,
  canRetry,
}: LeakSpeedCardProps) {
  const { lang, t } = useI18n();

  // §1.2: IP-only must not display any measurement at all.
  // Note: NOT_MEASURED_PROXY string is preserved verbatim for §13.7 static tests.
  if (mode !== "proxy") {
    const unmeasuredText = getLocalizedNotMeasuredProxy(lang);
    return (
      <Panel
        title={t("leak_speed.title")}
        hint={lang === "zh" ? "仅代理模式" : "proxy only"}
        footer={
          <span>
            {lang === "en"
              ? "requires IP:port + protocol"
              : lang === "zh"
                ? "需要 IP:端口 + 协议"
                : "cần IP:port + giao thức"}
          </span>
        }
      >
        <div className="col">
          <NotMeasured text={unmeasuredText || NOT_MEASURED_PROXY} />
          <div className="tiny muted">
            {lang === "en"
              ? "DNS/WebRTC leak and actual speed can only be measured when traffic routes through a proxy. Enter 1.2.3.4:8080 and choose protocol to enable."
              : lang === "zh"
                ? "DNS/WebRTC 泄漏和实际网速仅在流量走代理时可测。输入 1.2.3.4:8080 并选择协议以启用此模块。"
                : "Leak DNS/WebRTC và tốc độ thật chỉ đo được khi traffic đi qua proxy. Nhập dạng 1.2.3.4:8080 và chọn giao thức để bật module này."}
          </div>
        </div>
      </Panel>
    );
  }

  const shownLeak = measuredLeakOf(leak);
  const shownSpeed = measuredSpeedOf(speed);
  const leakError = leak?.error ?? null;
  const speedError = speed?.error ?? null;

  const hasLeakFlag = shownLeak
    ? Boolean(
        shownLeak.webrtc_leak ||
          shownLeak.dns_leak === true ||
          shownLeak.timezone_mismatch ||
          shownLeak.country_mismatch,
      )
    : false;

  return (
    <Panel
      title={t("leak_speed.title")}
      hint={
        hasLeakFlag ? (
          <span className="text-bad">
            {lang === "en" ? "leak detected" : lang === "zh" ? "检测到泄漏" : "có dấu hiệu leak"}
          </span>
        ) : (
          "proxy-check"
        )
      }
      footer={
        <>
          <span>
            {shownLeak
              ? lang === "en"
                ? "leak: measured"
                : lang === "zh"
                  ? "泄漏: 已测量"
                  : "leak: đã đo"
              : lang === "en"
                ? "leak: not measured"
                : lang === "zh"
                  ? "泄漏: 未测量"
                  : "leak: chưa đo"}{" "}
            ·{" "}
            {shownSpeed
              ? lang === "en"
                ? "speed: measured"
                : lang === "zh"
                  ? "速度: 已测量"
                  : "tốc độ: đã đo"
              : lang === "en"
                ? "speed: not measured"
                : lang === "zh"
                  ? "速度: 未测量"
                  : "tốc độ: chưa đo"}
          </span>
          <span className="mono">{shownSpeed?.measured_at ? fmtTime(shownSpeed.measured_at) : DASH}</span>
        </>
      }
    >
      <div className="col">
        <ExitIpSection exitIp={exitIp} inputIp={inputIp} loading={loading} lang={lang} />

        <Section title="Leak">
          {shownLeak ? (
            <LeakDetail leak={shownLeak} lang={lang} />
          ) : (
            <>
              {/* `mode === "proxy"` here, so `hasProxy` is true: the backend note
                  (or the browser-unavailable fallback) — never "cần nhập proxy". */}
              <NotMeasured
                text={notMeasuredText(
                  leak?.notes[0],
                  true,
                  getLocalizedNotMeasuredProxy(lang),
                  lang,
                )}
              />
              {leakError ? (
                <RetryLine
                  label={`${lang === "en" ? "Error: " : lang === "zh" ? "错误: " : "Lỗi: "}${getLocalizedShortError(
                    leakError,
                    lang,
                  )}`}
                  action={lang === "en" ? "Retry leak" : lang === "zh" ? "重试泄漏检测" : "Thử lại leak"}
                  onRetry={onRetry}
                  canRetry={canRetry}
                />
              ) : loading ? (
                <div className="tiny muted">
                  {lang === "en"
                    ? "Running headless Chromium via proxy…"
                    : lang === "zh"
                      ? "正在通过代理运行无头Chromium…"
                      : "Đang chạy Chromium headless qua proxy…"}
                </div>
              ) : null}
            </>
          )}
        </Section>

        <Section title={lang === "en" ? "Speed" : lang === "zh" ? "测速" : "Tốc độ"}>
          {shownSpeed ? (
            <SpeedDetail speed={shownSpeed} lang={lang} />
          ) : (
            <>
              <NotMeasured
                text={notMeasuredText(
                  speed?.notes[0],
                  true,
                  getLocalizedNotMeasuredProxy(lang),
                  lang,
                )}
              />
              {speedError ? (
                <RetryLine
                  label={`${lang === "en" ? "Error: " : lang === "zh" ? "错误: " : "Lỗi: "}${getLocalizedShortError(
                    speedError,
                    lang,
                  )}`}
                  action={lang === "en" ? "Retry speed" : lang === "zh" ? "重试测速" : "Thử lại tốc độ"}
                  onRetry={onRetry}
                  canRetry={canRetry}
                />
              ) : null}
            </>
          )}
        </Section>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Exit IP (§8.1)                                                      */
/* ------------------------------------------------------------------ */

interface ExitIpSectionProps {
  exitIp: ExitIpResult | null | undefined;
  inputIp?: string | null;
  loading?: boolean;
  lang?: Language;
}

function ExitIpSection({ exitIp, inputIp, loading, lang = "vi" }: ExitIpSectionProps) {
  const sectionTitle = lang === "en" ? "Actual Exit IP" : lang === "zh" ? "实际出口IP" : "IP thoát thật";

  if (!exitIp) {
    return (
      <Section title={sectionTitle}>
        <Empty icon="🚪">
          {loading
            ? lang === "en"
              ? "Detecting exit IP via proxy…"
              : lang === "zh"
                ? "正在检测代理出口IP…"
                : "Đang đo IP thoát qua proxy…"
            : lang === "en"
              ? "Exit IP not measured."
              : lang === "zh"
                ? "尚未测量出口IP。"
                : "Chưa đo IP thoát."}
        </Empty>
      </Section>
    );
  }

  const exitDiffers = Boolean(exitIp.differs_from_input);

  return (
    <Section title={sectionTitle}>
      <div className="kv kv--dense">
        <Kvp
          k={lang === "en" ? "Exit IP" : lang === "zh" ? "出口IP" : "IP thoát"}
          v={valueOrDash(exitIp.exit_ip)}
          tone={exitDiffers ? "bad" : exitIp.exit_ip ? "clean" : "unknown"}
        />
        <Kvp
          k={lang === "en" ? "Matches input" : lang === "zh" ? "匹配输入IP" : "Khớp IP nhập"}
          v={
            exitDiffers
              ? lang === "en"
                ? "MISMATCH"
                : lang === "zh"
                  ? "不一致"
                  : "KHÁC"
              : exitIp.exit_ip
                ? lang === "en"
                  ? "matches"
                  : lang === "zh"
                    ? "一致"
                    : "khớp"
                : DASH
          }
          tone={exitDiffers ? "bad" : undefined}
        />
      </div>

      {exitDiffers ? (
        <Banner
          tone="error"
          title={
            lang === "en"
              ? "Exit IP differs from input IP"
              : lang === "zh"
                ? "出口IP与输入IP不一致"
                : "IP thoát khác IP đã nhập"
          }
          detail={
            lang === "en"
              ? `Input ${valueOrDash(inputIp)} but exited as ${valueOrDash(
                  exitIp.exit_ip,
                )} — rotating proxy or gateway translation.`
              : lang === "zh"
                ? `输入为 ${valueOrDash(inputIp)} 但出口为 ${valueOrDash(
                    exitIp.exit_ip,
                  )} — 属于轮换代理或网关转发。`
                : `Nhập ${valueOrDash(inputIp)} nhưng thoát ra ${valueOrDash(
                    exitIp.exit_ip,
                  )} — proxy xoay IP hoặc bị chèn gateway.`
          }
        />
      ) : null}

      {exitIp.endpoints_disagree ? (
        <div className="tiny text-temp">
          {lang === "en"
            ? "Endpoints returned different IPs — rotating proxy detected; measurements reflect one capture."
            : lang === "zh"
              ? "不同端点返回不同IP — 检测到轮换代理；以下结果为单次抓取数值。"
              : "Hai endpoint trả về IP khác nhau — proxy xoay (rotating), số đo dưới đây chỉ là một lần bắt."}
        </div>
      ) : null}

      <div className="tblwrap" style={{ maxHeight: 66 }}>
        <table className="tbl tbl--compact">
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>IP</th>
              <th className="tbl__num">ms</th>
            </tr>
          </thead>
          <tbody>
            {exitIp.endpoint_results.map((endpoint, index) => (
              <tr
                key={`${endpoint.endpoint}-${index}`}
                className={cx(endpoint.ok ? undefined : "tbl__row--error")}
              >
                <td className="truncate" title={endpoint.endpoint}>
                  {endpoint.endpoint}
                </td>
                <td className="mono">
                  {endpoint.ok
                    ? valueOrDash(endpoint.exit_ip)
                    : lang === "en"
                      ? "error"
                      : lang === "zh"
                        ? "错误"
                        : "lỗi"}
                </td>
                <td className="tbl__num">{fmtMs(endpoint.latency_ms)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

/* ------------------------------------------------------------------ */
/* Leak detail (§8.2) — `leak` is non-nullable here on purpose          */
/* ------------------------------------------------------------------ */

function LeakDetail({ leak, lang = "vi" }: { leak: LeakResult; lang?: Language }) {
  const cleanLabel = lang === "en" ? "no leak" : lang === "zh" ? "无泄漏" : "không leak";
  const leakLabel = lang === "en" ? "LEAK" : lang === "zh" ? "存在泄漏" : "LEAK";

  return (
    <>
      <div className="kv kv--dense">
        <Kvp
          k="WebRTC"
          v={leak.webrtc_leak ? leakLabel : cleanLabel}
          tone={leak.webrtc_leak ? "bad" : "clean"}
          sub={
            leak.webrtc_leak && leak.webrtc_candidates.length > 0
              ? `${lang === "en" ? "Real candidate IP exposed: " : lang === "zh" ? "真实候选IP暴露: " : "Candidate lòi IP thật: "}${leak.webrtc_candidates.slice(0, 2).join(", ")}`
              : undefined
          }
        />
        <Kvp
          k="DNS leak"
          v={
            leak.dns_leak === null
              ? lang === "en"
                ? "inconclusive"
                : lang === "zh"
                  ? "未确定"
                  : "chưa kết luận"
              : leak.dns_leak
                ? leakLabel
                : cleanLabel
          }
          tone={leak.dns_leak === null ? "unknown" : leak.dns_leak ? "bad" : "clean"}
          sub={`${lang === "en" ? "method: " : lang === "zh" ? "检测方式: " : "phương pháp: "}${valueOrDash(leak.dns_method)}${
            leak.dns_resolver_seen
              ? ` · ${lang === "en" ? "resolver: " : lang === "zh" ? "解析器: " : "resolver thấy: "}${leak.dns_resolver_seen}`
              : ""
          }`}
        />
        <Kvp
          k="Timezone"
          v={
            leak.timezone_mismatch
              ? `${lang === "en" ? "mismatch" : lang === "zh" ? "不一致" : "lệch"} (${valueOrDash(leak.browser_timezone)} vs ${valueOrDash(leak.ip_timezone)})`
              : lang === "en"
                ? "match"
                : lang === "zh"
                  ? "一致"
                  : "khớp"
          }
          tone={leak.timezone_mismatch ? "suspect" : "clean"}
        />
        <Kvp
          k={lang === "en" ? "Language / Country" : lang === "zh" ? "语言 / 国家" : "Ngôn ngữ / nước"}
          v={`${valueOrDash(leak.browser_language)} · ${valueOrDash(leak.ip_country)}`}
          tone={leak.country_mismatch ? "suspect" : undefined}
        />
        <Kvp
          k="Headless flag"
          v={
            leak.headless_flags.length > 0
              ? leak.headless_flags.join(", ")
              : lang === "en"
                ? "none"
                : lang === "zh"
                  ? "未发现"
                  : "không thấy"
          }
          tone={leak.headless_flags.length > 0 ? "suspect" : "clean"}
          sub={
            lang === "en"
              ? "Warning only, not solely conclusive (§8.2)"
              : lang === "zh"
                ? "仅供参考，不作为单一依据 (§8.2)"
                : "Chỉ cảnh báo, không dùng làm verdict duy nhất (§8.2)"
          }
        />
        <Kvp
          k="JA3"
          v={
            leak.ja3
              ? leak.ja3
              : lang === "en"
                ? "unavailable"
                : lang === "zh"
                  ? "不可用"
                  : "không lấy được"
          }
          tone="muted"
          sub={
            leak.ja3
              ? `${lang === "en" ? "source: " : lang === "zh" ? "来源: " : "nguồn: "}${valueOrDash(leak.ja3_source)} · ${lang === "en" ? "low confidence" : lang === "zh" ? "置信度低" : "độ tin cậy thấp"}`
              : undefined
          }
        />
        <Kvp
          k="TCP/IP fingerprint"
          v={getLocalizedYesNo(
            leak.tcp_fingerprint_mismatch,
            lang,
            lang === "vi" ? "chưa rõ" : lang === "zh" ? "未确定" : "unknown",
          )}
          tone={leak.tcp_fingerprint_mismatch ? "temp" : undefined}
        />
      </div>

      {leak.downgrade ? (
        <Banner
          tone="error"
          title={
            lang === "en"
              ? "Leak caused verdict downgrade"
              : lang === "zh"
                ? "泄漏导致判定降级"
                : "Leak làm hạ bậc verdict"
          }
          detail={
            lang === "en"
              ? "WebRTC leaked real IP or DNS queries bypassed proxy — verdict downgraded per §6.5."
              : lang === "zh"
                ? "WebRTC暴露了真实IP或DNS查询绕过了代理 — 判定结果根据§6.5降级。"
                : "WebRTC lòi IP thật hoặc DNS đi ngoài proxy — verdict bị hạ theo §6.5."
          }
        />
      ) : null}

      {leak.notes.length > 0 ? (
        <div
          className="tiny muted"
          title={leak.notes.map((n) => getLocalizedProviderReason(n, lang)).join(" · ")}
        >
          {getLocalizedProviderReason(leak.notes[0], lang)}
        </div>
      ) : null}
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Speed detail (§8.3) — `speed` is non-nullable here on purpose        */
/* ------------------------------------------------------------------ */

function SpeedDetail({ speed, lang = "vi" }: { speed: SpeedResult; lang?: Language }) {
  const jitter = speed.jitter_ms;
  return (
    <>
      <div className="kv kv--dense">
        <Kvp k="Download" v={fmtMbps(speed.download_mbps)} tone="cyan" />
        <Kvp k="Latency" v={fmtMs(speed.latency_ms)} />
        <Kvp
          k="Jitter"
          v={fmtMs(jitter)}
          tone={jitter === null || jitter === undefined ? "unknown" : jitter > 60 ? "suspect" : "clean"}
        />
        <Kvp
          k="Upload"
          v={
            speed.upload_mbps === null
              ? lang === "en"
                ? "not measured"
                : lang === "zh"
                  ? "未测量"
                  : "không đo"
              : fmtMbps(speed.upload_mbps)
          }
          tone="muted"
          sub={
            speed.upload_mbps === null
              ? lang === "en"
                ? "only measured when public upload endpoint is available (§8.3)"
                : lang === "zh"
                  ? "仅在有公开上传端点时测试 (§8.3)"
                  : "chỉ đo khi có endpoint upload công khai (§8.3)"
              : undefined
          }
        />
      </div>

      <div className="tblwrap" style={{ maxHeight: 78 }}>
        <table className="tbl tbl--compact">
          <thead>
            <tr>
              <th>Endpoint</th>
              <th className="tbl__num">Mbps</th>
              <th className="tbl__num">ms</th>
              <th className="tbl__num">{lang === "en" ? "Size" : lang === "zh" ? "大小" : "Size"}</th>
            </tr>
          </thead>
          <tbody>
            {speed.endpoints.map((endpoint: SpeedEndpoint, index: number) => (
              <tr
                key={`${endpoint.endpoint}-${index}`}
                className={cx(endpoint.ok ? undefined : "tbl__row--error")}
              >
                <td className="truncate" title={endpoint.endpoint}>
                  {endpoint.endpoint}
                </td>
                <td className="tbl__num">{endpoint.ok ? fmtMbps(endpoint.download_mbps) : DASH}</td>
                <td className="tbl__num">{fmtMs(endpoint.latency_ms)}</td>
                <td className="tbl__num">{fmtBytes(endpoint.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="tiny muted">
        {lang === "en"
          ? "Speed depends on target servers and network congestion — relative comparison only (§8.3)."
          : lang === "zh"
            ? "速度取决于目标服务器和网络拥塞情况 — 仅作相对比较 (§8.3)。"
            : "Tốc độ phụ thuộc server đích và giờ đo — chỉ so sánh tương đối trong cùng lần test (§8.3)."}
        {speed.measured_at
          ? lang === "en"
            ? ` Measured at ${fmtTime(speed.measured_at)}.`
            : lang === "zh"
              ? ` 测量于 ${fmtTime(speed.measured_at)}。`
              : ` Đo lúc ${fmtTime(speed.measured_at)}.`
          : ""}
      </div>

      {speed.endpoints.length > 0 ? (
        <div className="tiny muted mono">
          {lang === "en"
            ? `tested from ${fmtNum(speed.endpoints.length, 0)} endpoint(s)`
            : lang === "zh"
              ? `测试来自 ${fmtNum(speed.endpoints.length, 0)} 个端点`
              : `đo từ ${fmtNum(speed.endpoints.length, 0)} endpoint`}
        </div>
      ) : null}
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Small per-module error + retry line (§3.4)                          */
/* ------------------------------------------------------------------ */

function RetryLine({
  label,
  action,
  onRetry,
  canRetry,
}: {
  label: string;
  action: string;
  onRetry?: () => void;
  canRetry?: boolean;
}) {
  return (
    <div className="row">
      <span className="tiny text-bad">{label}</span>
      {onRetry ? (
        <button type="button" className="btn btn--sm btn--ghost" onClick={onRetry} disabled={!canRetry}>
          ↻ {action}
        </button>
      ) : null}
    </div>
  );
}

export default LeakSpeedCard;
