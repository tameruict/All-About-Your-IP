/**
 * NetworkCard — the "MẠNG" cell of §3.2 (§9).
 *
 * ping / loss / traceroute / TTL. Two spec points drive the UI:
 * - the probe METHOD is always stated (ICMP vs TCP fallback), so a blocked
 *   ICMP never looks like "0 ms" (§9);
 * - an unavailable measurement renders "—", never a fabricated 0 (§14).
 */

import type { NetworkResult, TracerouteHop } from "../lib/types";
import { Empty, Kvp, Panel, Section, SkeletonKv } from "./ui/parts";
import {
  cx,
  DASH,
  fmtMs,
  fmtNum,
  fmtPct,
  getLocalizedProviderReason,
  getLocalizedYesNo,
  valueOrDash,
} from "./ui/meta";
import { useI18n, type Language } from "../lib/i18n";

export interface NetworkCardProps {
  network: NetworkResult | null | undefined;
  /** True while the network module still runs. */
  loading?: boolean;
  onRetry?: () => void;
  canRetry?: boolean;
  /** Reverse DNS is also shown on Tổng quan; here it is the hop context. */
  mode: "ip_only" | "proxy" | "unknown";
}

function getPingMethodLabel(method: string | null | undefined, lang: Language): string {
  if (!method) return DASH;
  const labels: Record<string, string> = {
    icmp: "ICMP",
    tcp_80: lang === "en" ? "TCP 80 (ICMP blocked)" : lang === "zh" ? "TCP 80 (ICMP被阻断)" : "TCP 80 (ICMP bị chặn)",
    tcp_443: lang === "en" ? "TCP 443 (ICMP blocked)" : lang === "zh" ? "TCP 443 (ICMP被阻断)" : "TCP 443 (ICMP bị chặn)",
    none: lang === "en" ? "unmeasured" : lang === "zh" ? "无法测量" : "không đo được",
  };
  return labels[method] ?? method;
}

export function NetworkCard({ network, loading, onRetry, canRetry, mode }: NetworkCardProps) {
  const { lang, t } = useI18n();
  const hops = network?.traceroute_hops ?? [];
  const lastHop = hops.length > 0 ? hops[hops.length - 1] : null;
  const international = hops.filter((hop: TracerouteHop) => hop.is_international).length;

  return (
    <Panel
      title={t("network.title")}
      hint={network ? getPingMethodLabel(network.ping_method, lang) : "ping · traceroute · TTL"}
      footer={
        <>
          <span>
            {hops.length > 0
              ? `${hops.length} ${lang === "en" ? (hops.length === 1 ? "hop" : "hops") : lang === "zh" ? "个跃点" : "hop"}`
              : lang === "en"
                ? "no traceroute"
                : lang === "zh"
                  ? "无路由追踪"
                  : "chưa có traceroute"}
          </span>
          <span className="mono">
            {network?.packets_sent !== null && network?.packets_sent !== undefined
              ? `${network.packets_received ?? 0}/${network.packets_sent} ${
                  lang === "en" ? "packets" : lang === "zh" ? "包" : "gói"
                }`
              : DASH}
          </span>
        </>
      }
    >
      {!network ? (
        loading ? (
          <SkeletonKv count={6} />
        ) : (
          <Empty icon="📶">
            {lang === "en"
              ? "No network data. IP-only mode still measures ping and reverse DNS."
              : lang === "zh"
                ? "暂无网络数据。单IP模式仍可测量延迟与反向DNS。"
                : "Chưa có dữ liệu mạng. IP-only vẫn đo được ping và reverse DNS."}
          </Empty>
        )
      ) : (
        <div className="col">
          <Section>
            <div className="kv kv--dense">
              <Kvp
                k={lang === "en" ? "Method" : lang === "zh" ? "探测方式" : "Phương pháp"}
                v={getPingMethodLabel(network.ping_method, lang)}
                tone="muted"
                sub={
                  lang === "en"
                    ? "If ICMP is blocked, falls back to TCP with explicit method label (§9)"
                    : lang === "zh"
                      ? "若ICMP被阻断则回退至TCP并标明探测方式 (§9)"
                      : "ICMP bị chặn thì fallback TCP và ghi rõ phương pháp (§9)"
                }
              />
              <Kvp
                k={lang === "en" ? "Avg Latency" : lang === "zh" ? "平均延迟" : "Latency TB"}
                v={fmtMs(network.latency_avg_ms)}
                tone="cyan"
              />
              <Kvp
                k="Min / Max"
                v={`${network.latency_min_ms !== null ? fmtMs(network.latency_min_ms) : DASH} / ${
                  network.latency_max_ms !== null ? fmtMs(network.latency_max_ms) : DASH
                }`}
                tone="muted"
              />
              <Kvp
                k="Jitter"
                v={fmtMs(network.jitter_ms)}
                tone={
                  network.jitter_ms === null || network.jitter_ms === undefined
                    ? "unknown"
                    : network.jitter_ms > 60
                      ? "suspect"
                      : "clean"
                }
              />
              <Kvp
                k={lang === "en" ? "Packet Loss" : lang === "zh" ? "丢包率" : "Mất gói"}
                v={fmtPct(network.packet_loss_pct, 1)}
                tone={
                  network.packet_loss_pct === null || network.packet_loss_pct === undefined
                    ? "unknown"
                    : network.packet_loss_pct > 10
                      ? "bad"
                      : network.packet_loss_pct > 0
                        ? "temp"
                        : "clean"
                }
              />
              <Kvp
                k={t("network.reverse_dns")}
                v={valueOrDash(network.reverse_dns)}
                sub={
                  network.reverse_dns
                    ? `${t("overview.matches_isp")}: ${getLocalizedYesNo(
                        network.reverse_dns_matches_isp,
                        lang,
                        lang === "vi" ? "chưa rõ" : lang === "zh" ? "未确定" : "unknown",
                      )}`
                    : lang === "en"
                      ? "No PTR record — common in datacenter IPs"
                      : lang === "zh"
                        ? "无PTR记录 — 许多机房IP刻意不配置PTR"
                        : "Không có PTR — nhiều IP datacenter cố tình không đặt PTR"
                }
              />
              <Kvp k="TTL" v={network.ttl !== null ? String(network.ttl) : DASH} tone="muted" />
              <Kvp k="TTL → OS" v={valueOrDash(network.os_guess)} tone="muted" />
            </div>
          </Section>

          {hops.length > 0 ? (
            <Section
              title={
                lang === "en"
                  ? `Traceroute${international > 0 ? ` · ${international} intl hop(s)` : ""}`
                  : lang === "zh"
                    ? `路由追踪${international > 0 ? ` · ${international} 个国际跃点` : ""}`
                    : `Traceroute${international > 0 ? ` · ${international} hop quốc tế` : ""}`
              }
            >
              <div className="tblwrap" style={{ maxHeight: 120 }}>
                <table className="tbl tbl--compact">
                  <thead>
                    <tr>
                      <th className="tbl__num">#</th>
                      <th>Hop</th>
                      <th className="tbl__num">RTT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hops.map((hop: TracerouteHop) => (
                      <tr key={`${hop.hop}-${hop.address ?? hop.hostname ?? ""}`}>
                        <td className="tbl__num">{hop.hop}</td>
                        <td className={cx("truncate", hop.is_international && "text-temp")}>
                          <span className="mono">{hop.address ?? "*"}</span>
                          {hop.hostname ? <span className="tbl__muted"> · {hop.hostname}</span> : null}
                        </td>
                        <td className="tbl__num">{hop.rtt_ms !== null ? fmtNum(hop.rtt_ms, 1) : DASH}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          ) : null}

          {lastHop && lastHop.is_international ? (
            <div
              className="tiny text-temp"
              title={
                lang === "en"
                  ? "RTT/intl hop is secondary evidence (§7.6)"
                  : lang === "zh"
                    ? "国际RTT与跃点仅作为辅助参考依据 (§7.6)"
                    : "RTT/hop quốc tế chỉ là bằng chứng phụ (§7.6)"
              }
            >
              {lang === "en"
                ? "Last hop exits country — used for location comparison, not conclusive."
                : lang === "zh"
                  ? "最后一跳路由指向境外 — 用于辅助位置比对，不直接作为结论。"
                  : "Hop cuối đi ra ngoài nước — dùng đối chiếu vị trí, không kết luận."}
            </div>
          ) : null}

          {network.notes.length > 0 ? (
            <div
              className="tiny muted"
              title={network.notes.map((n) => getLocalizedProviderReason(n, lang)).join(" · ")}
            >
              {getLocalizedProviderReason(network.notes[0], lang)}
            </div>
          ) : null}

          {mode === "ip_only" ? (
            <div className="tiny muted">
              {lang === "en"
                ? "Port checks only execute in proxy mode (§9) — currently pinging IP only."
                : lang === "zh"
                  ? "端口仅在代理模式下测试 (§9) — 当前仅测量至IP。"
                  : "Port chỉ được kiểm tra ở chế độ proxy (§9) — hiện chỉ đo tới IP."}
            </div>
          ) : null}

          {onRetry && canRetry && network.latency_avg_ms === null ? (
            <button type="button" className="btn btn--sm btn--ghost" onClick={onRetry}>
              ↻ {lang === "en" ? "Retry network" : lang === "zh" ? "重试网络探测" : "Thử lại mạng"}
            </button>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

export default NetworkCard;
