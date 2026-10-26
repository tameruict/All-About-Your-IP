/**
 * OverviewCard — the "TỔNG QUAN" cell of §3.2.
 *
 * Contents required by the spec's ASCII layout: ASN, ISP, IP type, reverse DNS.
 * This file is a layout extra (the 11 mandated components of §3.3 keep their
 * exact filenames); keeping it separate stops ReputationCard from turning into
 * a grab-bag.
 */

import type { AsnResult, IpType, NetworkResult } from "../lib/types";
import { Empty, Kvp, Panel, Section, SkeletonKv } from "./ui/parts";
import {
  cx,
  DASH,
  fmtInt,
  fmtMs,
  getLocalizedIpTypeLabel,
  getLocalizedYesNo,
  UNRELIABLE_CITY_TYPES,
  valueOrDash,
} from "./ui/meta";
import { useI18n } from "../lib/i18n";

export interface OverviewCardProps {
  ip: string | null;
  mode: "ip_only" | "proxy" | "unknown";
  ipVersion?: 4 | 6 | null;
  asn: AsnResult | null | undefined;
  network: NetworkResult | null | undefined;
  /** Country decided by the location engine, used as a cross-check column. */
  country?: string | null;
  /** True while the asn/geo modules still stream. */
  loading?: boolean;
  onRetry?: () => void;
  canRetry?: boolean;
}

const IP_TYPE_TONE: Record<IpType, string> = {
  residential: "text-clean",
  datacenter: "text-temp",
  mobile: "text-temp",
  cgnat: "text-temp",
  vpn: "text-suspect",
  proxy: "text-suspect",
  tor: "text-bad",
  anycast: "text-temp",
  edu: "text-clean",
  unknown: "text-unknown",
};

export function OverviewCard({
  ip,
  mode,
  ipVersion,
  asn,
  network,
  country,
  loading,
  onRetry,
  canRetry,
}: OverviewCardProps) {
  const { lang, t } = useI18n();
  const hasAny = Boolean(asn || network || ip);
  const flags = asn?.flags ?? null;

  const isResidential = asn?.ip_type === "residential";
  const isDatacenter = Boolean(flags?.hosting || asn?.ip_type === "datacenter");
  const isProxy = Boolean(flags?.proxy || asn?.ip_type === "proxy");
  const isVpn = Boolean(flags?.vpn || asn?.ip_type === "vpn");
  const isTor = Boolean(flags?.tor || asn?.ip_type === "tor");
  const isMobile = Boolean(flags?.mobile || asn?.ip_type === "mobile");

  const riskChecklist = [
    {
      label: t("overview.residential"),
      active: isResidential,
      tone: isResidential ? "chip--clean" : "chip--muted",
    },
    {
      label: t("overview.datacenter"),
      active: isDatacenter,
      tone: isDatacenter ? "chip--bad" : "chip--muted",
    },
    {
      label: t("overview.proxy"),
      active: isProxy,
      tone: isProxy ? "chip--suspect" : "chip--muted",
    },
    {
      label: t("overview.vpn"),
      active: isVpn,
      tone: isVpn ? "chip--suspect" : "chip--muted",
    },
    {
      label: t("overview.tor"),
      active: isTor,
      tone: isTor ? "chip--bad" : "chip--muted",
    },
    {
      label: t("overview.mobile"),
      active: isMobile,
      tone: isMobile ? "chip--info" : "chip--muted",
    },
  ];

  const cityUnreliable = asn ? UNRELIABLE_CITY_TYPES.includes(asn.ip_type) : false;

  return (
    <Panel
      title={t("overview.title")}
      hint={ip ? <span className="mono">{ip}</span> : t("overview.no_ip")}
      footer={
        <>
          <span>{mode === "proxy" ? t("input.mode_proxy") : mode === "ip_only" ? t("input.mode_ip") : DASH}</span>
          <span className="mono">IPv{ipVersion ?? DASH}</span>
        </>
      }
    >
      {!hasAny ? (
        loading ? (
          <SkeletonKv count={7} />
        ) : (
          <Empty icon="🌐">{t("overview.not_checked")}</Empty>
        )
      ) : (
        <div className="col">
          <Section>
            <div className="kv kv--dense">
              <Kvp k="IP" v={valueOrDash(ip)} tone="cyan" />
              <Kvp
                k={t("overview.country_geo")}
                v={valueOrDash(country ?? asn?.rir_country)}
                tone={asn?.country_mismatch ? "bad" : undefined}
                sub={
                  asn?.country_mismatch
                    ? lang === "en"
                      ? `RIR reports ${valueOrDash(asn.rir_country)} — country mismatch (§7.4)`
                      : lang === "zh"
                        ? `RIR报告为 ${valueOrDash(asn.rir_country)} — 国家/地区不一致 (§7.4)`
                        : `RIR nói ${valueOrDash(asn.rir_country)} — lệch quốc gia geo (§7.4)`
                    : undefined
                }
              />
              <Kvp
                k={t("overview.asn")}
                v={
                  asn && (asn.asn !== null || asn.asn_name)
                    ? `${asn.asn !== null ? `AS${fmtInt(asn.asn)}` : ""}${
                        asn.asn_name ? ` · ${asn.asn_name}` : ""
                      }`
                    : DASH
                }
                tone={asn && !asn.consensus ? "temp" : undefined}
                sub={
                  asn && !asn.consensus
                    ? lang === "en"
                      ? "ASN sources have not reached consensus (§6.3)"
                      : lang === "zh"
                        ? "ASN数据源尚未形成共识 (§6.3)"
                        : "Các nguồn ASN chưa đồng thuận (§6.3)"
                    : undefined
                }
              />
              <Kvp k={t("overview.isp_org")} v={valueOrDash(asn?.isp ?? asn?.organisation)} />
              <Kvp k={t("overview.prefix")} v={valueOrDash(asn?.prefix)} />
              <Kvp
                k={t("overview.ip_type")}
                v={
                  <span className={cx(asn ? IP_TYPE_TONE[asn.ip_type] : "text-unknown")}>
                    {getLocalizedIpTypeLabel(asn?.ip_type, lang)}
                  </span>
                }
                sub={cityUnreliable ? t("overview.city_unreliable") : undefined}
              />
              <Kvp
                k={t("overview.reverse_dns")}
                v={valueOrDash(network?.reverse_dns)}
                tone={network?.reverse_dns_matches_isp === false ? "temp" : undefined}
                sub={
                  network
                    ? network.reverse_dns
                      ? `${t("overview.matches_isp")}: ${getLocalizedYesNo(
                          network.reverse_dns_matches_isp,
                          lang,
                          lang === "vi" ? "chưa rõ" : lang === "zh" ? "未确定" : "unknown",
                        )}`
                      : t("overview.dynamic_ip_note")
                    : undefined
                }
              />
              <Kvp
                k={t("overview.ttl_os")}
                v={
                  network && (network.ttl !== null || network.os_guess)
                    ? `${network.ttl !== null ? `TTL ${network.ttl}` : DASH}${
                        network.os_guess ? ` · ${network.os_guess}` : ""
                      }`
                    : DASH
                }
                tone="muted"
              />
              <Kvp k={t("overview.avg_ping")} v={fmtMs(network?.latency_avg_ms)} tone="muted" />
            </div>
          </Section>

          <Section title={t("overview.risk_detection")}>
            <div className="risk-grid">
              {riskChecklist.map((item) => (
                <div key={item.label} className="risk-row">
                  <span className="risk-row__label">{item.label}</span>
                  <span className={cx("chip", item.tone)}>
                    {getLocalizedYesNo(item.active, lang)}
                  </span>
                </div>
              ))}
            </div>
          </Section>

          {onRetry && canRetry && !asn ? (
            <button type="button" className="btn btn--sm btn--ghost" onClick={onRetry}>
              {t("overview.retry_asn_geo")}
            </button>
          ) : null}
        </div>
      )}
    </Panel>
  );
}

export default OverviewCard;
