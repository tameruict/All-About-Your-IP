/**
 * UI-side helpers shared by every component.
 *
 * Rules enforced here:
 * - Multi-language display strings supported (Vietnamese 'vi', English 'en', Chinese 'zh').
 * - Vietnamese remains the default language across all helpers.
 * - Nothing here recomputes scoring (§4.1: the UI never scores). This module
 *   only maps backend values onto labels, colours and number formats.
 * - "Chưa đo được — cần nhập proxy" is exported once from here so the exact
 *   string from §1.2 cannot drift between components.
 */

import type {
  Category,
  DnsblGroup,
  HealthState,
  IpType,
  ModuleId,
  ModuleStatus,
  ProxyProtocol,
  Signal,
  SkipReason,
  Verdict,
} from "../../lib/types";

/* ------------------------------------------------------------------ */
/* Language types & normalisation                                      */
/* ------------------------------------------------------------------ */

export const SUPPORTED_LANGUAGES = ["vi", "en", "zh"] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];
export type Language = SupportedLanguage | "zh-CN" | (string & {});

/**
 * Normalises input language strings (e.g. 'zh-CN', 'en-US', 'vi') into 'vi' | 'en' | 'zh'.
 * Defaults to 'vi' for any unknown or unspecified locale.
 */
export function normalizeLanguage(lang?: Language | null): "vi" | "en" | "zh" {
  if (!lang) return "vi";
  const l = lang.toLowerCase().trim();
  if (l === "en" || l.startsWith("en-") || l.startsWith("en_")) return "en";
  if (l === "zh" || l.startsWith("zh-") || l.startsWith("zh_") || l === "cn") return "zh";
  return "vi";
}

/* ------------------------------------------------------------------ */
/* The exact string the spec demands for IP-only mode (§1.2)           */
/* ------------------------------------------------------------------ */

/** §1.2 — Leak / Speed must show exactly this when the user typed only an IP. */
export const NOT_MEASURED_PROXY = "Chưa đo được — cần nhập proxy";

export const LOCALIZED_NOT_MEASURED_PROXY: Record<"vi" | "en" | "zh", string> = {
  vi: NOT_MEASURED_PROXY,
  en: "Not measured — proxy required",
  zh: "未测量 — 需要输入代理",
};

export function getLocalizedNotMeasuredProxy(lang: Language = "vi"): string {
  const norm = normalizeLanguage(lang);
  return LOCALIZED_NOT_MEASURED_PROXY[norm] ?? NOT_MEASURED_PROXY;
}

/** Placeholder used wherever a value is genuinely absent (never "0"). */
export const DASH = "—";

/* ------------------------------------------------------------------ */
/* Verdict metadata (§3.1 colours, §3.3 five labels)                   */
/* ------------------------------------------------------------------ */

export type VerdictTone = "clean" | "temp" | "suspect" | "bad" | "unknown";

export interface VerdictMeta {
  verdict: Verdict;
  tone: VerdictTone;
  /** CSS class suffix used by chips / HUD / score boxes. */
  cls: string;
}

export const VERDICT_META: Record<Verdict, VerdictMeta> = {
  "Sạch": { verdict: "Sạch", tone: "clean", cls: "clean" },
  "Tạm": { verdict: "Tạm", tone: "temp", cls: "temp" },
  "Nghi ngờ": { verdict: "Nghi ngờ", tone: "suspect", cls: "suspect" },
  "Bẩn": { verdict: "Bẩn", tone: "bad", cls: "bad" },
  "Chưa đủ dữ liệu": { verdict: "Chưa đủ dữ liệu", tone: "unknown", cls: "unknown" },
};

export const ALL_VERDICTS: Verdict[] = ["Sạch", "Tạm", "Nghi ngờ", "Bẩn", "Chưa đủ dữ liệu"];

export const LOCALIZED_VERDICT_LABELS: Record<"vi" | "en" | "zh", Record<Verdict, string>> = {
  vi: {
    "Sạch": "Sạch",
    "Tạm": "Tạm",
    "Nghi ngờ": "Nghi ngờ",
    "Bẩn": "Bẩn",
    "Chưa đủ dữ liệu": "Chưa đủ dữ liệu",
  },
  en: {
    "Sạch": "Clean",
    "Tạm": "Fair",
    "Nghi ngờ": "Suspicious",
    "Bẩn": "Bad",
    "Chưa đủ dữ liệu": "Insufficient Data",
  },
  zh: {
    "Sạch": "纯净",
    "Tạm": "一般",
    "Nghi ngờ": "可疑",
    "Bẩn": "恶意",
    "Chưa đủ dữ liệu": "数据不足",
  },
};

export function resolveCanonicalVerdict(verdict: string | null | undefined): Verdict {
  if (!verdict) return "Chưa đủ dữ liệu";
  const trimmed = verdict.trim();
  if (trimmed === "Sạch" || trimmed.toLowerCase() === "clean" || trimmed === "纯净") return "Sạch";
  if (trimmed === "Tạm" || trimmed.toLowerCase() === "fair" || trimmed === "一般") return "Tạm";
  if (trimmed === "Nghi ngờ" || trimmed.toLowerCase() === "suspicious" || trimmed === "可疑") return "Nghi ngờ";
  if (trimmed === "Bẩn" || trimmed.toLowerCase() === "bad" || trimmed === "恶意") return "Bẩn";
  if (
    trimmed === "Chưa đủ dữ liệu" ||
    trimmed.toLowerCase() === "insufficient data" ||
    trimmed === "数据不足"
  ) {
    return "Chưa đủ dữ liệu";
  }
  const hit = ALL_VERDICTS.find((v) => v === trimmed);
  return hit ?? "Chưa đủ dữ liệu";
}

/** Normalises whatever the backend sent onto one of the five known labels. */
export function verdictMeta(verdict: string | null | undefined): VerdictMeta {
  if (!verdict) return VERDICT_META["Chưa đủ dữ liệu"];
  const hit = ALL_VERDICTS.find((v) => v === verdict);
  if (hit) return VERDICT_META[hit];
  const canonical = resolveCanonicalVerdict(verdict);
  return VERDICT_META[canonical];
}

export function getLocalizedVerdictMeta(
  verdict: string | null | undefined,
  lang: Language = "vi",
): VerdictMeta & { displayLabel: string } {
  const norm = normalizeLanguage(lang);
  const base = verdictMeta(verdict);
  const displayLabel =
    LOCALIZED_VERDICT_LABELS[norm]?.[base.verdict] ?? LOCALIZED_VERDICT_LABELS.vi[base.verdict];
  return {
    ...base,
    displayLabel,
  };
}

/** Score → tone, so the score box can be coloured without claiming a verdict. */
export function scoreTone(score: number | null | undefined): VerdictTone {
  if (score === null || score === undefined || Number.isNaN(score)) return "unknown";
  if (score >= 85) return "clean";
  if (score >= 65) return "temp";
  if (score >= 40) return "suspect";
  return "bad";
}

export function confidenceTone(confidence: number | null | undefined): VerdictTone {
  if (confidence === null || confidence === undefined) return "unknown";
  if (confidence >= 75) return "clean";
  if (confidence >= 50) return "temp";
  if (confidence >= 25) return "suspect";
  return "bad";
}

/* ------------------------------------------------------------------ */
/* Signal (§6.1)                                                       */
/* ------------------------------------------------------------------ */

export interface SignalMeta {
  label: string;
  cls: string;
  tone: VerdictTone;
}

export const SIGNAL_META: Record<Signal, SignalMeta> = {
  Clean: { label: "Sạch", cls: "clean", tone: "clean" },
  Suspicious: { label: "Nghi ngờ", cls: "suspect", tone: "suspect" },
  Bad: { label: "Bẩn", cls: "bad", tone: "bad" },
  Unknown: { label: "Không rõ", cls: "unknown", tone: "unknown" },
};

export const LOCALIZED_SIGNAL_LABELS: Record<"vi" | "en" | "zh", Record<Signal, string>> = {
  vi: {
    Clean: "Sạch",
    Suspicious: "Nghi ngờ",
    Bad: "Bẩn",
    Unknown: "Không rõ",
  },
  en: {
    Clean: "Clean",
    Suspicious: "Suspicious",
    Bad: "Bad",
    Unknown: "Unknown",
  },
  zh: {
    Clean: "纯净",
    Suspicious: "可疑",
    Bad: "恶意",
    Unknown: "未知",
  },
};

export function signalMeta(signal: Signal | null | undefined, lang: Language = "vi"): SignalMeta {
  if (lang === "vi") {
    return (signal && SIGNAL_META[signal]) || SIGNAL_META.Unknown;
  }
  return getLocalizedSignalMeta(signal, lang);
}

export function getLocalizedSignalMeta(
  signal: Signal | null | undefined,
  lang: Language = "vi",
): SignalMeta {
  const norm = normalizeLanguage(lang);
  const base = (signal && SIGNAL_META[signal]) || SIGNAL_META.Unknown;
  const key: Signal = signal && SIGNAL_META[signal] ? signal : "Unknown";
  const label = LOCALIZED_SIGNAL_LABELS[norm]?.[key] ?? LOCALIZED_SIGNAL_LABELS.vi[key];
  return {
    ...base,
    label,
  };
}

/* ------------------------------------------------------------------ */
/* Modules / statuses (§3.3)                                           */
/* ------------------------------------------------------------------ */

export const MODULE_LABELS: Record<ModuleId, string> = {
  validate: "Kiểm tra IP",
  geo: "Định vị",
  asn: "ASN",
  fraud: "Fraud",
  abuse: "Abuse",
  threat_intel: "Threat intel",
  dnsbl: "Blacklist",
  network: "Mạng",
  location: "Location engine",
  exit_ip: "IP thoát",
  leak: "Leak",
  speed: "Tốc độ",
  scoring: "Chấm điểm",
};

export const LOCALIZED_MODULE_LABELS: Record<"vi" | "en" | "zh", Record<ModuleId, string>> = {
  vi: MODULE_LABELS,
  en: {
    validate: "IP Validation",
    geo: "Geolocation",
    asn: "ASN",
    fraud: "Fraud",
    abuse: "Abuse",
    threat_intel: "Threat Intel",
    dnsbl: "Blacklist",
    network: "Network",
    location: "Location Engine",
    exit_ip: "Exit IP",
    leak: "Leak",
    speed: "Speed",
    scoring: "Scoring",
  },
  zh: {
    validate: "IP验证",
    geo: "地理位置",
    asn: "ASN",
    fraud: "欺诈检测",
    abuse: "滥用报告",
    threat_intel: "威胁情报",
    dnsbl: "黑名单",
    network: "网络",
    location: "定位引擎",
    exit_ip: "出口IP",
    leak: "泄漏检测",
    speed: "测速",
    scoring: "综合评分",
  },
};

export function getLocalizedModuleLabel(id: ModuleId, lang: Language = "vi"): string {
  const norm = normalizeLanguage(lang);
  return LOCALIZED_MODULE_LABELS[norm]?.[id] ?? MODULE_LABELS[id] ?? String(id);
}

/** Modules in the order the console lists them (§3.2 example order). */
export const MODULE_ORDER: ModuleId[] = [
  "validate",
  "geo",
  "asn",
  "fraud",
  "abuse",
  "threat_intel",
  "dnsbl",
  "network",
  "location",
  "exit_ip",
  "leak",
  "speed",
  "scoring",
];

export const STATUS_GLYPH: Record<ModuleStatus, string> = {
  pending: "·",
  running: "⟳",
  done: "✓",
  error: "!",
  skipped: "—",
};

export const STATUS_LABELS: Record<ModuleStatus, string> = {
  pending: "Chờ",
  running: "Đang chạy",
  done: "Xong",
  error: "Lỗi",
  skipped: "Bỏ qua",
};

export const LOCALIZED_STATUS_LABELS: Record<"vi" | "en" | "zh", Record<ModuleStatus, string>> = {
  vi: STATUS_LABELS,
  en: {
    pending: "Pending",
    running: "Running",
    done: "Done",
    error: "Error",
    skipped: "Skipped",
  },
  zh: {
    pending: "等待中",
    running: "运行中",
    done: "完成",
    error: "错误",
    skipped: "已跳过",
  },
};

export function getLocalizedStatusLabel(status: ModuleStatus, lang: Language = "vi"): string {
  const norm = normalizeLanguage(lang);
  return LOCALIZED_STATUS_LABELS[norm]?.[status] ?? STATUS_LABELS[status] ?? String(status);
}

/** §3.3 skip reasons, in Vietnamese. */
export const SKIP_REASON_LABELS: Record<SkipReason, string> = {
  missing_key: "thiếu API key",
  requires_proxy: "cần nhập proxy",
  quota_exhausted: "hết quota",
  disabled: "đã tắt trong Cài đặt",
  circuit_open: "provider tạm ngắt (lỗi liên tiếp)",
  not_implemented: "chưa hỗ trợ",
  unsupported_ip: "không áp dụng cho IP này",
};

export const LOCALIZED_SKIP_REASON_LABELS: Record<"vi" | "en" | "zh", Record<SkipReason, string>> = {
  vi: SKIP_REASON_LABELS,
  en: {
    missing_key: "Missing API key",
    requires_proxy: "Requires proxy",
    quota_exhausted: "Quota exhausted",
    disabled: "Disabled in settings",
    circuit_open: "Provider temporarily halted (consecutive errors)",
    not_implemented: "Not supported",
    unsupported_ip: "Not applicable to this IP",
  },
  zh: {
    missing_key: "缺少API密钥",
    requires_proxy: "需要代理",
    quota_exhausted: "配额耗尽",
    disabled: "已在设置中禁用",
    circuit_open: "服务商暂时熔断（连续错误）",
    not_implemented: "尚未支持",
    unsupported_ip: "不适用于此IP",
  },
};

export function getLocalizedSkipReasonLabel(
  reason: SkipReason | string | null | undefined,
  lang: Language = "vi",
): string {
  const norm = normalizeLanguage(lang);
  if (!reason) {
    return norm === "en" ? "Skipped" : norm === "zh" ? "已跳过" : "bỏ qua";
  }
  return (
    LOCALIZED_SKIP_REASON_LABELS[norm]?.[reason as SkipReason] ??
    SKIP_REASON_LABELS[reason as SkipReason] ??
    String(reason)
  );
}

export function skipReasonLabel(
  reason: SkipReason | string | null | undefined,
  lang: Language = "vi",
): string {
  return getLocalizedSkipReasonLabel(reason, lang);
}

/* ------------------------------------------------------------------ */
/* Categories / IP types / protocols                                   */
/* ------------------------------------------------------------------ */

export const CATEGORY_LABELS: Record<Category, string> = {
  geo: "Geo",
  asn: "ASN",
  fraud: "Fraud",
  abuse: "Abuse",
  threat_intel: "Threat intel",
  blacklist: "Blacklist",
  network: "Network",
  leak: "Leak",
  speed: "Speed",
  local_db: "Local DB",
};

export const LOCALIZED_CATEGORY_LABELS: Record<"vi" | "en" | "zh", Record<Category, string>> = {
  vi: CATEGORY_LABELS,
  en: {
    geo: "Geo",
    asn: "ASN",
    fraud: "Fraud",
    abuse: "Abuse",
    threat_intel: "Threat Intel",
    blacklist: "Blacklist",
    network: "Network",
    leak: "Leak",
    speed: "Speed",
    local_db: "Local DB",
  },
  zh: {
    geo: "地理位置",
    asn: "ASN",
    fraud: "欺诈检测",
    abuse: "滥用报告",
    threat_intel: "威胁情报",
    blacklist: "黑名单",
    network: "网络",
    leak: "泄漏检测",
    speed: "测速",
    local_db: "本地数据库",
  },
};

export function getLocalizedCategoryLabel(category: Category, lang: Language = "vi"): string {
  const norm = normalizeLanguage(lang);
  return (
    LOCALIZED_CATEGORY_LABELS[norm]?.[category] ??
    CATEGORY_LABELS[category] ??
    String(category)
  );
}

export const IP_TYPE_LABELS: Record<IpType, string> = {
  residential: "Residential",
  datacenter: "Datacenter / hosting",
  mobile: "Mobile",
  cgnat: "CGNAT",
  vpn: "VPN",
  tor: "Tor",
  proxy: "Proxy",
  anycast: "Anycast",
  edu: "Giáo dục / research",
  unknown: "Chưa xác định",
};

export const LOCALIZED_IP_TYPE_LABELS: Record<"vi" | "en" | "zh", Record<IpType, string>> = {
  vi: IP_TYPE_LABELS,
  en: {
    residential: "Residential",
    datacenter: "Datacenter / Hosting",
    mobile: "Mobile",
    cgnat: "CGNAT",
    vpn: "VPN",
    tor: "Tor",
    proxy: "Proxy",
    anycast: "Anycast",
    edu: "Education / Research",
    unknown: "Unknown",
  },
  zh: {
    residential: "住宅IP",
    datacenter: "数据中心 / 机房",
    mobile: "移动网络",
    cgnat: "CGNAT",
    vpn: "VPN",
    tor: "Tor",
    proxy: "代理",
    anycast: "Anycast任播",
    edu: "教育 / 科研",
    unknown: "未确定",
  },
};

export function getLocalizedIpTypeLabel(
  type: IpType | null | undefined,
  lang: Language = "vi",
): string {
  if (!type) return DASH;
  const norm = normalizeLanguage(lang);
  return LOCALIZED_IP_TYPE_LABELS[norm]?.[type] ?? IP_TYPE_LABELS[type] ?? String(type);
}

export function ipTypeLabel(type: IpType | null | undefined, lang: Language = "vi"): string {
  return getLocalizedIpTypeLabel(type, lang);
}

/** IP types whose city-level location is known to be unreliable (§7.5). */
export const UNRELIABLE_CITY_TYPES: IpType[] = ["mobile", "cgnat", "anycast", "vpn", "tor"];

export const PROTOCOL_LABELS: Record<ProxyProtocol, string> = {
  http: "HTTP",
  https: "HTTPS",
  socks5: "SOCKS5",
  socks4: "SOCKS4",
};

export function protocolLabel(protocol: ProxyProtocol | null | undefined): string {
  if (!protocol) return DASH;
  return PROTOCOL_LABELS[protocol] ?? String(protocol).toUpperCase();
}

export const DNSBL_GROUP_LABELS: Record<DnsblGroup, string> = {
  spamhaus: "Spamhaus",
  commercial: "Thương mại",
  community: "Cộng đồng",
  specialist: "Chuyên biệt",
};

export const LOCALIZED_DNSBL_GROUP_LABELS: Record<"vi" | "en" | "zh", Record<DnsblGroup, string>> = {
  vi: DNSBL_GROUP_LABELS,
  en: {
    spamhaus: "Spamhaus",
    commercial: "Commercial",
    community: "Community",
    specialist: "Specialist",
  },
  zh: {
    spamhaus: "Spamhaus",
    commercial: "商业级",
    community: "社区级",
    specialist: "专业级",
  },
};

export function getLocalizedDnsblGroupLabel(
  group: DnsblGroup | string | null | undefined,
  lang: Language = "vi",
): string {
  if (!group) return DASH;
  const norm = normalizeLanguage(lang);
  let key = String(group).toLowerCase().trim();
  if (key === "thương mại" || key === "thuong mai") key = "commercial";
  if (key === "cộng đồng" || key === "cong dong") key = "community";
  if (key === "chuyên biệt" || key === "chuyen biet") key = "specialist";
  return (
    LOCALIZED_DNSBL_GROUP_LABELS[norm]?.[key as DnsblGroup] ??
    DNSBL_GROUP_LABELS[key as DnsblGroup] ??
    String(group)
  );
}

export function dnsblGroupLabel(
  group: DnsblGroup | string | null | undefined,
  lang: Language = "vi",
): string {
  return getLocalizedDnsblGroupLabel(group, lang);
}

export const HEALTH_LABELS: Record<HealthState, string> = {
  green: "Tốt",
  yellow: "Chậm / lỗi tạm thời",
  red: "Lỗi",
  unknown: "Chưa rõ",
};

export const LOCALIZED_HEALTH_LABELS: Record<"vi" | "en" | "zh", Record<HealthState, string>> = {
  vi: HEALTH_LABELS,
  en: {
    green: "Good",
    yellow: "Degraded / Slow",
    red: "Down",
    unknown: "Unknown",
  },
  zh: {
    green: "正常",
    yellow: "缓慢 / 暂时异常",
    red: "故障",
    unknown: "未知",
  },
};

export function getLocalizedHealthLabel(state: HealthState, lang: Language = "vi"): string {
  const norm = normalizeLanguage(lang);
  return LOCALIZED_HEALTH_LABELS[norm]?.[state] ?? HEALTH_LABELS[state] ?? String(state);
}

/* ------------------------------------------------------------------ */
/* Network / provider error reasons (§3.3 "lý do nếu thiếu")           */
/* ------------------------------------------------------------------ */

export const ERROR_KIND_LABELS: Record<string, string> = {
  timeout: "timeout",
  http: "lỗi HTTP",
  parse: "dữ liệu không hợp lệ",
  auth: "sai / thiếu API key",
  no_key: "thiếu API key",
  quota: "hết quota",
  circuit_open: "provider tạm ngắt",
  network: "không có mạng",
  unsupported: "không hỗ trợ",
  invalid_input: "dữ liệu nhập sai",
  private_ip: "IP private / reserved",
  db: "lỗi database",
  io: "lỗi đọc/ghi file",
  internal: "lỗi nội bộ",
};

export const LOCALIZED_ERROR_KIND_LABELS: Record<"vi" | "en" | "zh", Record<string, string>> = {
  vi: ERROR_KIND_LABELS,
  en: {
    timeout: "timeout",
    http: "HTTP error",
    parse: "invalid data",
    auth: "invalid / missing API key",
    no_key: "missing API key",
    quota: "quota exhausted",
    circuit_open: "provider temporarily halted",
    network: "network error",
    unsupported: "unsupported",
    invalid_input: "invalid input",
    private_ip: "private / reserved IP",
    db: "database error",
    io: "file I/O error",
    internal: "internal error",
  },
  zh: {
    timeout: "请求超时",
    http: "HTTP错误",
    parse: "数据解析错误",
    auth: "API密钥错误 / 缺失",
    no_key: "缺少API密钥",
    quota: "配额耗尽",
    circuit_open: "服务商暂时熔断",
    network: "网络不可用",
    unsupported: "不支持",
    invalid_input: "输入数据无效",
    private_ip: "私有 / 保留IP",
    db: "数据库错误",
    io: "文件读写错误",
    internal: "内部错误",
  },
};

export function getLocalizedErrorKindLabel(
  kind: string | null | undefined,
  lang: Language = "vi",
): string {
  const norm = normalizeLanguage(lang);
  if (!kind) {
    return norm === "en" ? "unknown error" : norm === "zh" ? "未知错误" : "lỗi không rõ";
  }
  return LOCALIZED_ERROR_KIND_LABELS[norm]?.[kind] ?? ERROR_KIND_LABELS[kind] ?? String(kind);
}

export function errorKindLabel(kind: string | null | undefined, lang: Language = "vi"): string {
  return getLocalizedErrorKindLabel(kind, lang);
}

export function getLocalizedShortError(
  error: { kind?: string; message?: string | null; status?: number | null } | null | undefined,
  lang: Language = "vi",
): string {
  if (!error) return DASH;
  const kind = getLocalizedErrorKindLabel(error.kind, lang);
  const status = error.status ? ` ${error.status}` : "";
  return `${kind}${status}`;
}

/** Short "Lỗi: <lý do ngắn>" text for a provider row (§3.4). */
export function shortError(
  error: { kind?: string; message?: string | null; status?: number | null } | null | undefined,
  lang: Language = "vi",
): string {
  return getLocalizedShortError(error, lang);
}

/* ------------------------------------------------------------------ */
/* Number / value formatting (never fabricates a value)                 */
/* ------------------------------------------------------------------ */

export function fmtInt(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return String(Math.round(value));
}

export function fmtNum(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return value.toFixed(digits);
}

export function fmtPct(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return `${value.toFixed(digits)}%`;
}

export function fmtKm(value: number | null | undefined, lang: Language = "vi"): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  const norm = normalizeLanguage(lang);
  if (value >= 1000) {
    const k = (value / 1000).toFixed(1);
    return norm === "en" ? `${k}k km` : norm === "zh" ? `${k}千公里` : `${k} nghìn km`;
  }
  return `${value.toFixed(0)} km`;
}

export function fmtMs(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return `${value.toFixed(0)} ms`;
}

export function fmtMbps(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return `${value.toFixed(digits)} Mbps`;
}

export function fmtBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(0)} KB`;
  return `${value} B`;
}

/** ISO timestamp → "HH:MM DD/MM" (§3.3 cache wording). */
export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  return `${hh}:${mm} ${dd}/${mo}`;
}

/** ISO date → "DD/MM/YYYY" for DB versions (§7.3, §11). */
export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  return `${dd}/${mo}/${d.getFullYear()}`;
}

export function getLocalizedCacheNote(
  checkedAt: string | null | undefined,
  lang: Language = "vi",
): string {
  const norm = normalizeLanguage(lang);
  if (!checkedAt) {
    return norm === "en" ? "from cache" : norm === "zh" ? "来自缓存" : "từ cache";
  }
  const time = fmtTime(checkedAt);
  if (norm === "en") return `from cache, checked at ${time}`;
  if (norm === "zh") return `来自缓存，检测于 ${time}`;
  return `từ cache, check lúc ${time}`;
}

/** §3.4: "từ cache, check lúc HH:MM DD/MM". */
export function cacheNote(checkedAt: string | null | undefined, lang: Language = "vi"): string {
  return getLocalizedCacheNote(checkedAt, lang);
}

export function valueOrDash(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return DASH;
  const s = String(value).trim();
  return s.length === 0 ? DASH : s;
}

export function getLocalizedYesNo(
  value: boolean | null | undefined,
  lang: Language = "vi",
  unknownLabel = DASH,
): string {
  if (value === null || value === undefined) return unknownLabel;
  const norm = normalizeLanguage(lang);
  if (norm === "en") return value ? "Yes" : "No";
  if (norm === "zh") return value ? "是" : "否";
  return value ? "Có" : "Không";
}

/** Yes/no with localized support (default 'vi') and neutral dash for null/undefined. */
export function yesNo(
  value: boolean | null | undefined,
  langOrUnknownLabel?: Language | string,
  unknownLabel = DASH,
): string {
  let lang: Language = "vi";
  let fallback = unknownLabel;

  if (langOrUnknownLabel !== undefined) {
    const l = langOrUnknownLabel.toLowerCase().trim();
    if (
      l === "vi" ||
      l === "en" ||
      l === "zh" ||
      l.startsWith("en-") ||
      l.startsWith("zh-") ||
      l.startsWith("en_") ||
      l.startsWith("zh_") ||
      l === "cn"
    ) {
      lang = langOrUnknownLabel as Language;
    } else {
      fallback = langOrUnknownLabel;
    }
  }

  return getLocalizedYesNo(value, lang, fallback);
}

/* ------------------------------------------------------------------ */
/* Colours for the map (§3.3 multi-source colours)                     */
/* ------------------------------------------------------------------ */

const MAP_SOURCE_VARS = [
  "var(--map-src-1)",
  "var(--map-src-2)",
  "var(--map-src-3)",
  "var(--map-src-4)",
  "var(--map-src-5)",
  "var(--map-src-6)",
  "var(--map-src-7)",
];

export const CENTROID_COLOR = "var(--map-centroid)";

/** Stable colour per source: the same source keeps its colour across renders. */
export function srcColor(index: number): string {
  return MAP_SOURCE_VARS[index % MAP_SOURCE_VARS.length];
}

/** Alias kept for call sites that spell the intent out. */
export const sourceColorVar = srcColor;

/* ------------------------------------------------------------------ */
/* Location spread (§7.3)                                              */
/* ------------------------------------------------------------------ */

export interface SpreadMeta {
  label: string;
  tone: VerdictTone;
  /** 50 km → high, 50–200 km → medium, > 200 km → low, disagreement → disputed. */
  explanation: string;
}

export const SPREAD_META: Record<string, SpreadMeta> = {
  high: {
    label: "Nguồn chụm < 50 km",
    tone: "clean",
    explanation: "Các nguồn chụm trong 50 km — thành phố tin cậy cao (§7.3).",
  },
  medium: {
    label: "Nguồn lệch 50–200 km",
    tone: "temp",
    explanation: "Các nguồn lệch 50–200 km — thành phố chỉ nên tham khảo (§7.3).",
  },
  low: {
    label: "Nguồn lệch > 200 km",
    tone: "bad",
    explanation: "Các nguồn lệch hơn 200 km — không chốt thành phố, chỉ chốt quốc gia/vùng (§7.3).",
  },
  disputed: {
    label: "Tranh chấp",
    tone: "bad",
    explanation: "Các nguồn tranh chấp nhau — không chốt được thành phố (§7.3).",
  },
};

export const LOCALIZED_SPREAD_META: Record<"vi" | "en" | "zh", Record<string, SpreadMeta>> = {
  vi: SPREAD_META,
  en: {
    high: {
      label: "Sources converged < 50 km",
      tone: "clean",
      explanation: "Sources converge within 50 km — high city confidence (§7.3).",
    },
    medium: {
      label: "Sources deviate 50–200 km",
      tone: "temp",
      explanation: "Sources deviate by 50–200 km — city for reference only (§7.3).",
    },
    low: {
      label: "Sources deviate > 200 km",
      tone: "bad",
      explanation: "Sources deviate by > 200 km — country/region resolved, city unresolved (§7.3).",
    },
    disputed: {
      label: "Disputed",
      tone: "bad",
      explanation: "Sources dispute location — unable to resolve city (§7.3).",
    },
  },
  zh: {
    high: {
      label: "数据源聚合 < 50 km",
      tone: "clean",
      explanation: "各数据源误差在50 km以内 — 城市定位高度可信（§7.3）。",
    },
    medium: {
      label: "数据源偏差 50–200 km",
      tone: "temp",
      explanation: "各数据源偏差50–200 km — 城市仅供参考（§7.3）。",
    },
    low: {
      label: "数据源偏差 > 200 km",
      tone: "bad",
      explanation: "各数据源偏差超过200 km — 仅确认国家/地区，无法锁定城市（§7.3）。",
    },
    disputed: {
      label: "数据源冲突",
      tone: "bad",
      explanation: "各数据源存在争议冲突 — 无法确定城市（§7.3）。",
    },
  },
};

export function getLocalizedSpreadMeta(
  spread: string | null | undefined,
  lang: Language = "vi",
): SpreadMeta | null {
  if (!spread) return null;
  const norm = normalizeLanguage(lang);
  const key = spread.toLowerCase();
  const dict = LOCALIZED_SPREAD_META[norm] ?? LOCALIZED_SPREAD_META.vi;
  return dict[key] ?? { label: spread, tone: "unknown", explanation: "" };
}

/** Maps the backend `spread` string onto a readable Vietnamese badge. */
export function spreadLabel(
  spread: string | null | undefined,
  lang: Language = "vi",
): SpreadMeta | null {
  return getLocalizedSpreadMeta(spread, lang);
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

/** Two decimal places, used for lat/lon everywhere. */
export function fmtCoord(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return value.toFixed(2);
}

export function pluralize(count: number, unit: string): string {
  return `${count} ${unit}`;
}

/** Truncate a long provider message for a table cell. */
export function clampText(text: string | null | undefined, max = 120): string {
  if (!text) return DASH;
  const s = String(text).replace(/\s+/g, " ").trim();
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

/** Small class joiner, so components do not concatenate strings by hand. */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/* ------------------------------------------------------------------ */
/* Dynamic Message Localizers (§i18n)                                  */
/* ------------------------------------------------------------------ */

export interface ParsedInputLike {
  kind: string;
  ip?: string | null;
  port?: number | null;
  message?: string;
  isPublic?: boolean;
  reservedReason?: string | null;
}

export function getLocalizedInputMessage(
  parsed: ParsedInputLike,
  lang: Language = "vi",
): string {
  const norm = normalizeLanguage(lang);
  const msg = parsed.message ?? "";

  if (norm === "vi") {
    return msg.length > 0 ? msg : "Nhập IP công khai (ví dụ 8.8.8.8) hoặc IP:port của proxy.";
  }

  if (parsed.kind === "empty") {
    return norm === "en"
      ? "Enter a public IP (e.g. 8.8.8.8) or IP:port for proxy check."
      : "请输入公网 IP（例如 8.8.8.8）或代理 IP:端口。";
  }

  if (parsed.kind === "invalid") {
    if (msg.includes("quá dài")) {
      return norm === "en" ? "Input is too long." : "输入内容过长。";
    }
    if (msg.includes("trước dấu hai chấm")) {
      return norm === "en" ? "Missing IP address before colon." : "冒号前缺少 IP 地址。";
    }
    if (msg.includes("sau dấu hai chấm")) {
      return norm === "en" ? "Missing port number after colon." : "冒号后缺少端口号。";
    }
    if (msg.includes("Port phải là số")) {
      return norm === "en" ? "Port must be a number (1–65535)." : "端口必须为数字（1–65535）。";
    }
    if (msg.includes("Port phải trong khoảng")) {
      return norm === "en" ? "Port must be in range 1–65535." : "端口范围必须为 1–65535。";
    }
    return norm === "en"
      ? "Not a valid IPv4 or IPv6 address. E.g.: 8.8.8.8 or 1.2.3.4:8080"
      : "无效的 IPv4 或 IPv6 地址。例如：8.8.8.8 或 1.2.3.4:8080";
  }

  const rawReason = parsed.reservedReason ?? "";
  let reasonEn = "reserved / private";
  let reasonZh = "私有 / 保留";

  if (/loopback/i.test(rawReason)) {
    reasonEn = "loopback";
    reasonZh = "环回地址 (127.0.0.0/8)";
  } else if (/cgnat/i.test(rawReason)) {
    reasonEn = "CGNAT (RFC6598)";
    reasonZh = "运营商级 NAT (RFC6598)";
  } else if (/private/i.test(rawReason)) {
    reasonEn = "private (RFC1918)";
    reasonZh = "私有网络 (RFC1918)";
  } else if (/link-local/i.test(rawReason)) {
    reasonEn = "link-local";
    reasonZh = "链路本地";
  } else if (/multicast/i.test(rawReason)) {
    reasonEn = "multicast";
    reasonZh = "组播地址";
  } else if (/broadcast/i.test(rawReason)) {
    reasonEn = "broadcast";
    reasonZh = "广播地址";
  } else if (/tài liệu/i.test(rawReason)) {
    reasonEn = "documentation (TEST-NET)";
    reasonZh = "测试/文档专用 (TEST-NET)";
  }

  if (parsed.isPublic === false) {
    if (parsed.port !== null && parsed.port !== undefined) {
      return norm === "en"
        ? `Cannot dial ${parsed.ip}:${parsed.port} (${reasonEn}) — use a unicast address.`
        : `无法连接到 ${parsed.ip}:${parsed.port} (${reasonZh}) — 请使用单播地址。`;
    }
    return norm === "en"
      ? `IP ${reasonEn} — cannot check. Public IP required.`
      : `IP ${reasonZh} — 无法检测。需要公网 IP。`;
  }

  if (parsed.kind === "proxy" || (parsed.port !== null && parsed.port !== undefined)) {
    return norm === "en"
      ? `Proxy check: ${parsed.ip}:${parsed.port} — will test exit IP, leak, and speed.`
      : `代理检测：${parsed.ip}:${parsed.port} — 将检测出口IP、泄漏与测速。`;
  }

  // default ip_only public
  return norm === "en"
    ? "IP-only: check geo, ASN, fraud, blacklist, network. Leak and speed require proxy."
    : "纯 IP 检测：检测地理位置、ASN、欺诈风险、黑名单、网络。泄漏与测速需代理。";
}

export function getLocalizedProgressMessage(
  message: string | null | undefined,
  lang: Language = "vi",
): string {
  if (!message) return "";
  const norm = normalizeLanguage(lang);
  if (norm === "vi") return message;

  const m = message.trim();

  // 1. Validation
  if (m === "Input hợp lệ") {
    return norm === "en" ? "Valid input" : "输入有效";
  }
  if (m === "Không chạy: input không hợp lệ") {
    return norm === "en" ? "Skipped: invalid input" : "未运行：输入无效";
  }

  // 2. Exit IP
  if (m === "Đang xác định IP thoát") {
    return norm === "en" ? "Detecting exit IP" : "正在检测出口 IP";
  }
  const exitIpMatch = /^IP thoát:\s*(.*)$/.exec(m);
  if (exitIpMatch) {
    return norm === "en" ? `Exit IP: ${exitIpMatch[1]}` : `出口 IP: ${exitIpMatch[1]}`;
  }
  if (m.includes("Chưa xác định được IP thoát — không kết luận")) {
    return norm === "en" ? "Exit IP not determined — no verdict (§1.2)" : "未确定出口 IP — 无结论 (§1.2)";
  }
  const timeoutExitMatch = /^Hết thời gian chờ\s+(\d+)s\s+khi xác định IP thoát/i.exec(m);
  if (timeoutExitMatch) {
    return norm === "en"
      ? `Timed out after ${timeoutExitMatch[1]}s detecting exit IP via proxy — no verdict (§1.2)`
      : `通过代理确定出口 IP 超时 ${timeoutExitMatch[1]} 秒 — 无结论 (§1.2)`;
  }

  // 3. Running modules
  if (m === "Đang hỏi các nguồn geo") {
    return norm === "en" ? "Querying geo sources" : "正在查询地理位置数据源";
  }
  if (m === "Đang hỏi nguồn ASN") {
    return norm === "en" ? "Querying ASN sources" : "正在查询 ASN 数据源";
  }
  if (m === "Đang hỏi nguồn fraud score") {
    return norm === "en" ? "Querying fraud score sources" : "正在查询欺诈风险评分源";
  }
  if (m === "Đang hỏi nguồn abuse history") {
    return norm === "en" ? "Querying abuse history sources" : "正在查询滥用历史数据源";
  }
  if (m === "Đang hỏi threat intel") {
    return norm === "en" ? "Querying threat intel sources" : "正在查询威胁情报源";
  }
  if (m === "Đang tra DNSBL") {
    return norm === "en" ? "Querying DNSBL blacklists" : "正在查询 DNSBL 黑名单";
  }
  if (m === "Đang tam giác vị trí") {
    return norm === "en" ? "Triangulating location" : "正在三角校准地理位置";
  }
  if (m === "Đang đo mạng") {
    return norm === "en" ? "Testing network" : "正在测试网络连接";
  }
  if (m === "Đang kiểm leak trình duyệt") {
    return norm === "en" ? "Testing browser leaks" : "正在检测浏览器泄漏";
  }
  if (m === "Đang đo tốc độ") {
    return norm === "en" ? "Measuring speed" : "正在测速";
  }
  if (m === "Đang tổng hợp điểm") {
    return norm === "en" ? "Calculating scores" : "正在汇总评分";
  }

  // 4. Answered counts
  const geoAnsMatch = /^(\d+)\s+nguồn geo trả lời$/i.exec(m);
  if (geoAnsMatch) {
    return norm === "en" ? `${geoAnsMatch[1]} geo source(s) responded` : `${geoAnsMatch[1]} 个地理位置源已响应`;
  }
  if (m === "Không nguồn geo nào trả lời") {
    return norm === "en" ? "No geo sources responded" : "无地理位置数据源响应";
  }

  const fraudAnsMatch = /^(\d+)\s+nguồn fraud trả lời$/i.exec(m);
  if (fraudAnsMatch) {
    return norm === "en" ? `${fraudAnsMatch[1]} fraud source(s) responded` : `${fraudAnsMatch[1]} 个欺诈检测源已响应`;
  }
  if (m === "Không nguồn fraud nào trả lời") {
    return norm === "en" ? "No fraud sources responded" : "无欺诈检测源响应";
  }

  const abuseAnsMatch = /^(\d+)\s+nguồn abuse trả lời$/i.exec(m);
  if (abuseAnsMatch) {
    return norm === "en" ? `${abuseAnsMatch[1]} abuse source(s) responded` : `${abuseAnsMatch[1]} 个滥用检测源已响应`;
  }
  if (m.includes("Không nguồn abuse nào trả lời")) {
    return norm === "en" ? "No abuse sources responded (missing key or disconnected)" : "无滥用检测源响应（缺少密钥或已断开）";
  }

  const threatAnsMatch = /^(\d+)\s+nguồn threat intel trả lời$/i.exec(m);
  if (threatAnsMatch) {
    return norm === "en" ? `${threatAnsMatch[1]} threat intel source(s) responded` : `${threatAnsMatch[1]} 个威胁情报源已响应`;
  }
  if (m === "Không nguồn threat intel nào trả lời") {
    return norm === "en" ? "No threat intel sources responded" : "无威胁情报源响应";
  }

  // 5. ASN consensus
  if (m === "Đủ 2 nguồn đồng ý về ASN") {
    return norm === "en" ? "2 sources agree on ASN" : "已有 2 个源对 ASN 达成一致";
  }
  if (m === "Chưa đủ 2 nguồn đồng ý về ASN") {
    return norm === "en" ? "Fewer than 2 sources agree on ASN" : "未达到 2 个源对 ASN 达成一致";
  }

  // 6. DNSBL
  const dnsblAnsMatch = /^(\d+)\s+nhóm trả lời,\s*(\d+)\s+zone listed$/i.exec(m);
  if (dnsblAnsMatch) {
    return norm === "en"
      ? `${dnsblAnsMatch[1]} group(s) responded, ${dnsblAnsMatch[2]} zone(s) listed`
      : `${dnsblAnsMatch[1]} 个分组已响应，${dnsblAnsMatch[2]} 项名单命中`;
  }
  if (m.includes("Không nhóm DNSBL nào trả lời")) {
    return norm === "en" ? "No DNSBL groups responded — blacklist inconclusive" : "无 DNSBL 分组响应 — 黑名单无结论";
  }
  if (m === "DNSBL bị tắt trong Settings") {
    return norm === "en" ? "DNSBL disabled in Settings" : "DNSBL 在设置中已禁用";
  }

  // 7. Location spread
  const spreadMatch = /^Độ tụ\s+(.+?)\s*\|\s*(.*)$/i.exec(m);
  if (spreadMatch) {
    let spread = spreadMatch[1].trim();
    if (spread === "chặt") spread = norm === "en" ? "tight" : "精确";
    else if (spread === "ổn") spread = norm === "en" ? "moderate" : "良好";
    else if (spread === "rộng") spread = norm === "en" ? "wide" : "离散";
    else if (spread === "rất rộng") spread = norm === "en" ? "very wide" : "高度离散";
    else if (spread === "chưa rõ") spread = norm === "en" ? "unclear" : "未知";

    let loc = spreadMatch[2].trim();
    if (loc === "chưa xác định") loc = norm === "en" ? "unresolved" : "未确定";

    return norm === "en" ? `Spread: ${spread} | ${loc}` : `收敛度: ${spread} | ${loc}`;
  }

  // 8. Network ping/ptr
  const netMatch = /^Ping\s+(.+?)\s*\|\s*PTR\s+(.*)$/i.exec(m);
  if (netMatch) {
    let ptr = netMatch[2].trim();
    if (ptr === "không có") ptr = norm === "en" ? "none" : "无";
    return `Ping ${netMatch[1]} | PTR ${ptr}`;
  }

  // 9. Skipped proxy reasons
  if (m.includes("chưa xác định được IP thoát qua proxy")) {
    return norm === "en" ? "Skipped: exit IP not determined via proxy (§8.1)" : "未运行：未能通过代理确定出口 IP (§8.1)";
  }
  if (m === "Chưa đo được — cần nhập proxy") {
    return norm === "en" ? "Not measured — proxy required" : "未检测 — 需要代理";
  }

  // 10. Leak & Speed
  if (m === "Đã đo leak") {
    return norm === "en" ? "Leak test complete" : "泄漏检测完成";
  }
  if (m === "Người dùng tắt kiểm leak") {
    return norm === "en" ? "Leak test disabled by user" : "用户已禁用泄漏检测";
  }
  if (m.includes("Chưa đo được — cần trình duyệt")) {
    return norm === "en" ? "Not measured — browser required (§1.2)" : "未检测 — 需要浏览器 (§1.2)";
  }
  if (m === "Đã đo tốc độ") {
    return norm === "en" ? "Speed test complete" : "测速完成";
  }
  if (m === "Người dùng tắt đo tốc độ") {
    return norm === "en" ? "Speed test disabled by user" : "用户已禁用测速";
  }
  if (m.includes("Chưa đo được tốc độ")) {
    return norm === "en" ? "Speed not measured (§1.2)" : "测速未完成 (§1.2)";
  }

  // 11. Scoring conclusion
  const scoreMatch = /^(.+?)\s*\(Clean\s*([^,]+),\s*Confidence\s*([^)]+)\)$/i.exec(m);
  if (scoreMatch) {
    const rawVerdict = scoreMatch[1].trim();
    const cleanVal = scoreMatch[2].trim();
    const confVal = scoreMatch[3].trim();
    const localizedVerdict = getLocalizedVerdictMeta(rawVerdict as any, norm).displayLabel;
    return norm === "en"
      ? `${localizedVerdict} (Clean ${cleanVal}, Confidence ${confVal})`
      : `${localizedVerdict} (纯净度 ${cleanVal}, 置信度 ${confVal})`;
  }

  return m;
}

export function getLocalizedAspectLabel(
  aspect: string | null | undefined,
  lang: Language = "vi",
): string {
  if (!aspect) return DASH;
  const norm = normalizeLanguage(lang);
  const a = aspect.toLowerCase().trim();
  if (norm === "en") {
    switch (a) {
      case "country": return "Country";
      case "asn": return "ASN";
      case "ip_type": return "IP Type";
      case "fraud": return "Fraud";
      case "threat":
      case "threat_intel": return "Threat Intel";
      case "dnsbl":
      case "blacklist": return "Blacklist";
      case "leak": return "Leak";
      case "speed": return "Speed";
      case "geo": return "Geo";
      default: return aspect;
    }
  }
  if (norm === "zh") {
    switch (a) {
      case "country": return "国家";
      case "asn": return "ASN";
      case "ip_type": return "IP类型";
      case "fraud": return "欺诈检测";
      case "threat":
      case "threat_intel": return "威胁情报";
      case "dnsbl":
      case "blacklist": return "黑名单";
      case "leak": return "泄漏检测";
      case "speed": return "测速";
      case "geo": return "地理位置";
      default: return aspect;
    }
  }
  switch (a) {
    case "country": return "Quốc gia";
    case "asn": return "ASN";
    case "ip_type": return "Loại IP";
    case "fraud": return "Fraud";
    case "threat":
    case "threat_intel": return "Threat intel";
    case "dnsbl":
    case "blacklist": return "Blacklist";
    case "leak": return "Leak";
    case "speed": return "Tốc độ";
    case "geo": return "Geo";
    default: return aspect;
  }
}

export function getLocalizedVerdictReason(
  reason: string | null | undefined,
  lang: Language = "vi",
): string {
  if (!reason) return "";
  const norm = normalizeLanguage(lang);
  if (norm === "vi") return reason;

  let r = reason;

  if (norm === "en") {
    r = r
      // Exact full verdicts
      .replace(/Đủ quorum, các nguồn đồng thuận sạch, không dính blacklist\./gi, "Quorum met, sources agree clean, not listed on blacklists.")
      .replace(/Đủ quorum, có xung đột nhẹ hoặc 1 DNSBL cộng đồng\./gi, "Quorum met, minor conflict or 1 community DNSBL.")
      .replace(/Đồng thuận đa nguồn báo bẩn \/ dính nhiều nhóm blacklist\./gi, "Multi-source consensus reports bad / multiple blacklist groups matched.")
      .replace(/Clean Score\s*(\d+(?:\.\d+)?)\s*nằm trong dải\s*40[-—–]64\s*\(§6\.5\)\./gi, "Clean Score $1 in 40–64 range (§6.5).")
      .replace(/Không đủ nguồn geo\/ASN\/blacklist để kết luận sạch\./gi, "Insufficient geo/ASN/blacklist sources to conclude clean.")
      // Single hits & conflicts
      .replace(/Có nguồn báo bẩn trong khi phần còn lại sạch\s*[-—–]\s*không kết luận sạch\s*\(§6\.5\)\.?/gi, "Some sources report bad while others are clean — cannot conclude clean (§6.5). ")
      .replace(/Bằng chứng đơn lẻ mạnh \(Spamhaus\/Tor\) chưa có nguồn thứ hai xác nhận\s*[-—–]\s*verdict tối đa Nghi ngờ\s*\(§6\.5\)\.?/gi, "Strong single evidence (Spamhaus/Tor) without secondary confirmation — max verdict Suspicious (§6.5). ")
      .replace(/Dính blacklist nghiêm trọng đã được xác nhận\.?/gi, "Confirmed severe blacklist listing. ")
      .replace(/Dính blacklist ở\s*[≥>=]+\s*2\s*nhóm\s*[-—–]\s*không thể Sạch\.?/gi, "Listed in ≥2 blacklist groups — cannot be Clean. ")
      .replace(/Nhiều nguồn độc lập cùng báo bẩn\s*\(§6\.5\)\.?/gi, "Multiple independent sources report bad (§6.5). ")
      .replace(/Các nguồn không hoàn toàn đồng thuận\.?/gi, "Sources are not in full consensus. ")
      .replace(/Chỉ 1 nguồn \(([^)]+)\) báo bẩn trong khi các nguồn khác sạch\s*[-—–]\s*chưa đủ để kết luận Bẩn, nhưng không thể coi là Tạm\s*\(§6\.5\)\.?/gi, "Only 1 source ($1) reports bad while others are clean — insufficient to conclude Bad, but cannot be considered Fair (§6.5). ")
      .replace(/Clean Score\s*<\s*40\s*\(§6\.5\)\.?/gi, "Clean Score < 40 (§6.5). ")
      .replace(/\s*Nguồn lệch:\s*([^.]+)\./gi, " Dissenting sources: $1.")
      // Quorum & data checks
      .replace(/Chưa đủ dữ liệu:\s*thiếu quorum ở\s*(.+?)\s*[-—–]\s*không được kết luận/gi, "Insufficient data: missing quorum in $1 — no conclusion allowed")
      .replace(/Chưa đủ dữ liệu:\s*không có phiếu nào dùng được/gi, "Insufficient data: no usable votes")
      .replace(/Verdict bị chặn bởi quorum thiếu:\s*(.+?)(?=\.|$|\s*\(§6\.3\))/gi, "Verdict blocked due to missing quorum: $1 (§6.3)")
      .replace(/Thiếu quorum:\s*(\d+)\/(\d+)\s*phiếu\s*[-—–]\s*không được kết luận\s*\(§6\.3\)/gi, "Missing quorum: $1/$2 votes — no conclusion allowed (§6.3)")
      .replace(/Đủ quorum tối thiểu\s*\((\d+)\/(\d+)\),\s*còn thiếu nguồn phụ/gi, "Minimum quorum met ($1/$2), secondary sources missing")
      .replace(/Đủ quorum\s*\((\d+)\/(\d+)\)/gi, "Quorum met ($1/$2)")
      // Conflict messages
      .replace(/(\d+)\s+nguồn báo bẩn\s*\/\s*(\d+)\s+nguồn báo sạch(?:\s+trong khía cạnh|\s+khía cạnh)?\s+([a-zA-Z0-9_-]+)/gi, "$1 source(s) report bad / $2 source(s) report clean in $3")
      .replace(/Khía cạnh\s+([a-zA-Z0-9_-]+)\s+trộn lẫn nghi ngờ và sạch/gi, "Aspect $1 mixes suspicious and clean signals")
      // Legacy / score ranges
      .replace(/Điểm Clean nằm trong khoảng Nghi ngờ \(25-69\)\./gi, "Clean score falls in Suspicious range (25-69).")
      .replace(/Điểm Clean nằm trong khoảng Tạm \(70-84\)\./gi, "Clean score falls in Fair range (70-84).")
      .replace(/Điểm Clean sạch \(>=85\)\./gi, "Clean score is clean (>=85).")
      .replace(/Điểm Clean thấp \(<25\) nhưng chưa đủ đồng thuận để kết luận Bẩn\./gi, "Clean score is low (<25) but consensus is insufficient to conclude Bad.")
      .replace(/Quorum thiếu:\s*(.+?)(?=\.|$)/gi, "Missing quorum: $1")
      // Terms
      .replace(/khía cạnh bắt buộc/gi, "mandatory aspects")
      .replace(/Chưa đủ dữ liệu/gi, "Insufficient data")
      .replace(/Nghi ngờ/gi, "Suspicious")
      .replace(/Tạm/gi, "Fair")
      .replace(/Bẩn/gi, "Bad")
      .replace(/Sạch/gi, "Clean");
    return r.trim();
  }

  if (norm === "zh") {
    r = r
      // Exact full verdicts
      .replace(/Đủ quorum, các nguồn đồng thuận sạch, không dính blacklist\./gi, "达到法定数量，多源一致纯净，未列入黑名单。")
      .replace(/Đủ quorum, có xung đột nhẹ hoặc 1 DNSBL cộng đồng\./gi, "达到法定数量，存在轻微冲突或命中 1 个社区 DNSBL。")
      .replace(/Đồng thuận đa nguồn báo bẩn \/ dính nhiều nhóm blacklist\./gi, "多源共识判定恶意 / 命中多个黑名单分组。")
      .replace(/Clean Score\s*(\d+(?:\.\d+)?)\s*nằm trong dải\s*40[-—–]64\s*\(§6\.5\)\./gi, "纯净度得分 $1 处于 40–64 区间 (§6.5)。")
      .replace(/Không đủ nguồn geo\/ASN\/blacklist để kết luận sạch\./gi, "地理位置/ASN/黑名单数据源不足，无法得出纯净结论。")
      // Single hits & conflicts
      .replace(/Có nguồn báo bẩn trong khi phần còn lại sạch\s*[-—–]\s*không kết luận sạch\s*\(§6\.5\)\.?/gi, "部分源报告恶意而其余源纯净 — 无法得出纯净结论 (§6.5)。")
      .replace(/Bằng chứng đơn lẻ mạnh \(Spamhaus\/Tor\) chưa có nguồn thứ hai xác nhận\s*[-—–]\s*verdict tối đa Nghi ngờ\s*\(§6\.5\)\.?/gi, "存在强单点证据 (Spamhaus/Tor) 但无第二源确认 — 最高判定为可疑 (§6.5)。")
      .replace(/Dính blacklist nghiêm trọng đã được xác nhận\.?/gi, "已确认命中严重黑名单。")
      .replace(/Dính blacklist ở\s*[≥>=]+\s*2\s*nhóm\s*[-—–]\s*không thể Sạch\.?/gi, "命中 ≥2 个黑名单分组 — 无法判定为纯净。")
      .replace(/Nhiều nguồn độc lập cùng báo bẩn\s*\(§6\.5\)\.?/gi, "多个独立数据源共同报告恶意 (§6.5)。")
      .replace(/Các nguồn không hoàn toàn đồng thuận\.?/gi, "各数据源未完全达成一致。")
      .replace(/Chỉ 1 nguồn \(([^)]+)\) báo bẩn trong khi các nguồn khác sạch\s*[-—–]\s*chưa đủ để kết luận Bẩn, nhưng không thể coi là Tạm\s*\(§6\.5\)\.?/gi, "仅 1 个源 ($1) 报告恶意而其他源纯净 — 不足以判定为恶意，但不能视为一般 (§6.5)。")
      .replace(/Clean Score\s*<\s*40\s*\(§6\.5\)\.?/gi, "纯净度得分 < 40 (§6.5)。")
      .replace(/\s*Nguồn lệch:\s*([^.]+)\./gi, " 偏差数据源: $1。")
      // Quorum & data checks
      .replace(/Chưa đủ dữ liệu:\s*thiếu quorum ở\s*(.+?)\s*[-—–]\s*không được kết luận/gi, "数据不足：缺少 $1 法定数据源 — 无法得出结论")
      .replace(/Chưa đủ dữ liệu:\s*không có phiếu nào dùng được/gi, "数据不足：无可用评估数据")
      .replace(/Verdict bị chặn bởi quorum thiếu:\s*(.+?)(?=\.|$|\s*\(§6\.3\))/gi, "判定因缺少法定数据源受阻: $1 (§6.3)")
      .replace(/Thiếu quorum:\s*(\d+)\/(\d+)\s*phiếu\s*[-—–]\s*không được kết luận\s*\(§6\.3\)/gi, "缺少法定数量: $1/$2 票 — 无法得出结论 (§6.3)")
      .replace(/Đủ quorum tối thiểu\s*\((\d+)\/(\d+)\),\s*còn thiếu nguồn phụ/gi, "达到最低法定数量 ($1/$2)，缺少辅助数据源")
      .replace(/Đủ quorum\s*\((\d+)\/(\d+)\)/gi, "达到法定数量 ($1/$2)")
      // Conflict messages
      .replace(/(\d+)\s+nguồn báo bẩn\s*\/\s*(\d+)\s+nguồn báo sạch(?:\s+trong khía cạnh|\s+khía cạnh)?\s+([a-zA-Z0-9_-]+)/gi, "$1 个源报告恶意 / $2 个源报告纯净（在 $3 方面）")
      .replace(/Khía cạnh\s+([a-zA-Z0-9_-]+)\s+trộn lẫn nghi ngờ và sạch/gi, "维度 $1 混合了可疑与纯净信号")
      // Legacy / score ranges
      .replace(/Điểm Clean nằm trong khoảng Nghi ngờ \(25-69\)\./gi, "纯净度得分处于可疑区间 (25-69)。")
      .replace(/Điểm Clean nằm trong khoảng Tạm \(70-84\)\./gi, "纯净度得分处于一般区间 (70-84)。")
      .replace(/Điểm Clean sạch \(>=85\)\./gi, "纯净度得分纯净 (>=85)。")
      .replace(/Điểm Clean thấp \(<25\) nhưng chưa đủ đồng thuận để kết luận Bẩn\./gi, "纯净度得分低 (<25) 但尚未形成共识判定为恶意。")
      .replace(/Quorum thiếu:\s*(.+?)(?=\.|$)/gi, "缺少法定数据源: $1")
      // Terms
      .replace(/khía cạnh bắt buộc/gi, "必填评估维度")
      .replace(/Chưa đủ dữ liệu/gi, "数据不足")
      .replace(/Nghi ngờ/gi, "可疑")
      .replace(/Tạm/gi, "一般")
      .replace(/Bẩn/gi, "恶意")
      .replace(/Sạch/gi, "纯净");
    return r.trim();
  }

  return r;
}

export function getLocalizedProviderReason(
  reason: string | null | undefined,
  lang: Language = "vi",
): string {
  if (!reason) return "";
  const norm = normalizeLanguage(lang);
  if (norm === "vi") return reason;

  let r = reason;
  if (norm === "en") {
    r = r
      // Geo providers
      .replace(/DB geo cũ\s*>\s*(\d+)\s*ngày:\s*(.+?)\s*[-—–]\s*trừ điểm tin cậy\s*\(§7\.3\)/gi, "Geo DB older than $1 days: $2 — confidence penalty applied (§7.3)")
      .replace(/CẢNH BÁO ĐỎ:\s*các nguồn lệch\s*>\s*([0-9.,]+)\s*km\s*\(§7\.7\)/gi, "RED ALERT: sources deviate > $1 km (§7.7)")
      .replace(/Các nguồn lệch tới\s*([0-9.,]+)\s*km\s*[-—–]\s*KHÔNG chốt thành phố,\s*chỉ chốt quốc gia\/vùng\s*\(§7\.3\)/gi, "Sources deviate up to $1 km — city unresolved, country/region only (§7.3)")
      .replace(/IP anycast\s*[-—–]\s*không chốt thành phố\s*\(§7\.5\)/gi, "Anycast IP — city unresolved (§7.5)")
      .replace(/IP mobile\/CGNAT\s*[-—–]\s*vị trí thường là gateway nhà mạng,\s*không phải người dùng\s*\(§7\.5\)/gi, "Mobile/CGNAT IP — location is carrier gateway, not end user (§7.5)")
      .replace(/IP datacenter\/VPN\s*[-—–]\s*vị trí là nơi thoát,\s*không phải vị trí người thật\s*\(§7\.5\)/gi, "Datacenter/VPN IP — location is exit point, not real user (§7.5)")
      .replace(/ASN chưa đủ 2 nguồn đồng ý\s*[-—–]\s*geo\/ASN kém tin cậy\s*\(§6\.3\)/gi, "Fewer than 2 ASN sources agree — geo/ASN confidence reduced (§6.3)")
      .replace(/Nguồn geo độc lập\s*[-—–]\s*dùng để đối chiếu với ip-api\s*\(§7\.3\)/gi, "Independent geo source — cross-check with ip-api (§7.3)")
      .replace(/Chưa có nguồn geo nào trả về toạ độ/gi, "No geo source returned coordinates")
      .replace(/Các nguồn geo lệch\s*>\s*2\.?000\s*km/gi, "Geo sources differ by > 2,000 km")
      .replace(/Geo:\s*các nguồn chụm\s*<\s*50\s*km/gi, "Geo: sources converge < 50 km")
      .replace(/Geo:\s*lệch 50-200 km/gi, "Geo: deviation 50-200 km")
      .replace(/Geo:\s*lệch\s*>\s*200\s*km/gi, "Geo: deviation > 200 km")
      // AbuseIPDB
      .replace(/AbuseIPDB:\s*IP nằm trong whitelist\s*\(score\s*(\d+)\)/gi, "AbuseIPDB: IP is whitelisted (score $1)")
      .replace(/AbuseIPDB:\s*IP nằm trong whitelist/gi, "AbuseIPDB: IP is whitelisted")
      .replace(/AbuseIPDB:\s*0\s*report trong 90 ngày/gi, "AbuseIPDB: 0 reports in 90 days")
      .replace(/AbuseIPDB:\s*(\d+)\s*báo cáo gần đây\s*\(score\s*(\d+)\)/gi, "AbuseIPDB: $1 recent reports (score $2)")
      .replace(/AbuseIPDB:\s*(\d+)\s*báo cáo gần đây/gi, "AbuseIPDB: $1 recent reports")
      // BGPView
      .replace(/BGPView:\s*AS(\d+)\s*công bố\s*(.+)/gi, "BGPView: AS$1 announces $2")
      .replace(/BGPView:\s*không xác định được ASN\/prefix/gi, "BGPView: unable to determine ASN/prefix")
      // RIPEstat
      .replace(/RIPEstat:\s*AS(\d+)\s*công bố\s*(.+)/gi, "RIPEstat: AS$1 announces $2")
      .replace(/RIPEstat:\s*(.+?)\s*chưa được ASN nào công bố/gi, "RIPEstat: $1 not announced by any ASN")
      .replace(/RIPEstat:\s*không có dữ liệu prefix/gi, "RIPEstat: no prefix data available")
      // Team Cymru
      .replace(/Team Cymru:\s*AS(\d+)\s*công bố\s*(.+)/gi, "Team Cymru: AS$1 announces $2")
      .replace(/Team Cymru:\s*không có bản ghi ASN cho IP này\s*\(NXDOMAIN\)/gi, "Team Cymru: no ASN record for this IP (NXDOMAIN)")
      .replace(/Team Cymru:\s*bản ghi thiếu ASN hoặc prefix/gi, "Team Cymru: record missing ASN or prefix")
      // GreyNoise & Threat Intel
      .replace(/GreyNoise:\s*(.+?)\s*\(malicious,\s*đang quét diện rộng\)/gi, "GreyNoise: $1 (malicious, mass scanner)")
      .replace(/GreyNoise:\s*(.+?)\s*\(noise,\s*chưa quy kết được\)/gi, "GreyNoise: $1 (noise, unclassified)")
      .replace(/GreyNoise:\s*(.+?)\s*\(dịch vụ phổ biến,\s*không phải scanner\)/gi, "GreyNoise: $1 (common service, not a scanner)")
      .replace(/GreyNoise:\s*IP không quét diện rộng\s*\(noise=false,\s*riot=false\)/gi, "GreyNoise: IP not observed in mass scanning (noise=false, riot=false)")
      .replace(/Threat Intel:\s*IP không quét diện rộng\s*\(noise=false\)/gi, "Threat Intel: IP not observed in mass scanning (noise=false)")
      .replace(/Threat Intel:\s*(.+?)\s*\(scanner\/exposed\s*-\s*(.+?)\)/gi, "Threat Intel: $1 (scanner/exposed - $2)")
      .replace(/Threat Intel:\s*(.+?)\s*\(dịch vụ phổ biến,\s*không phải scanner\)/gi, "Threat Intel: $1 (common service, not a scanner)")
      .replace(/Threat Intel:\s*(.+?)\s*\(không ghi nhận hành vi scanner\)/gi, "Threat Intel: $1 (no scanner activity observed)")
      .replace(/GreyNoise:\s*IP không có trong dữ liệu scanner/gi, "GreyNoise: IP not observed in scanner data")
      // ipinfo
      .replace(/ipinfo:\s*IP là Tor exit/gi, "ipinfo: IP is Tor exit node")
      .replace(/ipinfo:\s*IP thuộc VPN/gi, "ipinfo: IP belongs to VPN")
      .replace(/ipinfo:\s*IP là proxy/gi, "ipinfo: IP is proxy")
      .replace(/ipinfo:\s*IP là relay\s*\(iCloud Private Relay\s*\/[^\)]*\)/gi, "ipinfo: IP is relay (iCloud Private Relay / similar)")
      .replace(/ipinfo:\s*IP thuộc dải hosting\/datacenter/gi, "ipinfo: IP belongs to datacenter / hosting")
      .replace(/ipinfo:\s*anycast\s*-\s*không chặt thành phố\s*\(§7\.5\)/gi, "ipinfo: anycast — city location is approximate (§7.5)")
      .replace(/ipinfo:\s*không phát hiện privacy flags/gi, "ipinfo: no privacy flags detected")
      // ip-api flags
      .replace(/IP bị gắn cờ proxy/gi, "ip-api flagged proxy=true")
      .replace(/ip-api gắn cờ proxy=true/gi, "ip-api flagged proxy=true")
      .replace(/IP thuộc dải hosting\/datacenter\s*-\s*vị trí geo có thể lệch\s*\(§7\.5\)/gi, "ip-api flagged hosting/datacenter=true (proxy=false)")
      .replace(/ip-api gắn cờ hosting\/datacenter=true\s*\(proxy=false\)/gi, "ip-api flagged hosting/datacenter=true (proxy=false)")
      .replace(/IP mobile\s*-\s*thành phố chỉ là gateway nhà mạng\s*\(§7\.5\)/gi, "Mobile IP — city is carrier gateway (§7.5)")
      // Scamalytics / IPQS
      .replace(/(\d+)\s*IP bị blocklist/gi, "$1 IP(s) blocklisted")
      .replace(/;\s*cờ:\s*(.+)/gi, "; flags: $1")
      // DNSBL / Cache
      .replace(/Listed\s*\(từ lịch sử cache\)/gi, "Listed (from cached history)")
      .replace(/Zone đã bị disable trong phiên này:\s*(.+)/gi, "Zone disabled for this session: $1")
      .replace(/Zone bị disable do lỗi lặp lại:\s*(.+)/gi, "Zone disabled due to repeated errors: $1")
      // Network notes
      .replace(/ICMP bị chặn hoặc không chạy được\s*-\s*thử TCP ping\s*\(§9\)/gi, "ICMP blocked or unavailable — falling back to TCP ping (§9)")
      .replace(/IP anycast\s*-\s*không chặt thành phố\s*\(§7\.5\)/gi, "Anycast IP — city location is approximate (§7.5)")
      .replace(/Không endpoint nào trả về IP thoát\./gi, "No endpoint returned an exit IP.")
      // Leak & speed
      .replace(/WebRTC lòi IP thật/gi, "WebRTC leaked real IP")
      .replace(/DNS leak/gi, "DNS leak detected")
      .replace(/Timezone browser lệch timezone IP/gi, "Browser timezone mismatches IP timezone")
      .replace(/Không thấy leak/gi, "No leak detected")
      .replace(/Cần ít nhất 2 endpoint độc lập để đo tốc độ\s*\(§8\.3\)\s*-\s*cấu hình hiện tại không đủ\./gi, "At least 2 independent endpoints required for speed test (§8.3) — current configuration is insufficient.")
      .replace(/Chưa đo được tốc độ:\s*cần ít nhất 2 endpoint độc lập trả về số liệu,\s*chỉ\s*(\d+)\s*endpoint thành công\./gi, "Speed not measured: at least 2 independent endpoints must return data, only $1 endpoint succeeded.")
      .replace(/Phương pháp:\s*tải file test qua proxy từ\s*(\d+)\s*endpoint độc lập/gi, "Method: download test file via proxy from $1 independent endpoints")
      // ASN consensus & Timezone
      .replace(/ASN:\s*≥2 nguồn đồng ý/gi, "ASN: ≥2 sources agree")
      .replace(/ASN:\s*chưa đủ 2 nguồn đồng ý/gi, "ASN: fewer than 2 sources agree")
      .replace(/Quốc gia RIR khác quốc gia geo/gi, "RIR country differs from geo country")
      .replace(/Timezone:\s*các nguồn khớp/gi, "Timezone: sources match")
      .replace(/Timezone:\s*(\d+)\s*giá trị khác nhau/gi, "Timezone: $1 distinct values")
      // General errors & auth
      .replace(/(\d+)\s+nguồn trả Unknown\s*\(timeout\/hết quota\/thiếu key\)\s*[-—–]\s*Confidence bị trừ/gi, "$1 source(s) returned Unknown (timeout/quota/missing key) — Confidence reduced")
      .replace(/Không provider nào quyết định verdict:\s*trọng số mỗi provider\s*[≤<=]+\s*40%\s*khía cạnh\s*\(§6\.4\)/gi, "No provider determines verdict: max weight per provider ≤ 40% of aspect (§6.4)")
      .replace(/Verdict bị chặn bởi quorum thiếu:\s*(.+?)(?=\.|$|\s*\(§6\.3\))/gi, "Verdict blocked due to missing quorum: $1 (§6.3)")
      .replace(/thiếu key hoặc bị ngắt/gi, "missing key or disconnected")
      .replace(/thiếu key/gi, "missing key")
      .replace(/hết quota/gi, "quota exhausted")
      .replace(/không trả lời trong 5s/gi, "did not respond in 5s")
      .replace(/timeout/gi, "timeout");
  } else if (norm === "zh") {
    r = r
      // Geo providers
      .replace(/DB geo cũ\s*>\s*(\d+)\s*ngày:\s*(.+?)\s*[-—–]\s*trừ điểm tin cậy\s*\(§7\.3\)/gi, "地理数据库超过 $1 天未更新: $2 — 已扣减置信度 (§7.3)")
      .replace(/CẢNH BÁO ĐỎ:\s*các nguồn lệch\s*>\s*([0-9.,]+)\s*km\s*\(§7\.7\)/gi, "红色警报: 各源偏差 > $1 km (§7.7)")
      .replace(/Các nguồn lệch tới\s*([0-9.,]+)\s*km\s*[-—–]\s*KHÔNG chốt thành phố,\s*chỉ chốt quốc gia\/vùng\s*\(§7\.3\)/gi, "各源偏差达 $1 km — 未锁定城市，仅锁定国家/区域 (§7.3)")
      .replace(/IP anycast\s*[-—–]\s*không chốt thành phố\s*\(§7\.5\)/gi, "Anycast任播IP — 未锁定城市 (§7.5)")
      .replace(/IP mobile\/CGNAT\s*[-—–]\s*vị trí thường là gateway nhà mạng,\s*không phải người dùng\s*\(§7\.5\)/gi, "移动蜂窝网络/CGNAT IP — 定位多为运营商网关而非真实用户 (§7.5)")
      .replace(/IP datacenter\/VPN\s*[-—–]\s*vị trí là nơi thoát,\s*không phải vị trí người thật\s*\(§7\.5\)/gi, "数据中心/VPN IP — 定位为出口节点而非真实用户 (§7.5)")
      .replace(/ASN chưa đủ 2 nguồn đồng ý\s*[-—–]\s*geo\/ASN kém tin cậy\s*\(§6\.3\)/gi, "达成一致的ASN源不足2个 — 地理位置/ASN置信度降低 (§6.3)")
      .replace(/Nguồn geo độc lập\s*[-—–]\s*dùng để đối chiếu với ip-api\s*\(§7\.3\)/gi, "独立地理位置源 — 用于与 ip-api 进行交叉核对 (§7.3)")
      .replace(/Chưa có nguồn geo nào trả về toạ độ/gi, "尚无地理位置数据源返回坐标")
      .replace(/Các nguồn geo lệch\s*>\s*2\.?000\s*km/gi, "地理位置源偏差 > 2,000 km")
      .replace(/Geo:\s*các nguồn chụm\s*<\s*50\s*km/gi, "地理位置: 各源收敛 < 50 km")
      .replace(/Geo:\s*lệch 50-200 km/gi, "地理位置: 偏差 50-200 km")
      .replace(/Geo:\s*lệch\s*>\s*200\s*km/gi, "地理位置: 偏差 > 200 km")
      // AbuseIPDB
      .replace(/AbuseIPDB:\s*IP nằm trong whitelist\s*\(score\s*(\d+)\)/gi, "AbuseIPDB: IP 位于白名单中 (评分 $1)")
      .replace(/AbuseIPDB:\s*IP nằm trong whitelist/gi, "AbuseIPDB: IP 位于白名单中")
      .replace(/AbuseIPDB:\s*0\s*report trong 90 ngày/gi, "AbuseIPDB: 90 天内 0 条报告")
      .replace(/AbuseIPDB:\s*(\d+)\s*báo cáo gần đây\s*\(score\s*(\d+)\)/gi, "AbuseIPDB: 最近有 $1 条滥用报告 (评分 $2)")
      .replace(/AbuseIPDB:\s*(\d+)\s*báo cáo gần đây/gi, "AbuseIPDB: 最近有 $1 条滥用报告")
      // BGPView
      .replace(/BGPView:\s*AS(\d+)\s*công bố\s*(.+)/gi, "BGPView: AS$1 宣告 $2")
      .replace(/BGPView:\s*không xác định được ASN\/prefix/gi, "BGPView: 无法确定 ASN/前缀")
      // RIPEstat
      .replace(/RIPEstat:\s*AS(\d+)\s*công bố\s*(.+)/gi, "RIPEstat: AS$1 宣告 $2")
      .replace(/RIPEstat:\s*(.+?)\s*chưa được ASN nào công bố/gi, "RIPEstat: $1 尚未被任何 ASN 宣告")
      .replace(/RIPEstat:\s*không có dữ liệu prefix/gi, "RIPEstat: 无前缀数据")
      // Team Cymru
      .replace(/Team Cymru:\s*AS(\d+)\s*công bố\s*(.+)/gi, "Team Cymru: AS$1 宣告 $2")
      .replace(/Team Cymru:\s*không có bản ghi ASN cho IP này\s*\(NXDOMAIN\)/gi, "Team Cymru: 此 IP 无 ASN 记录 (NXDOMAIN)")
      .replace(/Team Cymru:\s*bản ghi thiếu ASN hoặc prefix/gi, "Team Cymru: 记录缺少 ASN 或前缀")
      // GreyNoise & Threat Intel
      .replace(/GreyNoise:\s*(.+?)\s*\(malicious,\s*đang quét diện rộng\)/gi, "GreyNoise: $1 (恶意，正在进行广域扫描)")
      .replace(/GreyNoise:\s*(.+?)\s*\(noise,\s*chưa quy kết được\)/gi, "GreyNoise: $1 (杂音，尚未归类)")
      .replace(/GreyNoise:\s*(.+?)\s*\(dịch vụ phổ biến,\s*không phải scanner\)/gi, "GreyNoise: $1 (常用服务，非扫描器)")
      .replace(/GreyNoise:\s*IP không quét diện rộng\s*\(noise=false,\s*riot=false\)/gi, "GreyNoise: IP 未观察到广域扫描 (noise=false, riot=false)")
      .replace(/Threat Intel:\s*IP không quét diện rộng\s*\(noise=false\)/gi, "威胁情报: IP 未观察到广域扫描 (noise=false)")
      .replace(/Threat Intel:\s*(.+?)\s*\(scanner\/exposed\s*-\s*(.+?)\)/gi, "威胁情报: $1 (扫描器/暴露资产 - $2)")
      .replace(/Threat Intel:\s*(.+?)\s*\(dịch vụ phổ biến,\s*không phải scanner\)/gi, "威胁情报: $1 (常用服务，非扫描器)")
      .replace(/Threat Intel:\s*(.+?)\s*\(không ghi nhận hành vi scanner\)/gi, "威胁情报: $1 (未记录到扫描器行为)")
      .replace(/GreyNoise:\s*IP không có trong dữ liệu scanner/gi, "GreyNoise: IP 未出现在扫描器数据中")
      // ipinfo
      .replace(/ipinfo:\s*IP là Tor exit/gi, "ipinfo: IP 为 Tor 出口节点")
      .replace(/ipinfo:\s*IP thuộc VPN/gi, "ipinfo: IP 属于 VPN 网络")
      .replace(/ipinfo:\s*IP là proxy/gi, "ipinfo: IP 为代理")
      .replace(/ipinfo:\s*IP là relay\s*\(iCloud Private Relay\s*\/[^\)]*\)/gi, "ipinfo: IP 为中继 (iCloud专用代理等)")
      .replace(/ipinfo:\s*IP thuộc dải hosting\/datacenter/gi, "ipinfo: IP 属于机房/数据中心")
      .replace(/ipinfo:\s*anycast\s*-\s*không chặt thành phố\s*\(§7\.5\)/gi, "ipinfo: Anycast任播 — 城市级定位仅供参考 (§7.5)")
      .replace(/ipinfo:\s*không phát hiện privacy flags/gi, "ipinfo: 未检测到隐私标记")
      // ip-api flags
      .replace(/IP bị gắn cờ proxy/gi, "ip-api 标记 proxy=true")
      .replace(/ip-api gắn cờ proxy=true/gi, "ip-api 标记 proxy=true")
      .replace(/IP thuộc dải hosting\/datacenter\s*-\s*vị trí geo có thể lệch\s*\(§7\.5\)/gi, "ip-api 标记 hosting/datacenter=true (proxy=false)")
      .replace(/ip-api gắn cờ hosting\/datacenter=true\s*\(proxy=false\)/gi, "ip-api 标记 hosting/datacenter=true (proxy=false)")
      .replace(/IP mobile\s*-\s*thành phố chỉ là gateway nhà mạng\s*\(§7\.5\)/gi, "移动蜂窝网络IP — 城市仅代表运营商网关 (§7.5)")
      // Scamalytics / IPQS
      .replace(/(\d+)\s*IP bị blocklist/gi, "$1 个 IP 被列入黑名单")
      .replace(/;\s*cờ:\s*(.+)/gi, "; 标记: $1")
      // DNSBL / Cache
      .replace(/Listed\s*\(từ lịch sử cache\)/gi, "已列入黑名单 (来自缓存记录)")
      .replace(/Zone đã bị disable trong phiên này:\s*(.+)/gi, "该区域在此会话中已被停用: $1")
      .replace(/Zone bị disable do lỗi lặp lại:\s*(.+)/gi, "该区域因重复错误已被停用: $1")
      // Network notes
      .replace(/ICMP bị chặn hoặc không chạy được\s*-\s*thử TCP ping\s*\(§9\)/gi, "ICMP被阻断或不可用 — 回退至TCP ping (§9)")
      .replace(/IP anycast\s*-\s*không chặt thành phố\s*\(§7\.5\)/gi, "Anycast任播IP — 城市级定位仅供参考 (§7.5)")
      .replace(/Không endpoint nào trả về IP thoát\./gi, "没有端点返回出口 IP。")
      // Leak & speed
      .replace(/WebRTC lòi IP thật/gi, "WebRTC 暴露真实 IP")
      .replace(/DNS leak/gi, "检测到 DNS 泄漏")
      .replace(/Timezone browser lệch timezone IP/gi, "浏览器时区与 IP 时区不符")
      .replace(/Không thấy leak/gi, "未检测到泄漏")
      .replace(/Cần ít nhất 2 endpoint độc lập để đo tốc độ\s*\(§8\.3\)\s*-\s*cấu hình hiện tại không đủ\./gi, "测速需要至少 2 个独立端点 (§8.3) — 当前配置不足。")
      .replace(/Chưa đo được tốc độ:\s*cần ít nhất 2 endpoint độc lập trả về số liệu,\s*chỉ\s*(\d+)\s*endpoint thành công\./gi, "未测速：至少需要 2 个独立端点返回数据，仅 $1 个端点成功。")
      .replace(/Phương pháp:\s*tải file test qua proxy từ\s*(\d+)\s*endpoint độc lập/gi, "测试方法：通过代理从 $1 个独立端点下载测试文件")
      // ASN consensus & Timezone
      .replace(/ASN:\s*≥2 nguồn đồng ý/gi, "ASN: ≥2 个数据源一致")
      .replace(/ASN:\s*chưa đủ 2 nguồn đồng ý/gi, "ASN: 达成一致的源不足 2 个")
      .replace(/Quốc gia RIR khác quốc gia geo/gi, "RIR 注册国家与地理位置国家不符")
      .replace(/Timezone:\s*các nguồn khớp/gi, "时区: 各数据源一致")
      .replace(/Timezone:\s*(\d+)\s*giá trị khác nhau/gi, "时区: 出现 $1 种不同值")
      // General errors & auth
      .replace(/(\d+)\s+nguồn trả Unknown\s*\(timeout\/hết quota\/thiếu key\)\s*[-—–]\s*Confidence bị trừ/gi, "$1 个源返回未知 (超时/配额耗尽/缺少密钥) — 已扣减置信度")
      .replace(/Không provider nào quyết định verdict:\s*trọng số mỗi provider\s*[≤<=]+\s*40%\s*khía cạnh\s*\(§6\.4\)/gi, "无单一服务商主导判定：单个服务商权重 ≤ 维度的 40% (§6.4)")
      .replace(/Verdict bị chặn bởi quorum thiếu:\s*(.+?)(?=\.|$|\s*\(§6\.3\))/gi, "判定因缺少法定数据源受阻: $1 (§6.3)")
      .replace(/thiếu key hoặc bị ngắt/gi, "缺少密钥或已断开")
      .replace(/thiếu key/gi, "缺少密钥")
      .replace(/hết quota/gi, "配额耗尽")
      .replace(/không trả lời trong 5s/gi, "5秒内未响应")
      .replace(/timeout/gi, "超时");
  }
  return r;
}
