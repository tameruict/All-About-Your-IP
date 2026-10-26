/**
 * IP Checker — shared type contract between the React front-end and the Rust core.
 *
 * RULES
 * -----
 * - Every type here is 1:1 with a `#[derive(Serialize, Deserialize)]` Rust struct/enum.
 * - Field names are snake_case and MUST match the Rust serde output verbatim
 *   (see spec §4.4, §6.6, §10.1). No camelCase mapping layer anywhere.
 * - Enums are serialised as plain strings with the casing shown below
 *   (`Signal` is PascalCase because spec §6.6 shows `"signal": "Clean"`;
 *   every other enum is lowercase snake_case because §6.6 shows
 *   `"mode": "ip_only"` and `"category": "fraud"`).
 * - Anything marked `Nullable` mirrors `Option<T>` in Rust.
 * - This file is the front-end/back-end contract: other agents edit
 *   consumers, not the shapes. Additive changes only, never rename a field.
 */

/* ------------------------------------------------------------------ */
/* Primitive enums                                                     */
/* ------------------------------------------------------------------ */

/** Check mode. §1.2 — IP-only vs proxy-check. */
export type CheckMode = "ip_only" | "proxy" | "unknown";

/** Proxy protocol. Only meaningful when `mode === "proxy"`. */
export type ProxyProtocol = "http" | "https" | "socks5" | "socks4";

/** Provider category (§4.4 trait Provider::category). */
export type Category =
  | "geo"
  | "asn"
  | "fraud"
  | "abuse"
  | "threat_intel"
  | "blacklist"
  | "network"
  | "leak"
  | "speed"
  | "local_db";

/** Normalised provider verdict (§6.1). PascalCase on the wire — see §6.6 sample. */
export type Signal = "Clean" | "Suspicious" | "Bad" | "Unknown";

/** Final user-facing verdict (§6.5). Vietnamese labels, exact strings. */
export type Verdict = "Sạch" | "Tạm" | "Nghi ngờ" | "Bẩn" | "Chưa đủ dữ liệu";

/** Per-module progress state (§3.3 ScanProgress). */
export type ModuleStatus = "pending" | "running" | "done" | "error" | "skipped";

/** Why a module was skipped (§3.3). */
export type SkipReason =
  | "missing_key"
  | "requires_proxy"
  | "quota_exhausted"
  | "disabled"
  | "circuit_open"
  | "not_implemented"
  | "unsupported_ip";

/** Coarse classification of the IP itself (§5.1 hosting/proxy/mobile flags). */
export type IpType =
  | "residential"
  | "datacenter"
  | "mobile"
  | "cgnat"
  | "vpn"
  | "tor"
  | "proxy"
  | "anycast"
  | "edu"
  | "unknown";

/** Export format supported by `export_report` (§4.2, §10.3). */
export type ExportFormat = "json" | "csv";

/** Provider health colour shown in Settings (§5.5). */
export type HealthState = "green" | "yellow" | "red" | "unknown";

/** How a DNSBL group being listed should be interpreted (§6.1, §5.3). */
export type ListedVerdict = "bad" | "suspicious";

/** Group key of a DNSBL zone (§5.3: spamhaus | commercial | community | specialist). */
export type DnsblGroup = "spamhaus" | "commercial" | "community" | "specialist";

/** Module identifiers used in the streaming progress event (§3.3). */
export type ModuleId =
  | "validate"
  | "geo"
  | "asn"
  | "fraud"
  | "abuse"
  | "threat_intel"
  | "dnsbl"
  | "network"
  | "location"
  | "exit_ip"
  | "leak"
  | "speed"
  | "scoring";

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/** Mirrors `ProviderError` in Rust (§4.4). Serialised internally tagged. */
export interface ProviderError {
  /** Machine-readable kind: timeout | http | parse | auth | quota | network | unsupported | internal. */
  kind: string;
  /** Short human message. Never contains an API key or proxy credentials. */
  message: string;
  /** HTTP status when applicable. */
  status?: number | null;
  /** Whether retrying could help. */
  retryable: boolean;
}

/** Uniform error shape every `invoke()` rejection carries (§3.4). */
export interface CommandError {
  /** error kind: invalid_input | private_ip | network | db | io | internal. */
  kind: string;
  message: string;
  /** Validation detail, e.g. the offending input string. */
  detail?: string | null;
}

/* ------------------------------------------------------------------ */
/* Provider evidence (§4.4)                                            */
/* ------------------------------------------------------------------ */

/** Normalised provider result. Scoring and UI must not read raw provider fields. */
export interface ProviderEvidence {
  /** Registry id, e.g. "ipqualityscore", "spamhaus_zen". */
  provider: string;
  category: Category;
  /** Root data source, used for de-duplication of votes (§6.2). */
  upstream: string;
  signal: Signal;
  /** Provider's own score in its own scale; `null` when the provider has no score. */
  raw_score: number | null;
  /** Sanitised provider payload, ready to display / export. Key material stripped. */
  raw?: Record<string, unknown> | null;
  /** ISO-8601 with offset, e.g. "2026-10-25T11:30:00+07:00". */
  checked_at: string;
  /** Canonical URL the user can open to verify by hand. */
  source_url: string;
  /** Latency in ms when known. */
  latency_ms?: number | null;
  /** Failure detail when signal is Unknown. */
  error?: ProviderError | null;
  /** Short reason string shown in the Evidence table. */
  reason?: string | null;
  /** True when the answer came from cache rather than a live request. */
  from_cache?: boolean;
}

/** Alias kept for spec wording (§4.4 uses `Evidence` in the JSON sample). */
export type Evidence = ProviderEvidence;

/* ------------------------------------------------------------------ */
/* Geo / location (§7)                                                 */
/* ------------------------------------------------------------------ */

/** One geo source's opinion about the IP. §7.3 — never collapse to one point. */
export interface GeoPoint {
  /** Provider id or local DB name, e.g. "ip-api", "maxmind_geolite2_city". */
  source: string;
  /** api | local_db | cloud_range | bgp | reverse_dns. */
  source_kind: string;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  postal: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  /** Accuracy radius reported by the source, in km (MaxMind `accuracy_radius`). */
  accuracy_radius_km: number | null;
  /** Version string of the underlying DB, when the source is a local DB. */
  db_version: string | null;
  /** ISO date of the DB snapshot, when the source is a local DB. */
  db_updated_at: string | null;
  /** Distance from the computed centroid, in km (null for the centroid itself). */
  distance_from_centroid_km: number | null;
  /** True when the source returned a street-level address — flagged as untrustworthy (§7.1). */
  over_precise: boolean;
}

/** Result of the triangulation (location_engine). */
export interface LocationResult {
  /** Majority-vote country, or null when sources disagree too much. */
  country: string | null;
  country_code: string | null;
  /** Confidence in the country conclusion, 0–100. */
  country_confidence: number;
  /** Committed city, or null when spread > 200 km (§7.3). */
  city: string | null;
  region: string | null;
  /** Centroid of all usable points, or null when points are unusable. */
  centroid_latitude: number | null;
  centroid_longitude: number | null;
  /** Radius covering the points, in km. */
  radius_km: number | null;
  /** Spread label: high | medium | low | disputed. */
  spread: string;
  /** Per-source votes, for the map + "phiếu" table (§7.7). */
  points: GeoPoint[];
  /** True when any two sources are > 2000 km apart (§7.7 red warning). */
  big_divergence: boolean;
  /** Human-readable Vietnamese notes about what could / could not be concluded. */
  notes: string[];
  /** Location history change vs the previous cached check, when known (§7.7). */
  changed_since_last_check?: boolean;
  previous_country?: string | null;
  previous_city?: string | null;
}

/* ------------------------------------------------------------------ */
/* ASN (§5.1, §7.4)                                                    */
/* ------------------------------------------------------------------ */

/** One ASN / prefix / RIR opinion. */
export interface AsnRecord {
  source: string;
  asn: number | null;
  /** e.g. "AS15169". */
  asn_name: string | null;
  organisation: string | null;
  prefix: string | null;
  /** Country of the prefix registration (RIR), may differ from geo country (§7.4). */
  rir_country: string | null;
  registry: string | null;
  /** Team Cymru / BGPView confidence note, free text. */
  note?: string | null;
}

/** Aggregated ASN answer. */
export interface AsnResult {
  asn: number | null;
  asn_name: string | null;
  organisation: string | null;
  prefix: string | null;
  /** ISP / org as reported by geo providers. */
  isp: string | null;
  /** Country from the RIR record; divergence with geo country is a flag (§7.4). */
  rir_country: string | null;
  /** True when ≥2 sources agree on the ASN (§6.3). */
  consensus: boolean;
  /** True when geo country ≠ RIR country (§7.4). */
  country_mismatch: boolean;
  records: AsnRecord[];
  ip_type: IpType;
  /** Raw provider booleans used for ip_type (§5.1 hosting/proxy/mobile flags). */
  flags: {
    hosting: boolean;
    proxy: boolean;
    vpn: boolean;
    tor: boolean;
    mobile: boolean;
    anycast?: boolean;
  };
}

/* ------------------------------------------------------------------ */
/* Network probe (§9)                                                  */
/* ------------------------------------------------------------------ */

/** Ping / traceroute / reverse DNS summary. */
export interface NetworkResult {
  /** icmp | tcp_80 | tcp_443 | none. */
  ping_method: string;
  latency_avg_ms: number | null;
  latency_min_ms: number | null;
  latency_max_ms: number | null;
  /** Standard deviation, used as jitter. */
  jitter_ms: number | null;
  packets_sent: number | null;
  packets_received: number | null;
  /** 0–100. */
  packet_loss_pct: number | null;
  /** Reverse DNS (PTR) hostname. */
  reverse_dns: string | null;
  /** True when the PTR hostname plausibly matches the ISP/ASN (§9). */
  reverse_dns_matches_isp: boolean | null;
  /** Observed TTL, used as a weak OS hint only (§9). */
  ttl: number | null;
  os_guess: string | null;
  traceroute_hops: TracerouteHop[];
  /** Short note about limits ("ICMP bị chặn, dùng TCP ping 443"). */
  notes: string[];
}

export interface TracerouteHop {
  hop: number;
  address: string | null;
  hostname: string | null;
  rtt_ms: number | null;
  /** True when the hop's hostname/country leaves the country of the target. */
  is_international?: boolean;
}

/* ------------------------------------------------------------------ */
/* Blacklist / DNSBL (§5.3)                                            */
/* ------------------------------------------------------------------ */

/** One DNSBL zone result. */
export interface DnsblEntry {
  /** Registry id, e.g. "spamhaus_zen". */
  provider: string;
  /** Zone queried, e.g. "zen.spamhaus.org". */
  zone: string;
  group: DnsblGroup;
  listed: boolean;
  /** Return code(s) e.g. ["127.0.0.2"]. */
  return_codes: string[];
  signal: Signal;
  listed_verdict: ListedVerdict;
  /** Provider-supplied meaning of the code, when known. */
  reason: string | null;
  source_url: string;
  checked_at: string;
  /** Error detail when the query failed (zone dead / NXDOMAIN is NOT an error). */
  error?: ProviderError | null;
}

/** Aggregation per DNSBL group — a group is one vote, not each zone (§5.3). */
export interface DnsblGroupResult {
  group: DnsblGroup;
  /** Presentation label, Vietnamese OK. */
  label: string;
  checked: number;
  listed: number;
  /** Worst signal inside the group. */
  signal: Signal;
  /** True when at least one zone in the group answered. */
  answered: boolean;
  entries: DnsblEntry[];
}

/** Whole DNSBL module result. */
export interface DnsblResult {
  groups: DnsblGroupResult[];
  /** Total listed zones across every group. */
  total_listed: number;
  /** Distinct groups that answered (quorum needs ≥3, §6.3). */
  groups_answered: number;
  /** True when Spamhaus ZEN or a Tor exit list hit (§6.5 forcible downgrade). */
  hard_hit: boolean;
  notes: string[];
}

/* ------------------------------------------------------------------ */
/* Proxy mode: exit IP, leak, speed (§8)                               */
/* ------------------------------------------------------------------ */

/** Real exit IP measured through the proxy (§8.1). */
export interface ExitIpResult {
  /** Proxy reachable at all. */
  reachable: boolean;
  /** Exit IP reported by each endpoint. */
  endpoint_results: ExitIpEndpoint[];
  /** Agreed exit IP, or null when endpoints disagree. */
  exit_ip: string | null;
  /** True when exit_ip !== the IP the user typed (§8.1 red flag). */
  differs_from_input: boolean;
  /** True when two endpoints reported different IPs (rotating proxy). */
  endpoints_disagree: boolean;
  notes: string[];
}

export interface ExitIpEndpoint {
  endpoint: string;
  ok: boolean;
  exit_ip: string | null;
  latency_ms: number | null;
  error: string | null;
}

/** Browser leak module (§8.2). Implemented locally, never scraped. */
export interface LeakResult {
  /** False when proxy mode was not requested — UI must show "Chưa đo được". */
  measured: boolean;
  webrtc_leak: boolean;
  /** ICE candidates that contained the machine's real IP. */
  webrtc_candidates: string[];
  dns_leak: boolean | null;
  /** dns | none | unknown. */
  dns_method: string;
  /** Resolver seen by the test page. */
  dns_resolver_seen: string | null;
  browser_timezone: string | null;
  ip_timezone: string | null;
  timezone_mismatch: boolean;
  browser_language: string | null;
  ip_country: string | null;
  country_mismatch: boolean;
  /** Headless / automation fingerprints found locally (§8.2). */
  headless_flags: string[];
  ja3: string | null;
  ja3_source: string | null;
  /** True when the TTL/UA pair looks inconsistent (§8.2 optional). */
  tcp_fingerprint_mismatch: boolean | null;
  /** True when the leak module downgrades the verdict (§6.5). */
  downgrade: boolean;
  notes: string[];
  error?: ProviderError | null;
}

/** Speed module (§8.3). Never cached (§10.2). */
export interface SpeedResult {
  measured: boolean;
  endpoints: SpeedEndpoint[];
  /** Best-case download throughput in Mbps across endpoints. */
  download_mbps: number | null;
  latency_ms: number | null;
  jitter_ms: number | null;
  /** Upload only when explicitly enabled by the user. */
  upload_mbps: number | null;
  measured_at: string | null;
  notes: string[];
  error?: ProviderError | null;
}

export interface SpeedEndpoint {
  endpoint: string;
  ok: boolean;
  download_mbps: number | null;
  latency_ms: number | null
  ;
  jitter_ms: number | null;
  bytes: number | null;
  duration_ms: number | null;
  error: string | null;
}

/* ------------------------------------------------------------------ */
/* Scoring (§6)                                                        */
/* ------------------------------------------------------------------ */

/** Weighted per-aspect breakdown of the Clean Score (§6.4). */
export interface ScoreBreakdown {
  /** Aspect key: fraud | blacklist | asn | abuse | consistency. */
  aspect: string;
  /** Aspect weight, 0–1, total = 1. */
  weight: number;
  /** Aspect score 0–100 before weighting, null when the aspect had no usable votes. */
  aspect_score: number | null;
  /** aspect_score × weight, null when unavailable. */
  weighted: number | null;
  /** Votes used for this aspect (after upstream de-duplication). */
  votes: number;
  /** True when the aspect met its quorum (§6.3). */
  quorum_met: boolean;
  /** Text explanation for the Evidence panel. */
  note: string;
}

/** Conflict between sources (§6.5). */
export interface ConflictFlag {
  /** hard = forces downgrade / blocks a "clean" verdict. */
  severity: "hard" | "soft";
  aspect: string;
  /** Providers on the "bad" side. */
  dissenting: string[];
  /** Providers on the "clean" side. */
  agreeing: string[];
  message: string;
}

/** Quorum bookkeeping (§6.3). */
export interface QuorumStatus {
  aspect: string;
  required: number;
  actual: number;
  met: boolean;
  missing: string[];
}

/** Full scoring output. Embedded in FullCheckResult. */
export interface ScoringResult {
  clean_score: number | null;
  confidence_score: number;
  verdict: Verdict;
  verdict_reason: string;
  breakdown: ScoreBreakdown[];
  conflicts: ConflictFlag[];
  quorum: QuorumStatus[];
  /** True when at least one single-source hard hit exists (§6.5). */
  single_source_evidence: boolean;
  /** Vietnamese notes surfaced in the UI. */
  notes: string[];
}

/* ------------------------------------------------------------------ */
/* Scan / session (§3.3, §4.2)                                         */
/* ------------------------------------------------------------------ */

/** Live state of one module, streamed through `check-progress`. */
export interface ModuleState {
  module: ModuleId;
  status: ModuleStatus;
  /** 0–100 within the module. */
  progress: number;
  started_at: string | null;
  finished_at: string | null;
  /** Number of providers done / total for aggregated modules. */
  providers_done: number;
  providers_total: number;
  skip_reason?: SkipReason | null;
  /** Short status line for the console log. */
  message: string;
  error?: ProviderError | null;
}

/**
 * Payload of the `check-progress` Tauri event (§4.2 `check_ip_stream`).
 * Emitted many times per check; the front-end must render incrementally.
 */
export interface CheckProgressEvent {
  check_id: string;
  /** ISO-8601 start time of the streamed check. */
  started_at: string;
  module: ModuleId;
  status: ModuleStatus;
  progress: number;
  message: string;
  /** Present when a module streamed a final payload (scoring, dnsbl, ...). */
  partial?: Partial<FullCheckResult> | null;
  modules: ModuleState[];
}

/** One DNSBL / provider line for the streaming console. */
export interface CheckLogLine {
  check_id: string;
  at: string;
  module: ModuleId;
  level: "info" | "warn" | "error" | "success";
  message: string;
}

/* ------------------------------------------------------------------ */
/* Request inputs                                                      */
/* ------------------------------------------------------------------ */

/**
 * Proxy credentials. Passed per-request only — never persisted, never cached,
 * never written to SQLite (§8.4, §10.1).
 */
export interface ProxyCredentials {
  username: string;
  password: string;
}

/**
 * Options accepted by `check_ip` / `check_ip_stream`.
 * The Rust side is tolerant: every field has a default.
 */
export interface CheckOptions {
  /** Explicit protocol; omitted means "auto" (detected from input / defaults to http). */
  protocol?: ProxyProtocol | null;
  /** Proxy credentials, transient. */
  credentials?: ProxyCredentials | null;
  /** false = ignore cache, force a live check (§10.2 "Check lại" button). */
  use_cache?: boolean;
  /** false = do not persist to history (§3.3 checkbox). */
  save_to_history?: boolean;
  /** Run the proxy-mode leak module (Chromium). Requires proxy input. */
  run_leak_check?: boolean;
  /** Run the proxy-mode speed module. Requires proxy input. */
  run_speed_check?: boolean;
  /** Override global per-provider timeout (ms). Clamped to 1000–30000. */
  timeout_ms?: number | null;
  /** Restrict to a subset of modules; null = all applicable. */
  modules?: ModuleId[] | null;
}

/* ------------------------------------------------------------------ */
/* Core results (§4.2, §6.6)                                           */
/* ------------------------------------------------------------------ */

/**
 * Result of one full check. Field names follow spec §6.6 exactly for the
 * top level; the nested blocks are the additive extensions every module needs.
 */
export interface FullCheckResult {
  /** Row id of `checks.id`. */
  check_id: string;
  /** Short alias some call-sites use; always equals check_id (§6.6 has no id field before export). */
  id?: string;
  ip: string;
  mode: CheckMode;
  clean_score: number | null;
  confidence_score: number;
  verdict: Verdict;
  verdict_reason: string;
  evidence: ProviderEvidence[];
  checked_at: string;
  /** True when the whole result came from the SQLite cache (§3.4, §10.2). */
  from_cache: boolean;

  /* ---- proxy-mode metadata (never contains credentials) ---- */
  proxy_host?: string | null;
  proxy_port?: number | null;
  proxy_protocol?: ProxyProtocol | null;

  /* ---- module payloads ---- */
  is_private: boolean;
  validation_error?: string | null;
  ip_version?: 4 | 6 | null;
  location?: LocationResult | null;
  asn?: AsnResult | null;
  dnsbl?: DnsblResult | null;
  network?: NetworkResult | null;
  exit_ip?: ExitIpResult | null;
  leak?: LeakResult | null;
  speed?: SpeedResult | null;
  scoring?: ScoringResult | null;

  /** Health snapshot of every provider touched by this check (§5.5). */
  provider_health?: ProviderHealth[];

  /** Version + date of the local geo DBs used, for display (§7.3, §11). */
  geo_db_versions?: GeoDbVersion[];

  /** Modules that ran, with their final state. */
  modules?: ModuleState[];

  /** Total wall-clock duration of the check in ms. */
  duration_ms?: number | null;

  /** App/build version that produced the record. */
  app_version?: string | null;
}

/**
 * The live session returned by `check_ip` (and the terminal state of
 * `check_ip_stream`). `result` is the same payload as `get_check_detail`.
 */
export interface CheckSession {
  check_id: string;
  input: string;
  ip: string;
  mode: CheckMode;
  started_at: string;
  finished_at: string | null;
  /** True once every module reached done/error/skipped. */
  complete: boolean;
  result: FullCheckResult | null;
  modules: ModuleState[];
  errors: ProviderError[];
}

/** History row (§10.1 `checks` table). */
export interface CheckSummary {
  check_id: string;
  ip: string;
  mode: CheckMode;
  proxy_host: string | null;
  proxy_port: number | null;
  proxy_protocol: ProxyProtocol | null;
  clean_score: number | null;
  confidence_score: number | null;
  verdict: Verdict | null;
  verdict_reason: string | null;
  checked_at: string;
}

/* ------------------------------------------------------------------ */
/* Provider health (§5.5)                                              */
/* ------------------------------------------------------------------ */

/** Runtime health of one provider (§5.5). */
export interface ProviderHealth {
  provider: string;
  category: Category;
  upstream: string;
  /** green | yellow | red | unknown. */
  state: HealthState;
  /** 0–100. */
  success_rate: number;
  latency_avg_ms: number | null;
  last_error_at: string | null;
  last_error: string | null;
  /** Consecutive failures; ≥5 opens the circuit breaker (§4.3). */
  consecutive_failures: number;
  /** True while the circuit breaker is open. */
  circuit_open: boolean;
  /** When the breaker auto-closes again. */
  circuit_open_until: string | null;
  /** Current effective weight after health decay (§5.5). */
  effective_weight: number;
  configured_weight: number;
  requires_key: boolean;
  /** False when the provider needs a key and none is stored. */
  has_key: boolean;
  enabled: boolean;
  /** True when the free-tier quota is exhausted locally. */
  quota_exhausted: boolean;
  quota_reset_at: string | null;
  /** Local DB version, for local_db providers. */
  db_version: string | null;
  db_updated_at: string | null;
  total_checks: number;
}

/** Local geo database version row (§10.1 `geo_db_versions`). */
export interface GeoDbVersion {
  db_name: string;
  version: string | null;
  updated_at: string | null;
  /** True when older than 60 days (§7.3). */
  stale: boolean;
}

/* ------------------------------------------------------------------ */
/* Settings (§3.3 SettingsPanel, §10.1)                                */
/* ------------------------------------------------------------------ */

/** Per-provider user overrides. Keys live in Credential Manager, never here. */
export interface ProviderSetting {
  provider: string;
  enabled: boolean;
  /** Null = use registry default. */
  timeout_ms: number | null;
  /** Local free-tier rate limit in requests/minute; null = registry default. */
  rate_limit: number | null;
  /** Only ever true/false — the key value itself is never serialised. */
  has_key: boolean;
  /** Stored in Credential Manager under this label; empty when unset. */
  key_label: string;
}

/** Per-group DNSBL toggle (§3.3). */
export interface DnsblGroupSetting {
  group: DnsblGroup;
  enabled: boolean;
}

/** Global app settings. Section-by-section so it can grow without breaking clients. */
export interface Settings {
  /* providers */
  providers: ProviderSetting[];
  /** Global default timeout for providers, 5000–8000 (§4.3). */
  default_timeout_ms: number;
  /** Max concurrent provider requests (§4.3, default 8). */
  max_concurrency: number;
  /** Circuit breaker threshold: failures before opening (§4.3). */
  circuit_failure_threshold: number;
  /** Circuit breaker cool-down in minutes (§4.3). */
  circuit_cooldown_minutes: number;

  /* dnsbl */
  dnsbl_groups: DnsblGroupSetting[];
  /** Master switch for the DNSBL module. */
  dnsbl_enabled: boolean;

  /* history / cache */
  save_history: boolean;
  /** Cache TTLs in hours (§10.2). */
  cache_ttl_geo_hours: number;
  cache_ttl_reputation_hours: number;
  cache_ttl_blacklist_hours: number;
  cache_ttl_abuse_hours: number;

  /* proxy mode */
  leak_check_enabled: boolean;
  speed_check_enabled: boolean;
  /** Chromium executable override; empty = auto-detect (§8.2). */
  browser_path: string;

  /* export / storage */
  export_dir: string;
  app_data_dir: string;
  /** Log retention in days (§11). */
  log_retention_days: number;

  /* ui / meta */
  /** "system" | "vi" — UI is Vietnamese-first (§3). */
  ui_language: string;
  /** false = auto update check disabled. */
  auto_update_check: boolean;
  /** Settings schema version for forward migration. */
  settings_version: number;
}

/* ------------------------------------------------------------------ */
/* Streaming + misc helpers                                            */
/* ------------------------------------------------------------------ */

/** Name of the Tauri event streamed by `check_ip_stream`. */
export const CHECK_PROGRESS_EVENT = "check-progress" as const;

/** Vietnamese display labels for verdicts (UI helper, not wire data). */
export const VERDICT_LABELS: Record<Verdict, string> = {
  "Sạch": "Sạch",
  "Tạm": "Tạm",
  "Nghi ngờ": "Nghi ngờ",
  "Bẩn": "Bẩn",
  "Chưa đủ dữ liệu": "Chưa đủ dữ liệu",
};

/** Category weights from §6.4 — informational; scoring lives in Rust. */
export const CATEGORY_WEIGHTS: Record<string, number> = {
  fraud: 0.35,
  blacklist: 0.25,
  asn: 0.2,
  abuse: 0.1,
  consistency: 0.1,
};

/** Resolved signature map of every Tauri command (§4.2 + Settings extensions). */
export interface CommandMap {
  check_ip: { args: { input: string; options?: CheckOptions | null }; result: CheckSession };
  /**
   * Resolves with the finished session, not `void`.
   *
   * Typing this as `void` forced callers to run the whole pipeline a second
   * time just to learn the `check_id`, and that second run minted a fresh id
   * with `save_to_history: false` — so the id the UI held was never in the
   * cache and export failed with "Không có dữ liệu để xuất". One click is one
   * run; the returned session is the row that was actually persisted.
   */
  check_ip_stream: { args: { input: string; options?: CheckOptions | null }; result: CheckSession };
  get_history: { args: { limit: number }; result: CheckSummary[] };
  get_check_detail: { args: { check_id: string }; result: FullCheckResult };
  export_report: { args: { check_id: string; format: ExportFormat }; result: string };
  get_provider_health: { args: Record<string, never>; result: ProviderHealth[] };
  save_settings: { args: { settings: Settings }; result: void };
  get_settings: { args: Record<string, never>; result: Settings };

  /* ---- Settings panel extensions (§3.3 SettingsPanel, §7.3 geo DB version) ---- */
  save_provider_key: { args: { provider_id: string; key: string }; result: void };
  clear_provider_key: { args: { provider_id: string }; result: void };
  get_geo_db_versions: { args: Record<string, never>; result: GeoDbVersion[] };

  /* ---- shell bridge ---- */
  /**
   * Tauri v2 has no implicit `<a target="_blank">` handler, so external source
   * links were inert in the packaged app. One validated Rust command opens them
   * through the OS instead of granting the webview a shell.
   */
  open_external: { args: { url: string }; result: void };
}

/** Union of every command name — handy for typed log helpers. */
export type CommandName = keyof CommandMap;
