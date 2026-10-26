/**
 * Internationalization (i18n) Core System for IP Checker.
 *
 * Supported languages:
 * - `vi`: Tiếng Việt (Default, preserve exact current application terms)
 * - `en`: English (Professional cyber-security & networking terminology)
 * - `zh`: 简体中文 (Simplified Chinese, natural and industry-standard security terms)
 *
 * Features:
 * - Full type-safety for nested translation keys (e.g., "common.ok", "verdict.sach")
 * - Parameterized template interpolation ({count}, {{count}}, etc.)
 * - Automatic persistence to `localStorage` under `ip_checker_locale`
 * - Cross-component & cross-tab reactivity via custom events & storage events
 * - Safe fallbacks (Language -> Vietnamese default -> key)
 * - Standalone pure translation functions for non-React contexts
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

/* ------------------------------------------------------------------ */
/* Core Types                                                         */
/* ------------------------------------------------------------------ */

export type Language = "vi" | "en" | "zh";

export interface LanguageInfo {
  code: Language;
  name: string;
  nativeName: string;
  flag: string;
}

export const SUPPORTED_LANGUAGES: readonly LanguageInfo[] = [
  { code: "vi", name: "Vietnamese", nativeName: "Tiếng Việt", flag: "🇻🇳" },
  { code: "en", name: "English", nativeName: "English", flag: "🇺🇸" },
  { code: "zh", name: "Simplified Chinese", nativeName: "简体中文", flag: "🇨🇳" },
] as const;

export const DEFAULT_LANGUAGE: Language = "vi";
export const STORAGE_LOCALE_KEY = "ip_checker_locale";
export const LOCALE_CHANGE_EVENT = "ip_checker_locale_changed";

/* ------------------------------------------------------------------ */
/* Dictionary Interface Definition                                    */
/* ------------------------------------------------------------------ */

export interface I18nDictionary {
  common: {
    ok: string;
    cancel: string;
    save: string;
    close: string;
    copy: string;
    copied: string;
    retry: string;
    refresh: string;
    clear: string;
    loading: string;
    search: string;
    all: string;
    yes: string;
    no: string;
    dash: string;
    error: string;
    details: string;
    from_cache: string;
    live: string;
    final_result: string;
  };
  header: {
    title: string;
    subtitle: string;
    scanning: string;
    no_ipc: string;
    no_ipc_hint: string;
    provider_health: string;
    health_tooltip: string;
    providers_good: string;
    providers_slow: string;
    providers_error: string;
    providers_unknown: string;
    settings: string;
    lang_select: string;
  };
  input: {
    placeholder: string;
    scan: string;
    scanning: string;
    paste: string;
    clear: string;
    proxy_auth: string;
    username: string;
    password: string;
    save_history: string;
    mode_proxy: string;
    mode_ip: string;
    invalid_ip: string;
    reserved_ip: string;
    tip_ctrl_k: string;
  };
  verdict: {
    sach: string;
    tam: string;
    nghi_ngo: string;
    ban: string;
    chua_du: string;
    not_checked: string;
    clean_score: string;
    confidence: string;
    weighted_avg: string;
    coverage_consensus: string;
    copy_ip: string;
    copy_verdict: string;
    single_evidence: string;
    conflict_sources: string;
    missing_quorum: string;
    no_verdict_hint: string;
    duration: string;
    live_updating: string;
    final_result: string;
  };
  progress: {
    title: string;
    modules_count: string;
    logs: string;
    waiting: string;
    running: string;
    done: string;
    error: string;
    skipped: string;
    retry_module: string;
  };
  modules: {
    validate: string;
    geo: string;
    asn: string;
    fraud: string;
    abuse: string;
    threat_intel: string;
    dnsbl: string;
    network: string;
    location: string;
    exit_ip: string;
    leak: string;
    speed: string;
    scoring: string;
  };
  skip_reasons: {
    missing_key: string;
    requires_proxy: string;
    quota_exhausted: string;
    disabled: string;
    circuit_open: string;
    not_implemented: string;
    unsupported_ip: string;
  };
  error_kinds: {
    timeout: string;
    http: string;
    parse: string;
    auth: string;
    no_key: string;
    quota: string;
    circuit_open: string;
    network: string;
    unsupported: string;
    invalid_input: string;
    private_ip: string;
    db: string;
    io: string;
    internal: string;
    unknown: string;
  };
  overview: {
    title: string;
    no_ip: string;
    not_checked: string;
    ip: string;
    country_geo: string;
    asn: string;
    isp_org: string;
    prefix: string;
    ip_type: string;
    reverse_dns: string;
    ttl_os: string;
    avg_ping: string;
    risk_detection: string;
    residential: string;
    datacenter: string;
    proxy: string;
    vpn: string;
    tor: string;
    mobile: string;
    matches_isp: string;
    dynamic_ip_note: string;
    city_unreliable: string;
    retry_asn_geo: string;
  };
  ip_types: {
    residential: string;
    datacenter: string;
    mobile: string;
    cgnat: string;
    vpn: string;
    tor: string;
    proxy: string;
    anycast: string;
    edu: string;
    unknown: string;
  };
  location: {
    title: string;
    location_map: string;
    spread_high: string;
    spread_medium: string;
    spread_low: string;
    spread_disputed: string;
    spread_high_exp: string;
    spread_medium_exp: string;
    spread_low_exp: string;
    spread_disputed_exp: string;
    divergence_warning: string;
    coordinates: string;
    no_geo_data: string;
    centroid: string;
  };
  reputation: {
    title: string;
    clean: string;
    suspicious: string;
    bad: string;
    unknown: string;
    fraud_score: string;
    abuse_reports: string;
    quota_exhausted: string;
    no_key: string;
    timeout: string;
    error: string;
    aspects: string;
    no_data: string;
  };
  blacklist: {
    title: string;
    all: string;
    listed: string;
    clean: string;
    timeout: string;
    spamhaus: string;
    commercial: string;
    community: string;
    specialist: string;
    zone: string;
    status: string;
    reason: string;
    checked_at: string;
    no_hits: string;
    listed_count: string;
  };
  network: {
    title: string;
    bgp_prefix: string;
    rir: string;
    registered_country: string;
    upstream: string;
    as_name: string;
    routes: string;
    reverse_dns: string;
    ping: string;
    no_network_data: string;
  };
  leak_speed: {
    title: string;
    webrtc_leak: string;
    dns_leak: string;
    http_leak: string;
    ping: string;
    download_speed: string;
    not_measured_proxy: string;
    no_leak: string;
    leaking: string;
    test_failed: string;
    retry: string;
  };
  evidence: {
    title: string;
    all: string;
    agree_clean: string;
    divergent: string;
    reported_bad: string;
    missing: string;
    search_placeholder: string;
    provider: string;
    upstream: string;
    category: string;
    signal: string;
    score: string;
    latency: string;
    timestamp: string;
    raw_data: string;
    view_source: string;
    no_evidence: string;
  };
  history: {
    title: string;
    search_placeholder: string;
    all_verdicts: string;
    from_cache_label: string;
    recheck: string;
    clear_history: string;
    no_history: string;
    export_json: string;
    export_csv: string;
    copy_report: string;
    health_btn: string;
    search_aria_label: string;
    filter_verdict: string;
    load_cache_tooltip: string;
    recheck_tooltip: string;
    row_aria_label: string;
    reading_history: string;
    cannot_read_history: string;
  };
  settings: {
    title: string;
    save: string;
    close: string;
    saving: string;
    saved: string;
    general: string;
    api_keys: string;
    timeout: string;
    max_concurrency: string;
    failure_threshold: string;
    cooldown_minutes: string;
    dnsbl_groups: string;
    cache_ttl: string;
    export_directory: string;
    browse: string;
    geo_db_versions: string;
    language: string;
    select_language: string;
    unsaved_changes: string;
    synced: string;
    revert: string;
    no_config: string;
    failed_save: string;
    language_hint: string;
    key_security_title: string;
    key_security_detail: string;
    search_provider_placeholder: string;
    search_provider_label: string;
    only_key_required: string;
    no_providers: string;
    no_key_needed: string;
    key_configured: string;
    optional_key: string;
    no_key: string;
    quota_exhausted: string;
    enter_new_key: string;
    optional_key_hint: string;
    paste_api_key: string;
    save_key: string;
    delete_key_title: string;
    free_source: string;
    enable: string;
    toggle_dnsbl_module: string;
    enable_blacklist_module: string;
    dnsbl_votes_note: string;
    export_dir_hint: string;
    no_local_db: string;
    updated_col: string;
    stale_db_badge: string;
    stale_db_warning: string;
    provider_health_title: string;
    no_health_data: string;
    notes_col: string;
    effective_weight_hint: string;
    circuit_open_until: string;
    other_title: string;
    save_history_default: string;
    check_leak_proxy: string;
    check_speed_proxy: string;
    auto_update: string;
    log_retention: string;
  };
  export: {
    export_success: string;
    export_error: string;
    copy_success: string;
    copy_error: string;
    report_summary: string;
    export_json_tooltip: string;
    export_csv_tooltip: string;
    copy_summary_tooltip: string;
    refresh_health_tooltip: string;
    close_notice: string;
  };
  banners: {
    input_not_scannable: string;
    private_ip_stopped: string;
    no_core_connection: string;
    check_failed: string;
    cache_note_title: string;
    cache_note_hint: string;
    cache_detail_title: string;
    cache_detail_hint: string;
    cannot_read_cache: string;
    scanning_wait_export: string;
    no_result_to_export: string;
    no_result_to_copy: string;
    exported_file: string;
    export_file_error: string;
    copied_summary: string;
    clipboard_blocked: string;
    private_no_api: string;
    private_no_api_hint: string;
    rerun_whole_suite: string;
    rerun_whole_suite_hint: string;
    running_no_ipc: string;
    running_no_ipc_hint: string;
    no_network: string;
    no_network_hint: string;
    reload_history: string;
    quota_exhausted_penalty: string;
    quota_penalty_hint: string;
    hard_conflict: string;
  };
  report: {
    summary_title: string;
    verdict_label: string;
    reason_label: string;
    location_label: string;
    asn_label: string;
    ip_type_label: string;
    blacklist_label: string;
    blacklist_hits: string;
    blacklist_clean: string;
    checked_at_label: string;
    sources_label: string;
    from_cache_note: string;
  };
  cards: {
    proxy_only_hint: string;
    sqlite_local: string;
    click_to_view_cache: string;
    offline_viewing_cache: string;
  };
}

/* ------------------------------------------------------------------ */
/* Dictionaries                                                       */
/* ------------------------------------------------------------------ */

export const VI_DICTIONARY: I18nDictionary = {
  common: {
    ok: "OK",
    cancel: "Hủy",
    save: "Lưu",
    close: "Đóng",
    copy: "Copy",
    copied: "✓ Đã copy!",
    retry: "Thử lại",
    refresh: "Làm mới",
    clear: "Xoá",
    loading: "Đang tải…",
    search: "Tìm kiếm",
    all: "Tất cả",
    yes: "Có",
    no: "Không",
    dash: "—",
    error: "Lỗi",
    details: "Chi tiết",
    from_cache: "từ cache",
    live: "đang cập nhật trực tiếp",
    final_result: "kết quả cuối",
  },
  header: {
    title: "IP CHECKER // TERMINAL",
    subtitle: "đa nguồn · đối chiếu vị trí · blacklist trực tiếp",
    scanning: "Đang quét",
    no_ipc: "Không có IPC",
    no_ipc_hint: "Hãy chạy app bằng npm run tauri:dev",
    provider_health: "Provider health",
    health_tooltip: "Trạng thái từng provider (xem chi tiết trong Cài đặt)",
    providers_good: "{count} provider tốt",
    providers_slow: "{count} provider chậm / lỗi tạm thời",
    providers_error: "{count} provider lỗi",
    providers_unknown: "{count} provider không rõ",
    settings: "⚙ Cài đặt",
    lang_select: "Ngôn ngữ",
  },
  input: {
    placeholder: "1.2.3.4  hoặc  1.2.3.4:8080",
    scan: "Scan",
    scanning: "Đang quét…",
    paste: "📋 Dán & Quét",
    clear: "Xoá nhanh (Esc)",
    proxy_auth: "User/pass",
    username: "username (tuỳ chọn)",
    password: "password (tuỳ chọn)",
    save_history: "Lưu vào lịch sử",
    mode_proxy: "Proxy-check",
    mode_ip: "IP-only",
    invalid_ip: "IP không hợp lệ",
    reserved_ip: "IP private / reserved",
    tip_ctrl_k: "Phím tắt Ctrl+K để focus nhanh",
  },
  verdict: {
    sach: "Sạch",
    tam: "Tạm",
    nghi_ngo: "Nghi ngờ",
    ban: "Bẩn",
    chua_du: "Chưa đủ dữ liệu",
    not_checked: "chưa check",
    clean_score: "Clean Score",
    confidence: "Confidence",
    weighted_avg: "trung bình có trọng số",
    coverage_consensus: "độ phủ & đồng thuận",
    copy_ip: "Click để copy địa chỉ IP",
    copy_verdict: "Click để copy kết luận",
    single_evidence: "bằng chứng đơn lẻ",
    conflict_sources: "xung đột nguồn ×{count}",
    missing_quorum: "thiếu quorum",
    no_verdict_hint: "Chưa có kết luận — nhập IP và bấm Scan.",
    duration: "Thời gian: {duration}s",
    live_updating: "đang cập nhật trực tiếp",
    final_result: "kết quả cuối",
  },
  progress: {
    title: "Tiến trình quét",
    modules_count: "{done}/{total} module",
    logs: "Log tiến trình",
    waiting: "Chờ",
    running: "Đang chạy",
    done: "Xong",
    error: "Lỗi",
    skipped: "Bỏ qua",
    retry_module: "Thử lại module {module}",
  },
  modules: {
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
  },
  skip_reasons: {
    missing_key: "thiếu API key",
    requires_proxy: "cần nhập proxy",
    quota_exhausted: "hết quota",
    disabled: "đã tắt trong Cài đặt",
    circuit_open: "provider tạm ngắt (lỗi liên tiếp)",
    not_implemented: "chưa hỗ trợ",
    unsupported_ip: "không áp dụng cho IP này",
  },
  error_kinds: {
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
    unknown: "lỗi không rõ",
  },
  overview: {
    title: "Tổng quan",
    no_ip: "chưa có IP",
    not_checked: "Chưa check IP nào.",
    ip: "IP",
    country_geo: "Quốc gia (geo)",
    asn: "ASN",
    isp_org: "ISP / tổ chức",
    prefix: "Prefix",
    ip_type: "Loại IP",
    reverse_dns: "Reverse DNS",
    ttl_os: "TTL / OS",
    avg_ping: "Ping TB",
    risk_detection: "Nhận diện rủi ro",
    residential: "Residential",
    datacenter: "Server / Datacenter",
    proxy: "Proxy",
    vpn: "VPN",
    tor: "Tor Exit Node",
    mobile: "Mobile Network",
    matches_isp: "Khớp ISP",
    dynamic_ip_note: "Thường gặp ở IP dân cư động",
    city_unreliable: "Loại IP này làm vị trí thành phố kém tin cậy (§7.5)",
    retry_asn_geo: "↻ Thử lại ASN / geo",
  },
  ip_types: {
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
  },
  location: {
    title: "Định vị",
    location_map: "Bản đồ vị trí",
    spread_high: "Nguồn chụm < 50 km",
    spread_medium: "Nguồn lệch 50–200 km",
    spread_low: "Nguồn lệch > 200 km",
    spread_disputed: "Tranh chấp",
    spread_high_exp: "Các nguồn chụm trong 50 km — thành phố tin cậy cao (§7.3).",
    spread_medium_exp: "Các nguồn lệch 50–200 km — thành phố chỉ nên tham khảo (§7.3).",
    spread_low_exp: "Các nguồn lệch hơn 200 km — không chốt thành phố, chỉ chốt quốc gia/vùng (§7.3).",
    spread_disputed_exp: "Các nguồn tranh chấp nhau — không chốt được thành phố (§7.3).",
    divergence_warning: "Các nguồn lệch nhau rất lớn (> 2.000 km)",
    coordinates: "Toạ độ",
    no_geo_data: "Chưa có nguồn geo nào trả về toạ độ. Không vẽ bản đồ để tránh tạo cảm giác vị trí đã được xác nhận.",
    centroid: "centroid",
  },
  reputation: {
    title: "Reputation",
    clean: "Sạch",
    suspicious: "Nghi ngờ",
    bad: "Bẩn",
    unknown: "Không rõ",
    fraud_score: "Score gốc",
    abuse_reports: "Báo cáo abuse",
    quota_exhausted: "Hết quota free",
    no_key: "Thiếu key",
    timeout: "Timeout",
    error: "Lỗi",
    aspects: "fraud · abuse · threat",
    no_data: "Chưa có kết quả reputation.",
  },
  blacklist: {
    title: "Blacklist",
    all: "Tất cả nhóm",
    listed: "● Chỉ dính",
    clean: "không dính",
    timeout: "Timeout",
    spamhaus: "Spamhaus",
    commercial: "Thương mại",
    community: "Cộng đồng",
    specialist: "Chuyên biệt",
    zone: "Zone",
    status: "Trạng thái",
    reason: "Lý do",
    checked_at: "Lúc",
    no_hits: "không dính list nào",
    listed_count: "{count} list dính",
  },
  network: {
    title: "Mạng",
    bgp_prefix: "Prefix BGP",
    rir: "RIR",
    registered_country: "Quốc gia đăng ký",
    upstream: "Upstream",
    as_name: "Tên AS",
    routes: "Traceroute",
    reverse_dns: "Reverse DNS",
    ping: "Ping",
    no_network_data: "Chưa có dữ liệu mạng. IP-only vẫn đo được ping và reverse DNS.",
  },
  leak_speed: {
    title: "Leak + Tốc độ",
    webrtc_leak: "WebRTC leak",
    dns_leak: "DNS leak",
    http_leak: "HTTP leak",
    ping: "Ping proxy",
    download_speed: "Tốc độ tải",
    not_measured_proxy: "Chưa đo được — cần nhập proxy",
    no_leak: "Không leak",
    leaking: "có dấu hiệu leak",
    test_failed: "Đo thất bại",
    retry: "Thử lại leak / tốc độ",
  },
  evidence: {
    title: "Bằng chứng",
    all: "Tất cả",
    agree_clean: "Đồng ý sạch",
    divergent: "Lệch",
    reported_bad: "Báo bẩn",
    missing: "Thiếu",
    search_placeholder: "Lọc provider, upstream, category…",
    provider: "Provider",
    upstream: "Upstream",
    category: "Category",
    signal: "Tín hiệu",
    score: "Score",
    latency: "Độ trễ",
    timestamp: "Lúc",
    raw_data: "Dữ liệu gốc",
    view_source: "Nguồn",
    no_evidence: "Chưa có bằng chứng nào.",
  },
  history: {
    title: "Lịch sử",
    search_placeholder: "Tìm IP / proxy…",
    all_verdicts: "Tất cả ({count})",
    from_cache_label: "từ cache, check lúc {time}",
    recheck: "Check lại",
    clear_history: "Xoá lịch sử",
    no_history: "Chưa có lịch sử check.",
    export_json: "Xuất JSON",
    export_csv: "Xuất CSV",
    copy_report: "Copy báo cáo",
    health_btn: "↻ Health",
    search_aria_label: "Tìm trong lịch sử",
    filter_verdict: "Lọc theo kết luận",
    load_cache_tooltip: "Load lại kết quả này từ cache",
    recheck_tooltip: "Check lại — bỏ qua cache, gọi mới (§10.2)",
    row_aria_label: "Xem lại {target}, kết luận {verdict}, clean {clean}/100, tin cậy {confidence}%, {mode}, lúc {time}",
    reading_history: "Đang đọc lịch sử…",
    cannot_read_history: "Không đọc được lịch sử: {error}",
  },
  settings: {
    title: "Cài đặt",
    save: "Lưu cài đặt",
    close: "Đóng",
    saving: "Đang lưu…",
    saved: "Đã lưu!",
    general: "Cài đặt chung",
    api_keys: "API Keys",
    timeout: "Timeout (ms)",
    max_concurrency: "Số luồng tối đa",
    failure_threshold: "Ngưỡng lỗi ngắt mạch",
    cooldown_minutes: "Thời gian phục hồi (phút)",
    dnsbl_groups: "Nhóm DNSBL",
    cache_ttl: "Thời gian lưu cache (phút)",
    export_directory: "Thư mục xuất file",
    browse: "Duyệt…",
    geo_db_versions: "Phiên bản Geo DB",
    language: "Ngôn ngữ",
    select_language: "Chọn ngôn ngữ hiển thị",
    unsaved_changes: "có thay đổi chưa lưu",
    synced: "đã đồng bộ",
    revert: "Hoàn tác",
    no_config: "Chưa đọc được cấu hình (không có kết nối tới Tauri core).",
    failed_save: "Không lưu được cài đặt",
    language_hint: "Chuyển đổi ngôn ngữ hiển thị giao diện và xuất báo cáo.",
    key_security_title: "Key lưu trong Windows Credential Manager",
    key_security_detail: "Ô nhập luôn trống sau khi lưu; app chỉ hiển thị trạng thái có key hay chưa.",
    search_provider_placeholder: "Tìm provider (vd: ipqs, abuseipdb, virustotal)…",
    search_provider_label: "Tìm kiếm provider",
    only_key_required: "Chỉ hiện nguồn cần API key",
    no_providers: "Chưa có provider nào trong registry.",
    no_key_needed: "không cần key",
    key_configured: "đã có key",
    optional_key: "key tuỳ chọn",
    no_key: "chưa có key",
    quota_exhausted: "hết quota",
    enter_new_key: "nhập key mới để thay",
    optional_key_hint: "key tuỳ chọn (tăng quota)",
    paste_api_key: "dán API key",
    save_key: "Lưu key",
    delete_key_title: "Xoá key khỏi Credential Manager",
    free_source: "Nguồn miễn phí / không dùng key",
    enable: "bật",
    toggle_dnsbl_module: "Bật/tắt toàn bộ module blacklist",
    enable_blacklist_module: "bật module blacklist",
    dnsbl_votes_note: "Mỗi nhóm là 1 phiếu, không phải mỗi zone (§5.3).",
    export_dir_hint: "JSON/CSV ghi vào thư mục này, không chứa API key hay credential (§10.3).",
    no_local_db: "Chưa cài DB local nào — triangulation chỉ dùng API.",
    updated_col: "Cập nhật",
    stale_db_badge: "cũ > 60 ngày",
    stale_db_warning: "{count} DB quá 60 ngày — điểm tin cậy vị trí bị trừ (§7.3). Cập nhật trong bản release mới.",
    provider_health_title: "Health từng provider",
    no_health_data: "Chưa có dữ liệu health.",
    notes_col: "Ghi chú",
    effective_weight_hint: "Trọng số hiệu dụng sau khi bị giảm vì lỗi (§5.5)",
    circuit_open_until: "tạm ngắt tới {time}",
    other_title: "Khác",
    save_history_default: "lưu lịch sử mặc định",
    check_leak_proxy: "đo leak ở proxy mode",
    check_speed_proxy: "đo tốc độ ở proxy mode",
    auto_update: "tự kiểm tra cập nhật",
    log_retention: "log giữ {days} ngày",
  },
  export: {
    export_success: "Đã xuất file thành công: {path}",
    export_error: "Xuất file thất bại: {error}",
    copy_success: "Đã copy báo cáo vào clipboard!",
    copy_error: "Không thể copy báo cáo",
    report_summary: "Báo cáo tóm tắt",
    export_json_tooltip: "Xuất toàn bộ FullCheckResult kèm evidence (§10.3)",
    export_csv_tooltip: "1 dòng / 1 IP (§10.3)",
    copy_summary_tooltip: "Copy báo cáo tóm tắt để dán chat",
    refresh_health_tooltip: "Đọc lại health từng provider",
    close_notice: "Đóng thông báo",
  },
  banners: {
    input_not_scannable: "Không check được input này",
    private_ip_stopped: "IP private / reserved — đã dừng",
    no_core_connection: "Không có kết nối tới core / mạng",
    check_failed: "Check thất bại",
    cache_note_title: "Kết quả từ cache ({time})",
    cache_note_hint: "Bấm “Check lại” ở lịch sử nếu muốn gọi mới hoàn toàn (bỏ qua cache).",
    cache_detail_title: "Kết quả lưu trong cache ({time})",
    cache_detail_hint: "Đang xem bản lưu trong cache — không phải check mới. Bấm “Check lại” để gọi lại thật.",
    cannot_read_cache: "Không đọc được bản lưu",
    scanning_wait_export: "Đang quét — đợi kết quả cuối rồi hãy xuất.",
    no_result_to_export: "Chưa có kết quả để xuất.",
    no_result_to_copy: "Chưa có kết quả để copy.",
    exported_file: "Đã ghi {format}: {file}",
    export_file_error: "Xuất {format} lỗi: {error}",
    copied_summary: "Đã copy báo cáo tóm tắt vào clipboard.",
    clipboard_blocked: "Không copy được — clipboard bị chặn.",
    private_no_api: "IP private / reserved — không gọi API",
    private_no_api_hint: "Dải private/loopback/reserved không có dữ liệu công khai để đối chiếu. Hãy nhập IP public.",
    rerun_whole_suite: "Chạy lại cả bộ (yêu cầu từ module {module})",
    rerun_whole_suite_hint: "Backend chưa chạy được riêng 1 module — lần này gọi lại toàn bộ và không ghi thêm lịch sử.",
    running_no_ipc: "Đang chạy ngoài Tauri (không có IPC)",
    running_no_ipc_hint: "Mở app bằng `npm run tauri:dev` để gọi được các command. Giao diện vẫn xem được nhưng không check được IP thật.",
    no_network: "Không có mạng",
    no_network_hint: "Không gọi được provider. Bạn vẫn xem được lịch sử / cache ở bảng bên dưới.",
    reload_history: "Tải lại lịch sử",
    quota_exhausted_penalty: "Hết quota / thiếu key",
    quota_penalty_hint: "{notice} Verdict có thể bị chặn ở mức “Chưa đủ dữ liệu” theo §6.3.",
    hard_conflict: "Xung đột nguồn (hard)",
  },
  report: {
    summary_title: "BÁO CÁO TÓM TẮT IP CHECKER",
    verdict_label: "Kết luận",
    reason_label: "Lý do",
    location_label: "Vị trí",
    asn_label: "ASN / Tổ chức",
    ip_type_label: "Loại IP",
    blacklist_label: "Blacklist",
    blacklist_hits: "{count} list dính",
    blacklist_clean: "không dính",
    checked_at_label: "Check lúc",
    sources_label: "Nguồn",
    from_cache_note: " (từ cache)",
  },
  cards: {
    proxy_only_hint: "proxy only",
    sqlite_local: "SQLite local",
    click_to_view_cache: "bấm 1 dòng để load từ cache",
    offline_viewing_cache: "đang offline — vẫn xem được cache",
  },
};

export const EN_DICTIONARY: I18nDictionary = {
  common: {
    ok: "OK",
    cancel: "Cancel",
    save: "Save",
    close: "Close",
    copy: "Copy",
    copied: "✓ Copied!",
    retry: "Retry",
    refresh: "Refresh",
    clear: "Clear",
    loading: "Loading…",
    search: "Search",
    all: "All",
    yes: "Yes",
    no: "No",
    dash: "—",
    error: "Error",
    details: "Details",
    from_cache: "from cache",
    live: "live updating",
    final_result: "final result",
  },
  header: {
    title: "IP CHECKER // TERMINAL",
    subtitle: "multi-source · geo-triangulation · direct blacklist",
    scanning: "Scanning",
    no_ipc: "No IPC",
    no_ipc_hint: "Run the application with npm run tauri:dev",
    provider_health: "Provider Health",
    health_tooltip: "Health status of each provider (view details in Settings)",
    providers_good: "{count} providers healthy",
    providers_slow: "{count} providers slow / degraded",
    providers_error: "{count} providers error",
    providers_unknown: "{count} providers unknown",
    settings: "⚙ Settings",
    lang_select: "Language",
  },
  input: {
    placeholder: "1.2.3.4  or  1.2.3.4:8080",
    scan: "Scan",
    scanning: "Scanning…",
    paste: "📋 Paste & Scan",
    clear: "Clear (Esc)",
    proxy_auth: "User/pass",
    username: "username (optional)",
    password: "password (optional)",
    save_history: "Save to history",
    mode_proxy: "Proxy-check",
    mode_ip: "IP-only",
    invalid_ip: "Invalid IP address",
    reserved_ip: "Private / reserved IP",
    tip_ctrl_k: "Shortcut Ctrl+K to quickly focus",
  },
  verdict: {
    sach: "Clean",
    tam: "Fair",
    nghi_ngo: "Suspicious",
    ban: "Bad",
    chua_du: "Insufficient Data",
    not_checked: "not checked",
    clean_score: "Clean Score",
    confidence: "Confidence",
    weighted_avg: "weighted average",
    coverage_consensus: "coverage & consensus",
    copy_ip: "Click to copy IP address",
    copy_verdict: "Click to copy verdict",
    single_evidence: "single evidence",
    conflict_sources: "source conflict ×{count}",
    missing_quorum: "missing quorum",
    no_verdict_hint: "No verdict yet — enter IP and click Scan.",
    duration: "Duration: {duration}s",
    live_updating: "live updating",
    final_result: "final result",
  },
  progress: {
    title: "Scan Progress",
    modules_count: "{done}/{total} modules",
    logs: "Scan logs",
    waiting: "Pending",
    running: "Running",
    done: "Done",
    error: "Error",
    skipped: "Skipped",
    retry_module: "Retry module {module}",
  },
  modules: {
    validate: "IP Validation",
    geo: "Geolocation",
    asn: "ASN",
    fraud: "Fraud Score",
    abuse: "Abuse Reports",
    threat_intel: "Threat Intel",
    dnsbl: "DNSBL Blacklist",
    network: "Network",
    location: "Location Engine",
    exit_ip: "Exit IP",
    leak: "Proxy Leak",
    speed: "Speed Test",
    scoring: "Scoring",
  },
  skip_reasons: {
    missing_key: "missing API key",
    requires_proxy: "requires proxy",
    quota_exhausted: "quota exhausted",
    disabled: "disabled in Settings",
    circuit_open: "circuit open (consecutive errors)",
    not_implemented: "not implemented",
    unsupported_ip: "unsupported for this IP",
  },
  error_kinds: {
    timeout: "timeout",
    http: "HTTP error",
    parse: "invalid data",
    auth: "invalid / missing API key",
    no_key: "missing API key",
    quota: "quota exceeded",
    circuit_open: "circuit open",
    network: "network error",
    unsupported: "unsupported",
    invalid_input: "invalid input",
    private_ip: "private / reserved IP",
    db: "database error",
    io: "file I/O error",
    internal: "internal error",
    unknown: "unknown error",
  },
  overview: {
    title: "Overview",
    no_ip: "no IP",
    not_checked: "No IP has been checked yet.",
    ip: "IP",
    country_geo: "Country (Geo)",
    asn: "ASN",
    isp_org: "ISP / Organization",
    prefix: "Prefix",
    ip_type: "IP Type",
    reverse_dns: "Reverse DNS",
    ttl_os: "TTL / OS",
    avg_ping: "Avg Ping",
    risk_detection: "Risk Detection",
    residential: "Residential",
    datacenter: "Server / Datacenter",
    proxy: "Proxy",
    vpn: "VPN",
    tor: "Tor Exit Node",
    mobile: "Mobile Network",
    matches_isp: "Matches ISP",
    dynamic_ip_note: "Common for dynamic residential IPs",
    city_unreliable: "This IP type makes city-level geolocation unreliable (§7.5)",
    retry_asn_geo: "↻ Retry ASN / Geo",
  },
  ip_types: {
    residential: "Residential",
    datacenter: "Datacenter / hosting",
    mobile: "Mobile",
    cgnat: "CGNAT",
    vpn: "VPN",
    tor: "Tor",
    proxy: "Proxy",
    anycast: "Anycast",
    edu: "Education / Research",
    unknown: "Unknown",
  },
  location: {
    title: "Location",
    location_map: "Location Map",
    spread_high: "Sources cluster < 50 km",
    spread_medium: "Sources diverge 50–200 km",
    spread_low: "Sources diverge > 200 km",
    spread_disputed: "Disputed",
    spread_high_exp: "Sources cluster within 50 km — high city confidence (§7.3).",
    spread_medium_exp: "Sources diverge 50–200 km — city should only be reference (§7.3).",
    spread_low_exp: "Sources diverge > 200 km — city unconfirmed, only country/region confirmed (§7.3).",
    spread_disputed_exp: "Sources dispute each other — unable to confirm city (§7.3).",
    divergence_warning: "Major divergence between sources (> 2,000 km)",
    coordinates: "Coordinates",
    no_geo_data: "No geo source returned coordinates. Map is omitted to avoid implying a confirmed location.",
    centroid: "centroid",
  },
  reputation: {
    title: "Reputation",
    clean: "Clean",
    suspicious: "Suspicious",
    bad: "Bad",
    unknown: "Unknown",
    fraud_score: "Raw Score",
    abuse_reports: "Abuse Reports",
    quota_exhausted: "Free quota exhausted",
    no_key: "Missing key",
    timeout: "Timeout",
    error: "Error",
    aspects: "fraud · abuse · threat",
    no_data: "No reputation results yet.",
  },
  blacklist: {
    title: "Blacklist",
    all: "All Groups",
    listed: "● Listed only",
    clean: "clean",
    timeout: "Timeout",
    spamhaus: "Spamhaus",
    commercial: "Commercial",
    community: "Community",
    specialist: "Specialist",
    zone: "Zone",
    status: "Status",
    reason: "Reason",
    checked_at: "Checked",
    no_hits: "no lists hit",
    listed_count: "{count} lists hit",
  },
  network: {
    title: "Network",
    bgp_prefix: "BGP Prefix",
    rir: "RIR",
    registered_country: "Registered Country",
    upstream: "Upstream",
    as_name: "AS Name",
    routes: "Traceroute",
    reverse_dns: "Reverse DNS",
    ping: "Ping",
    no_network_data: "No network data available. IP-only mode still measures ping and reverse DNS.",
  },
  leak_speed: {
    title: "Leak & Speed",
    webrtc_leak: "WebRTC leak",
    dns_leak: "DNS leak",
    http_leak: "HTTP leak",
    ping: "Proxy ping",
    download_speed: "Download speed",
    not_measured_proxy: "Not measured — proxy required",
    no_leak: "No leak",
    leaking: "leak detected",
    test_failed: "Test failed",
    retry: "Retry leak / speed",
  },
  evidence: {
    title: "Evidence",
    all: "All",
    agree_clean: "Agree clean",
    divergent: "Divergent",
    reported_bad: "Reported bad",
    missing: "Missing",
    search_placeholder: "Filter provider, upstream, category…",
    provider: "Provider",
    upstream: "Upstream",
    category: "Category",
    signal: "Signal",
    score: "Score",
    latency: "Latency",
    timestamp: "Time",
    raw_data: "Raw Data",
    view_source: "Source",
    no_evidence: "No evidence recorded yet.",
  },
  history: {
    title: "History",
    search_placeholder: "Search IP / proxy…",
    all_verdicts: "All ({count})",
    from_cache_label: "from cache, checked at {time}",
    recheck: "Recheck",
    clear_history: "Clear history",
    no_history: "No check history yet.",
    export_json: "Export JSON",
    export_csv: "Export CSV",
    copy_report: "Copy Report",
    health_btn: "↻ Health",
    search_aria_label: "Search history",
    filter_verdict: "Filter by verdict",
    load_cache_tooltip: "Load this result from cache",
    recheck_tooltip: "Recheck — bypass cache and query live (§10.2)",
    row_aria_label: "Review {target}, verdict {verdict}, clean {clean}/100, confidence {confidence}%, {mode}, at {time}",
    reading_history: "Loading history…",
    cannot_read_history: "Cannot read history: {error}",
  },
  settings: {
    title: "Settings",
    save: "Save settings",
    close: "Close",
    saving: "Saving…",
    saved: "Saved!",
    general: "General Settings",
    api_keys: "API Keys",
    timeout: "Timeout (ms)",
    max_concurrency: "Max Concurrency",
    failure_threshold: "Circuit Breaker Threshold",
    cooldown_minutes: "Cooldown Period (min)",
    dnsbl_groups: "DNSBL Groups",
    cache_ttl: "Cache TTL (min)",
    export_directory: "Export Directory",
    browse: "Browse…",
    geo_db_versions: "Geo DB Versions",
    language: "Language",
    select_language: "Select display language",
    unsaved_changes: "unsaved changes",
    synced: "synced",
    revert: "Revert",
    no_config: "Cannot load configuration (no connection to Tauri core).",
    failed_save: "Failed to save settings",
    language_hint: "Switch application interface and generated report language.",
    key_security_title: "Keys securely stored in Windows Credential Manager",
    key_security_detail: "Input field is always cleared after saving; app only shows whether a key is configured.",
    search_provider_placeholder: "Search provider (e.g. ipqs, abuseipdb)…",
    search_provider_label: "Search provider",
    only_key_required: "Show key-required sources only",
    no_providers: "No providers registered in registry.",
    no_key_needed: "no key needed",
    key_configured: "key configured",
    optional_key: "optional key",
    no_key: "no key",
    quota_exhausted: "quota exhausted",
    enter_new_key: "enter new key to replace",
    optional_key_hint: "optional key (higher quota)",
    paste_api_key: "paste API key",
    save_key: "Save key",
    delete_key_title: "Delete key from Credential Manager",
    free_source: "Free source / no key required",
    enable: "enable",
    toggle_dnsbl_module: "Toggle entire DNSBL module",
    enable_blacklist_module: "enable blacklist module",
    dnsbl_votes_note: "Each group counts as 1 vote, not each individual zone (§5.3).",
    export_dir_hint: "JSON/CSV written to this folder, contains no API keys or credentials (§10.3).",
    no_local_db: "No local DB installed — triangulation uses APIs only.",
    updated_col: "Updated",
    stale_db_badge: "stale > 60 days",
    stale_db_warning: "{count} DB older than 60 days — location confidence penalty applied (§7.3). Update in newer release.",
    provider_health_title: "Provider Health",
    no_health_data: "No health data available.",
    notes_col: "Notes",
    effective_weight_hint: "Effective weight after error penalties (§5.5)",
    circuit_open_until: "circuit open until {time}",
    other_title: "Other",
    save_history_default: "save history by default",
    check_leak_proxy: "check leak in proxy mode",
    check_speed_proxy: "check speed in proxy mode",
    auto_update: "auto-check for updates",
    log_retention: "keep logs for {days} days",
  },
  export: {
    export_success: "File exported successfully: {path}",
    export_error: "Export failed: {error}",
    copy_success: "Report copied to clipboard!",
    copy_error: "Failed to copy report",
    report_summary: "Summary Report",
    export_json_tooltip: "Export complete FullCheckResult with evidence (§10.3)",
    export_csv_tooltip: "1 row / 1 IP (§10.3)",
    copy_summary_tooltip: "Copy summary report to paste into chat",
    refresh_health_tooltip: "Refresh health status for each provider",
    close_notice: "Close notice",
  },
  banners: {
    input_not_scannable: "Cannot check this input",
    private_ip_stopped: "Private / reserved IP — stopped",
    no_core_connection: "No connection to core / network",
    check_failed: "Check failed",
    cache_note_title: "Cached result ({time})",
    cache_note_hint: "Click 'Recheck' in history to perform a fresh scan.",
    cache_detail_title: "Cached result ({time})",
    cache_detail_hint: "Viewing cached result — not a live check. Click 'Recheck' for fresh data.",
    cannot_read_cache: "Cannot read cached record",
    scanning_wait_export: "Scanning in progress — wait for final result before exporting.",
    no_result_to_export: "No results available to export.",
    no_result_to_copy: "No results available to copy.",
    exported_file: "Exported {format}: {file}",
    export_file_error: "Export {format} error: {error}",
    copied_summary: "Summary report copied to clipboard.",
    clipboard_blocked: "Failed to copy — clipboard access blocked.",
    private_no_api: "Private / reserved IP — no API called",
    private_no_api_hint: "Private/loopback/reserved ranges do not have public data to correlate. Please enter a public IP.",
    rerun_whole_suite: "Rerunning entire suite (requested from module {module})",
    rerun_whole_suite_hint: "Backend cannot run an isolated single module — rerunning all modules without saving duplicate history.",
    running_no_ipc: "Running outside Tauri (no IPC)",
    running_no_ipc_hint: "Launch app via `npm run tauri:dev` to enable IPC commands. UI is viewable but live IP check is disabled.",
    no_network: "No network connection",
    no_network_hint: "Cannot reach providers. You can still view history and cache below.",
    reload_history: "Reload history",
    quota_exhausted_penalty: "Quota exhausted / Missing key",
    quota_penalty_hint: "{notice} Verdict may be capped at 'Insufficient Data' per §6.3.",
    hard_conflict: "Source conflict (hard)",
  },
  report: {
    summary_title: "IP CHECKER SUMMARY REPORT",
    verdict_label: "Verdict",
    reason_label: "Reason",
    location_label: "Location",
    asn_label: "ASN / Organization",
    ip_type_label: "IP Type",
    blacklist_label: "Blacklist",
    blacklist_hits: "{count} blacklists listed",
    blacklist_clean: "clean (no hits)",
    checked_at_label: "Checked at",
    sources_label: "Sources",
    from_cache_note: " (from cache)",
  },
  cards: {
    proxy_only_hint: "proxy only",
    sqlite_local: "SQLite local",
    click_to_view_cache: "click a row to load from cache",
    offline_viewing_cache: "offline — viewing cached data",
  },
};

export const ZH_DICTIONARY: I18nDictionary = {
  common: {
    ok: "确定",
    cancel: "取消",
    save: "保存",
    close: "关闭",
    copy: "复制",
    copied: "✓ 已复制！",
    retry: "重试",
    refresh: "刷新",
    clear: "清空",
    loading: "加载中…",
    search: "搜索",
    all: "全部",
    yes: "是",
    no: "否",
    dash: "—",
    error: "错误",
    details: "详情",
    from_cache: "来自缓存",
    live: "实时更新中",
    final_result: "最终结果",
  },
  header: {
    title: "IP CHECKER // TERMINAL",
    subtitle: "多源对比 · 位置三角校准 · 实时黑名单",
    scanning: "正在扫描",
    no_ipc: "无 IPC 连接",
    no_ipc_hint: "请使用 npm run tauri:dev 运行应用",
    provider_health: "提供商健康度",
    health_tooltip: "各数据提供商运行状态（在设置中查看详情）",
    providers_good: "{count} 个正常",
    providers_slow: "{count} 个较慢 / 临时异常",
    providers_error: "{count} 个故障",
    providers_unknown: "{count} 个未知",
    settings: "⚙ 设置",
    lang_select: "语言",
  },
  input: {
    placeholder: "1.2.3.4  或  1.2.3.4:8080",
    scan: "扫描",
    scanning: "正在扫描…",
    paste: "📋 粘贴并扫描",
    clear: "快速清空 (Esc)",
    proxy_auth: "认证信息",
    username: "用户名 (可选)",
    password: "密码 (可选)",
    save_history: "保存到历史",
    mode_proxy: "代理检测",
    mode_ip: "纯 IP 检测",
    invalid_ip: "无效 IP 地址",
    reserved_ip: "私有 / 保留 IP",
    tip_ctrl_k: "快捷键 Ctrl+K 快速定位聚焦",
  },
  verdict: {
    sach: "纯净",
    tam: "一般",
    nghi_ngo: "可疑",
    ban: "恶意",
    chua_du: "数据不足",
    not_checked: "未检测",
    clean_score: "纯净度评分",
    confidence: "置信度",
    weighted_avg: "加权平均",
    coverage_consensus: "覆盖率与共识",
    copy_ip: "点击复制 IP 地址",
    copy_verdict: "点击复制检测结论",
    single_evidence: "单一证据",
    conflict_sources: "源冲突 ×{count}",
    missing_quorum: "缺少 Quorum 共识",
    no_verdict_hint: "暂无结论 — 请输入 IP 并点击扫描。",
    duration: "耗时: {duration}s",
    live_updating: "实时更新中",
    final_result: "最终结果",
  },
  progress: {
    title: "扫描进度",
    modules_count: "{done}/{total} 个模块",
    logs: "进度日志",
    waiting: "等待中",
    running: "运行中",
    done: "完成",
    error: "错误",
    skipped: "已跳过",
    retry_module: "重试模块 {module}",
  },
  modules: {
    validate: "IP 校验",
    geo: "地理定位",
    asn: "ASN",
    fraud: "欺诈评分",
    abuse: "滥用举报",
    threat_intel: "威胁情报",
    dnsbl: "黑名单 (DNSBL)",
    network: "网络",
    location: "位置共识引擎",
    exit_ip: "出口 IP",
    leak: "代理泄漏",
    speed: "网络测速",
    scoring: "综合评分",
  },
  skip_reasons: {
    missing_key: "缺少 API Key",
    requires_proxy: "需要代理",
    quota_exhausted: "配额耗尽",
    disabled: "已在设置中禁用",
    circuit_open: "临时熔断 (连续错误)",
    not_implemented: "尚未实现",
    unsupported_ip: "不适用于此 IP",
  },
  error_kinds: {
    timeout: "超时",
    http: "HTTP 错误",
    parse: "数据格式无效",
    auth: "API Key 错误或失效",
    no_key: "缺少 API Key",
    quota: "配额已超限",
    circuit_open: "服务已熔断",
    network: "网络断开",
    unsupported: "不支持",
    invalid_input: "输入无效",
    private_ip: "私有 / 保留 IP",
    db: "数据库错误",
    io: "文件读写错误",
    internal: "内部错误",
    unknown: "未知错误",
  },
  overview: {
    title: "总览",
    no_ip: "未指定 IP",
    not_checked: "尚未检测任何 IP。",
    ip: "IP",
    country_geo: "国家/地区 (地理)",
    asn: "ASN",
    isp_org: "运营商 / 组织",
    prefix: "网段前缀 (Prefix)",
    ip_type: "IP 类型",
    reverse_dns: "反向 DNS (PTR)",
    ttl_os: "TTL / 操作系统",
    avg_ping: "平均延迟",
    risk_detection: "风险识别",
    residential: "原生住宅",
    datacenter: "服务器 / 机房",
    proxy: "代理节点",
    vpn: "VPN 专网",
    tor: "Tor 出口节点",
    mobile: "移动蜂窝网络",
    matches_isp: "匹配 ISP",
    dynamic_ip_note: "常见于动态家庭宽带 IP",
    city_unreliable: "此类 IP 会导致城市级定位不可靠 (§7.5)",
    retry_asn_geo: "↻ 重试 ASN / 地理定位",
  },
  ip_types: {
    residential: "原生住宅 (Residential)",
    datacenter: "数据中心 / 托管 (Datacenter)",
    mobile: "移动蜂窝网络 (Mobile)",
    cgnat: "运营商级 NAT (CGNAT)",
    vpn: "虚拟专用网 (VPN)",
    tor: "Tor 匿名网络",
    proxy: "代理网络 (Proxy)",
    anycast: "任播网络 (Anycast)",
    edu: "教育 / 科研机构",
    unknown: "未知类型",
  },
  location: {
    title: "地理定位",
    location_map: "位置地图",
    spread_high: "各源聚合 < 50 km",
    spread_medium: "各源偏差 50–200 km",
    spread_low: "各源偏差 > 200 km",
    spread_disputed: "存在争议",
    spread_high_exp: "各数据源聚类在 50 km 以内 — 城市定位高度可信 (§7.3)。",
    spread_medium_exp: "各数据源偏差 50–200 km — 城市信息仅供参考 (§7.3)。",
    spread_low_exp: "各数据源偏差大于 200 km — 无法确定城市，仅确认国家/地区 (§7.3)。",
    spread_disputed_exp: "数据源之间存在互斥争议 — 无法确定城市 (§7.3)。",
    divergence_warning: "数据源之间偏差极大 (> 2,000 km)",
    coordinates: "经纬度坐标",
    no_geo_data: "暂无地理源返回坐标。未绘制地图以避免造成已确认位置的误导。",
    centroid: "质心 (centroid)",
  },
  reputation: {
    title: "信誉声誉",
    clean: "纯净",
    suspicious: "可疑",
    bad: "恶意",
    unknown: "未知",
    fraud_score: "原始评分",
    abuse_reports: "滥用举报",
    quota_exhausted: "免费配额已用尽",
    no_key: "缺少 Key",
    timeout: "超时",
    error: "错误",
    aspects: "欺诈 · 滥用 · 威胁",
    no_data: "暂无信誉检测数据。",
  },
  blacklist: {
    title: "黑名单",
    all: "全部黑名单组",
    listed: "● 仅命中",
    clean: "未列入",
    timeout: "超时",
    spamhaus: "Spamhaus",
    commercial: "商业级",
    community: "社区级",
    specialist: "专业级",
    zone: "检测列表 (Zone)",
    status: "状态",
    reason: "原因",
    checked_at: "检测时间",
    no_hits: "未命中任何列表",
    listed_count: "命中 {count} 个列表",
  },
  network: {
    title: "网络",
    bgp_prefix: "BGP 前缀",
    rir: "RIR 注册局",
    registered_country: "注册国家",
    upstream: "上游网络",
    as_name: "AS 名称",
    routes: "路由追踪 (Traceroute)",
    reverse_dns: "反向 DNS",
    ping: "Ping 延迟",
    no_network_data: "暂无网络数据。纯 IP 模式仍可测量 Ping 和反向 DNS。",
  },
  leak_speed: {
    title: "泄漏与测速",
    webrtc_leak: "WebRTC 泄漏",
    dns_leak: "DNS 泄漏",
    http_leak: "HTTP 头泄漏",
    ping: "代理 Ping 延迟",
    download_speed: "下载速度",
    not_measured_proxy: "未测量 — 需要输入代理",
    no_leak: "无泄漏",
    leaking: "检测到泄漏",
    test_failed: "测试失败",
    retry: "重试泄漏 / 测速",
  },
  evidence: {
    title: "证据",
    all: "全部",
    agree_clean: "判定纯净",
    divergent: "存疑偏差",
    reported_bad: "报告恶意",
    missing: "缺失",
    search_placeholder: "筛选提供商、上游、分类…",
    provider: "提供商",
    upstream: "上游源",
    category: "分类",
    signal: "信号",
    score: "评分",
    latency: "延迟",
    timestamp: "时间",
    raw_data: "原始数据",
    view_source: "来源",
    no_evidence: "暂无采集到的证据。",
  },
  history: {
    title: "历史记录",
    search_placeholder: "搜索 IP / 代理…",
    all_verdicts: "全部 ({count})",
    from_cache_label: "来自缓存，检测于 {time}",
    recheck: "重新检测",
    clear_history: "清空历史",
    no_history: "暂无检测历史。",
    export_json: "导出 JSON",
    export_csv: "导出 CSV",
    copy_report: "复制报告",
    health_btn: "↻ 刷新健康度",
    search_aria_label: "搜索历史记录",
    filter_verdict: "按判定结果筛选",
    load_cache_tooltip: "从缓存加载此结果",
    recheck_tooltip: "重新检测 — 跳过缓存并重新发起在线请求 (§10.2)",
    row_aria_label: "查看 {target}, 判定 {verdict}, 纯净度 {clean}/100, 置信度 {confidence}%, {mode}, 时间 {time}",
    reading_history: "正在读取历史记录…",
    cannot_read_history: "读取历史记录失败: {error}",
  },
  settings: {
    title: "设置",
    save: "保存设置",
    close: "关闭",
    saving: "正在保存…",
    saved: "已保存！",
    general: "常规设置",
    api_keys: "API 密钥",
    timeout: "超时时间 (ms)",
    max_concurrency: "最大并发数",
    failure_threshold: "熔断错误阈值",
    cooldown_minutes: "冷却恢复时间 (分钟)",
    dnsbl_groups: "DNSBL 黑名单组",
    cache_ttl: "缓存保留时间 (分钟)",
    export_directory: "导出目录",
    browse: "浏览…",
    geo_db_versions: "离线 Geo 数据库版本",
    language: "界面语言",
    select_language: "选择界面显示语言",
    unsaved_changes: "有未保存的更改",
    synced: "已同步",
    revert: "撤销",
    no_config: "无法加载配置（未连接到 Tauri 核心）。",
    failed_save: "保存设置失败",
    language_hint: "切换软件界面与导出报告的显示语言。",
    key_security_title: "密钥安全保存在 Windows Credential Manager",
    key_security_detail: "保存后输入框始终清空；应用仅展示是否已配置密钥状态。",
    search_provider_placeholder: "搜索服务商 (如 ipqs, abuseipdb)…",
    search_provider_label: "搜索服务商",
    only_key_required: "仅显示需要密钥的来源",
    no_providers: "注册表中暂无服务商。",
    no_key_needed: "无需密钥",
    key_configured: "已配置密钥",
    optional_key: "可选密钥",
    no_key: "未配置密钥",
    quota_exhausted: "配额耗尽",
    enter_new_key: "输入新密钥以替换",
    optional_key_hint: "可选密钥（更高配额）",
    paste_api_key: "粘贴 API 密钥",
    save_key: "保存密钥",
    delete_key_title: "从凭据管理器中删除密钥",
    free_source: "免费源 / 无需密钥",
    enable: "启用",
    toggle_dnsbl_module: "启用/禁用整个黑名单模块",
    enable_blacklist_module: "启用黑名单模块",
    dnsbl_votes_note: "每个分组计为 1 票，而非每个 zone 计票 (§5.3)。",
    export_dir_hint: "JSON/CSV 写入此目录，不包含任何 API 密钥或凭据 (§10.3)。",
    no_local_db: "未安装本地数据库 — 定位仅使用在线 API。",
    updated_col: "更新时间",
    stale_db_badge: "过期 > 60 天",
    stale_db_warning: "{count} 个数据库已超过 60 天 — 定位置信度将扣分 (§7.3)。请在软件新版本中更新。",
    provider_health_title: "各服务商健康度",
    no_health_data: "暂无服务商健康度数据。",
    notes_col: "备注",
    effective_weight_hint: "错误扣减后的实际权重 (§5.5)",
    circuit_open_until: "熔断暂停至 {time}",
    other_title: "其他",
    save_history_default: "默认保存历史记录",
    check_leak_proxy: "代理模式下检测泄漏",
    check_speed_proxy: "代理模式下测试速度",
    auto_update: "自动检查软件更新",
    log_retention: "日志保留 {days} 天",
  },
  export: {
    export_success: "文件导出成功: {path}",
    export_error: "导出失败: {error}",
    copy_success: "检测报告已复制到剪贴板！",
    copy_error: "复制报告失败",
    report_summary: "检测摘要报告",
    export_json_tooltip: "导出包含所有证据的完整 FullCheckResult (§10.3)",
    export_csv_tooltip: "每行 1 个 IP (§10.3)",
    copy_summary_tooltip: "复制摘要报告以便粘贴到聊天",
    refresh_health_tooltip: "重新读取各数据源健康状态",
    close_notice: "关闭通知",
  },
  banners: {
    input_not_scannable: "无法检测此输入",
    private_ip_stopped: "私有 / 保留 IP — 已停止",
    no_core_connection: "无法连接到核心 / 网络",
    check_failed: "检测失败",
    cache_note_title: "本地缓存结果 ({time})",
    cache_note_hint: "点击历史记录中的“重新检测”以发起全新请求。",
    cache_detail_title: "缓存中的结果 ({time})",
    cache_detail_hint: "正在查看缓存记录 — 非最新检测。点击“重新检测”以在线更新。",
    cannot_read_cache: "无法读取缓存记录",
    scanning_wait_export: "正在扫描 — 请等待最终结果后再导出。",
    no_result_to_export: "暂无结果可导出。",
    no_result_to_copy: "暂无结果可复制。",
    exported_file: "已导出 {format}: {file}",
    export_file_error: "导出 {format} 失败: {error}",
    copied_summary: "摘要报告已复制到剪贴板。",
    clipboard_blocked: "复制失败 — 剪贴板访问被阻止。",
    private_no_api: "私有 / 保留 IP — 未调用任何接口",
    private_no_api_hint: "私有/环回/保留网段无公网数据可比对。请输入公网 IP。",
    rerun_whole_suite: "重新执行全量检测 (来自模块 {module} 的请求)",
    rerun_whole_suite_hint: "后端不支持单模块独立运行 — 本次将重测所有模块且不新增历史记录。",
    running_no_ipc: "运行在 Tauri 外部 (无 IPC)",
    running_no_ipc_hint: "请使用 `npm run tauri:dev` 启动应用以启用 IPC。当前界面仅供预览，无法进行实际检测。",
    no_network: "无网络连接",
    no_network_hint: "无法连接服务商。您仍可在下方查看历史记录与缓存。",
    reload_history: "重新加载历史",
    quota_exhausted_penalty: "配额耗尽 / 缺少密钥",
    quota_penalty_hint: "{notice} 判定结果可能被限制为“数据不足” (§6.3)。",
    hard_conflict: "数据源严重冲突 (hard)",
  },
  report: {
    summary_title: "IP CHECKER 综合检测报告",
    verdict_label: "判定结果",
    reason_label: "判定原因",
    location_label: "地理位置",
    asn_label: "ASN / 所属机构",
    ip_type_label: "IP 类型",
    blacklist_label: "黑名单",
    blacklist_hits: "命中 {count} 个黑名单",
    blacklist_clean: "未命中任何黑名单",
    checked_at_label: "检测时间",
    sources_label: "数据来源",
    from_cache_note: " (来自缓存)",
  },
  cards: {
    proxy_only_hint: "仅代理模式",
    sqlite_local: "本地 SQLite",
    click_to_view_cache: "点击一行以加载缓存记录",
    offline_viewing_cache: "离线状态 — 仍可浏览缓存",
  },
};

export const DICTIONARY: Record<Language, I18nDictionary> = {
  vi: VI_DICTIONARY,
  en: EN_DICTIONARY,
  zh: ZH_DICTIONARY,
};

/* ------------------------------------------------------------------ */
/* Type-Safe Key Paths                                                */
/* ------------------------------------------------------------------ */

type NestedKeyOf<ObjectType extends object> = {
  [Key in keyof ObjectType & (string | number)]: ObjectType[Key] extends object
    ? `${Key}` | `${Key}.${NestedKeyOf<ObjectType[Key]>}`
    : `${Key}`;
}[keyof ObjectType & (string | number)];

export type TranslationKey = NestedKeyOf<I18nDictionary> | (string & {});

/* ------------------------------------------------------------------ */
/* Persistence & State Sync Helpers                                   */
/* ------------------------------------------------------------------ */

/**
 * Retrieves the currently saved language from localStorage, falling back to 'vi'.
 */
export function getStoredLanguage(): Language {
  if (typeof window === "undefined" || !window.localStorage) {
    return DEFAULT_LANGUAGE;
  }
  try {
    const stored = window.localStorage.getItem(STORAGE_LOCALE_KEY);
    if (stored === "vi" || stored === "en" || stored === "zh") {
      return stored;
    }
  } catch (err) {
    console.warn("Failed to read locale from localStorage:", err);
  }
  return DEFAULT_LANGUAGE;
}

/**
 * Persists the language to localStorage and emits an event for multi-tab/component sync.
 */
export function setStoredLanguage(lang: Language): void {
  if (typeof window === "undefined" || !window.localStorage) {
    return;
  }
  try {
    window.localStorage.setItem(STORAGE_LOCALE_KEY, lang);
    window.dispatchEvent(
      new CustomEvent<Language>(LOCALE_CHANGE_EVENT, { detail: lang }),
    );
  } catch (err) {
    console.warn("Failed to save locale to localStorage:", err);
  }
}

/* ------------------------------------------------------------------ */
/* Template Formatter & Path Resolver                                 */
/* ------------------------------------------------------------------ */

export type ParamValues = Record<
  string,
  string | number | boolean | null | undefined
>;

function formatTemplate(text: string, params?: ParamValues): string {
  if (!params) return text;
  return text.replace(
    /{{\s*([a-zA-Z0-9_]+)\s*}}|{\s*([a-zA-Z0-9_]+)\s*}/g,
    (match, p1, p2) => {
      const key = p1 || p2;
      if (key in params) {
        const val = params[key];
        return val !== null && val !== undefined ? String(val) : "";
      }
      return match;
    },
  );
}

function resolvePath(obj: unknown, path: string): string | undefined {
  if (!obj || !path) return undefined;
  const parts = path.split(".");
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return typeof cur === "string" ? cur : undefined;
}

/* ------------------------------------------------------------------ */
/* Standalone Translation Helpers                                     */
/* ------------------------------------------------------------------ */

/**
 * Pure translation function usable anywhere (even outside React tree).
 */
export function getTranslation(
  lang: Language,
  key: string,
  params?: ParamValues,
): string {
  const currentDict = DICTIONARY[lang] || DICTIONARY.vi;
  let text = resolvePath(currentDict, key);

  // If key is a flat name without a dot, search each section of currentDict
  if (text === undefined && !key.includes(".")) {
    for (const section of Object.values(currentDict)) {
      if (
        section &&
        typeof section === "object" &&
        typeof (section as Record<string, unknown>)[key] === "string"
      ) {
        text = (section as Record<string, string>)[key];
        break;
      }
    }
  }

  // Fallback to Vietnamese if missing in requested language
  if (text === undefined && lang !== "vi") {
    text = resolvePath(DICTIONARY.vi, key);
    if (text === undefined && !key.includes(".")) {
      for (const section of Object.values(DICTIONARY.vi)) {
        if (
          section &&
          typeof section === "object" &&
          typeof (section as Record<string, unknown>)[key] === "string"
        ) {
          text = (section as Record<string, string>)[key];
          break;
        }
      }
    }
  }

  const result = text !== undefined ? text : key;
  return formatTemplate(result, params);
}

/**
 * Short alias for standalone translations.
 */
export function tLang(
  lang: Language,
  key: TranslationKey,
  params?: ParamValues,
): string {
  return getTranslation(lang, key, params);
}

/* ------------------------------------------------------------------ */
/* React Context & Provider                                           */
/* ------------------------------------------------------------------ */

export interface I18nContextValue {
  lang: Language;
  setLang: (lang: Language) => void;
  t: (key: TranslationKey, params?: ParamValues) => string;
}

export const I18nContext = createContext<I18nContextValue>({
  lang: DEFAULT_LANGUAGE,
  setLang: () => {},
  t: (key, params) => getTranslation(DEFAULT_LANGUAGE, key, params),
});

export interface I18nProviderProps {
  children: React.ReactNode;
  initialLang?: Language;
}

export function I18nProvider({ children, initialLang }: I18nProviderProps) {
  const [lang, setLangState] = useState<Language>(
    () => initialLang ?? getStoredLanguage(),
  );

  const setLang = useCallback((nextLang: Language) => {
    setLangState(nextLang);
    setStoredLanguage(nextLang);
  }, []);

  useEffect(() => {
    const handleLocaleChange = (event: Event) => {
      const customEvent = event as CustomEvent<Language>;
      if (
        customEvent.detail &&
        (customEvent.detail === "vi" ||
          customEvent.detail === "en" ||
          customEvent.detail === "zh")
      ) {
        setLangState(customEvent.detail);
      } else {
        setLangState(getStoredLanguage());
      }
    };

    const handleStorage = (event: StorageEvent) => {
      if (event.key === STORAGE_LOCALE_KEY && event.newValue) {
        if (
          event.newValue === "vi" ||
          event.newValue === "en" ||
          event.newValue === "zh"
        ) {
          setLangState(event.newValue);
        }
      }
    };

    window.addEventListener(LOCALE_CHANGE_EVENT, handleLocaleChange);
    window.addEventListener("storage", handleStorage);
    return () => {
      window.removeEventListener(LOCALE_CHANGE_EVENT, handleLocaleChange);
      window.removeEventListener("storage", handleStorage);
    };
  }, []);

  const t = useCallback(
    (key: TranslationKey, params?: ParamValues) => {
      return getTranslation(lang, key, params);
    },
    [lang],
  );

  const value = useMemo(
    () => ({
      lang,
      setLang,
      t,
    }),
    [lang, setLang, t],
  );

  return React.createElement(I18nContext.Provider, { value }, children);
}

/**
 * Primary React hook for consuming internationalization.
 */
export function useI18n(): I18nContextValue {
  return useContext(I18nContext);
}

/* ------------------------------------------------------------------ */
/* Specialized Domain Mapping Helpers                                 */
/* ------------------------------------------------------------------ */

/**
 * Translates backend verdict strings ("Sạch", "Tạm", "Nghi ngờ", "Bẩn", "Chưa đủ dữ liệu").
 */
export function getVerdictTranslation(
  lang: Language,
  verdict: string | null | undefined,
): string {
  if (!verdict) return DICTIONARY[lang].verdict.chua_du;
  switch (verdict) {
    case "Sạch":
      return DICTIONARY[lang].verdict.sach;
    case "Tạm":
      return DICTIONARY[lang].verdict.tam;
    case "Nghi ngờ":
      return DICTIONARY[lang].verdict.nghi_ngo;
    case "Bẩn":
      return DICTIONARY[lang].verdict.ban;
    case "Chưa đủ dữ liệu":
      return DICTIONARY[lang].verdict.chua_du;
    default:
      return verdict;
  }
}

export type VerdictTone = "clean" | "temp" | "suspect" | "bad" | "unknown";

export interface LocalizedVerdictMeta {
  verdict: string;
  displayLabel: string;
  tone: VerdictTone;
  cls: string;
}

const VERDICT_BASE_META: Record<string, { tone: VerdictTone; cls: string }> = {
  "Sạch": { tone: "clean", cls: "clean" },
  "Tạm": { tone: "temp", cls: "temp" },
  "Nghi ngờ": { tone: "suspect", cls: "suspect" },
  "Bẩn": { tone: "bad", cls: "bad" },
  "Chưa đủ dữ liệu": { tone: "unknown", cls: "unknown" },
};

/**
 * Returns localized verdict metadata including CSS class, tone and localized display label.
 */
export function getLocalizedVerdictMeta(
  verdict: string | null | undefined,
  lang: Language,
): LocalizedVerdictMeta {
  const normVerdict = verdict && VERDICT_BASE_META[verdict] ? verdict : "Chưa đủ dữ liệu";
  const base = VERDICT_BASE_META[normVerdict];
  const displayLabel = getVerdictTranslation(lang, normVerdict);
  return {
    verdict: normVerdict,
    displayLabel,
    tone: base.tone,
    cls: base.cls,
  };
}

/**
 * Formats a localized "from cache" note with formatted timestamp.
 */
export function getLocalizedCacheNote(
  cachedAt: string | null | undefined,
  lang: Language,
): string {
  if (!cachedAt) {
    return lang === "vi" ? "từ cache" : lang === "zh" ? "来自缓存" : "from cache";
  }
  let timeStr = cachedAt;
  const d = new Date(cachedAt);
  if (!Number.isNaN(d.getTime())) {
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const mo = String(d.getMonth() + 1).padStart(2, "0");
    timeStr = `${hh}:${mm} ${dd}/${mo}`;
  }

  if (lang === "vi") {
    return `từ cache, check lúc ${timeStr}`;
  }
  if (lang === "zh") {
    return `来自缓存，检测于 ${timeStr}`;
  }
  return `from cache, checked at ${timeStr}`;
}

/**
 * Translates signal strings ("Clean", "Suspicious", "Bad", "Unknown").
 */
export function getSignalTranslation(
  lang: Language,
  signal: string | null | undefined,
): string {
  if (!signal) return DICTIONARY[lang].reputation.unknown;
  switch (signal) {
    case "Clean":
      return DICTIONARY[lang].reputation.clean;
    case "Suspicious":
      return DICTIONARY[lang].reputation.suspicious;
    case "Bad":
      return DICTIONARY[lang].reputation.bad;
    case "Unknown":
    default:
      return DICTIONARY[lang].reputation.unknown;
  }
}

/**
 * Translates module IDs to localized display names.
 */
export function getModuleTranslation(
  lang: Language,
  moduleId: string | null | undefined,
): string {
  if (!moduleId) return "";
  const dict = DICTIONARY[lang].modules;
  const key = moduleId as keyof typeof dict;
  return dict[key] ?? moduleId;
}

/**
 * Translates module execution status ("pending", "running", "done", "error", "skipped").
 */
export function getStatusTranslation(
  lang: Language,
  status: string | null | undefined,
): string {
  if (!status) return "";
  const dict = DICTIONARY[lang].progress;
  switch (status) {
    case "pending":
      return dict.waiting;
    case "running":
      return dict.running;
    case "done":
      return dict.done;
    case "error":
      return dict.error;
    case "skipped":
      return dict.skipped;
    default:
      return status;
  }
}

/**
 * Translates module skip reasons.
 */
export function getSkipReasonTranslation(
  lang: Language,
  reason: string | null | undefined,
): string {
  if (!reason) return DICTIONARY[lang].progress.skipped;
  const dict = DICTIONARY[lang].skip_reasons;
  const key = reason as keyof typeof dict;
  return dict[key] ?? String(reason);
}

/**
 * Translates network/provider error kinds.
 */
export function getErrorKindTranslation(
  lang: Language,
  kind: string | null | undefined,
): string {
  if (!kind) return DICTIONARY[lang].error_kinds.unknown;
  const dict = DICTIONARY[lang].error_kinds;
  const key = kind as keyof typeof dict;
  return dict[key] ?? String(kind);
}

/**
 * Translates IP types.
 */
export function getIpTypeTranslation(
  lang: Language,
  ipType: string | null | undefined,
): string {
  if (!ipType) return DICTIONARY[lang].common.dash;
  const dict = DICTIONARY[lang].ip_types;
  const key = ipType as keyof typeof dict;
  return dict[key] ?? String(ipType);
}

/**
 * Translates DNSBL group names.
 */
export function getDnsblGroupTranslation(
  lang: Language,
  group: string | null | undefined,
): string {
  if (!group) return DICTIONARY[lang].common.dash;
  const dict = DICTIONARY[lang].blacklist;
  switch (group) {
    case "spamhaus":
      return dict.spamhaus;
    case "commercial":
      return dict.commercial;
    case "community":
      return dict.community;
    case "specialist":
      return dict.specialist;
    default:
      return String(group);
  }
}

/**
 * Translates Geo location spread labels & explanations.
 */
export function getSpreadMetaTranslation(
  lang: Language,
  spread: string | null | undefined,
): { label: string; explanation: string } | null {
  if (!spread) return null;
  const key = spread.toLowerCase();
  const loc = DICTIONARY[lang].location;

  switch (key) {
    case "high":
      return {
        label: loc.spread_high,
        explanation: loc.spread_high_exp,
      };
    case "medium":
      return {
        label: loc.spread_medium,
        explanation: loc.spread_medium_exp,
      };
    case "low":
      return {
        label: loc.spread_low,
        explanation: loc.spread_low_exp,
      };
    case "disputed":
      return {
        label: loc.spread_disputed,
        explanation: loc.spread_disputed_exp,
      };
    default:
      return {
        label: spread,
        explanation: "",
      };
  }
}

export const getLocalizedModuleLabel = getModuleTranslation;
export const getLocalizedStatusLabel = getStatusTranslation;
export const getLocalizedSkipReasonLabel = getSkipReasonTranslation;

export {
  getLocalizedAspectLabel,
  getLocalizedInputMessage,
  getLocalizedProgressMessage,
  getLocalizedVerdictReason,
  getLocalizedProviderReason,
} from "../components/ui/meta.ts";

export default useI18n;
