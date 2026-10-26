import test from "node:test";
import assert from "node:assert/strict";

import {
  NOT_MEASURED_PROXY,
  DASH,
  VERDICT_META,
  ALL_VERDICTS,
  MODULE_LABELS,
  MODULE_ORDER,
  STATUS_GLYPH,
  STATUS_LABELS,
  SKIP_REASON_LABELS,
  CATEGORY_LABELS,
  IP_TYPE_LABELS,
  UNRELIABLE_CITY_TYPES,
  PROTOCOL_LABELS,
  DNSBL_GROUP_LABELS,
  HEALTH_LABELS,
  ERROR_KIND_LABELS,
  SPREAD_META,
  CENTROID_COLOR,
  verdictMeta,
  scoreTone,
  confidenceTone,
  signalMeta,
  skipReasonLabel,
  ipTypeLabel,
  protocolLabel,
  dnsblGroupLabel,
  errorKindLabel,
  shortError,
  fmtInt,
  fmtNum,
  fmtPct,
  fmtKm,
  fmtMs,
  fmtMbps,
  fmtBytes,
  fmtTime,
  fmtDate,
  cacheNote,
  valueOrDash,
  yesNo,
  srcColor,
  sourceColorVar,
  spreadLabel,
  fmtCoord,
  pluralize,
  clampText,
  cx,
  // New i18n helpers and functions:
  SUPPORTED_LANGUAGES,
  normalizeLanguage,
  getLocalizedModuleLabel,
  getLocalizedStatusLabel,
  getLocalizedSkipReasonLabel,
  getLocalizedCategoryLabel,
  getLocalizedIpTypeLabel,
  getLocalizedDnsblGroupLabel,
  getLocalizedHealthLabel,
  getLocalizedErrorKindLabel,
  getLocalizedVerdictMeta,
  getLocalizedSignalMeta,
  getLocalizedSpreadMeta,
  getLocalizedCacheNote,
  getLocalizedYesNo,
  getLocalizedShortError,
  getLocalizedNotMeasuredProxy,
  getLocalizedProviderReason,
} from "./meta.ts";

test("backward compatibility: constants and types exist verbatim", () => {
  assert.equal(NOT_MEASURED_PROXY, "Chưa đo được — cần nhập proxy");
  assert.equal(DASH, "—");
  assert.equal(ALL_VERDICTS.length, 5);
  assert.equal(MODULE_ORDER.length, 13);
  assert.equal(CENTROID_COLOR, "var(--map-centroid)");

  assert.equal(VERDICT_META["Sạch"].tone, "clean");
  assert.equal(VERDICT_META["Tạm"].tone, "temp");
  assert.equal(VERDICT_META["Nghi ngờ"].tone, "suspect");
  assert.equal(VERDICT_META["Bẩn"].tone, "bad");
  assert.equal(VERDICT_META["Chưa đủ dữ liệu"].tone, "unknown");

  assert.equal(STATUS_GLYPH.done, "✓");
  assert.equal(STATUS_LABELS.done, "Xong");
  assert.equal(SKIP_REASON_LABELS.missing_key, "thiếu API key");
  assert.equal(CATEGORY_LABELS.geo, "Geo");
  assert.equal(IP_TYPE_LABELS.residential, "Residential");
  assert.equal(DNSBL_GROUP_LABELS.commercial, "Thương mại");
  assert.equal(HEALTH_LABELS.green, "Tốt");
  assert.equal(ERROR_KIND_LABELS.quota, "hết quota");
  assert.equal(SPREAD_META.high.tone, "clean");
});

test("backward compatibility: existing functions maintain default Vietnamese behavior", () => {
  assert.equal(verdictMeta("Sạch").verdict, "Sạch");
  assert.equal(verdictMeta(null).verdict, "Chưa đủ dữ liệu");
  assert.equal(signalMeta("Clean").label, "Sạch");
  assert.equal(signalMeta(null).label, "Không rõ");
  assert.equal(skipReasonLabel("missing_key"), "thiếu API key");
  assert.equal(skipReasonLabel(null), "bỏ qua");
  assert.equal(ipTypeLabel("datacenter"), "Datacenter / hosting");
  assert.equal(ipTypeLabel(null), DASH);
  assert.equal(dnsblGroupLabel("specialist"), "Chuyên biệt");
  assert.equal(dnsblGroupLabel(null), DASH);
  assert.equal(errorKindLabel("timeout"), "timeout");
  assert.equal(errorKindLabel(null), "lỗi không rõ");
  assert.equal(shortError({ kind: "timeout", status: 408 }), "timeout 408");
  assert.equal(shortError(null), DASH);
  assert.equal(cacheNote("2026-10-25T12:30:00Z").startsWith("từ cache, check lúc "), true);
  assert.equal(yesNo(true), "Có");
  assert.equal(yesNo(false), "Không");
  assert.equal(yesNo(null), DASH);
  assert.equal(spreadLabel("high")?.label, "Nguồn chụm < 50 km");
  assert.equal(spreadLabel(null), null);
});

test("normalizeLanguage helper handles locales gracefully", () => {
  assert.equal(normalizeLanguage("vi"), "vi");
  assert.equal(normalizeLanguage("en"), "en");
  assert.equal(normalizeLanguage("en-US"), "en");
  assert.equal(normalizeLanguage("en_GB"), "en");
  assert.equal(normalizeLanguage("zh"), "zh");
  assert.equal(normalizeLanguage("zh-CN"), "zh");
  assert.equal(normalizeLanguage("zh_TW"), "zh");
  assert.equal(normalizeLanguage("cn"), "zh");
  assert.equal(normalizeLanguage(null), "vi");
  assert.equal(normalizeLanguage(undefined), "vi");
  assert.equal(normalizeLanguage("fr"), "vi");
});

test("getLocalizedNotMeasuredProxy", () => {
  assert.equal(getLocalizedNotMeasuredProxy(), NOT_MEASURED_PROXY);
  assert.equal(getLocalizedNotMeasuredProxy("vi"), "Chưa đo được — cần nhập proxy");
  assert.equal(getLocalizedNotMeasuredProxy("en"), "Not measured — proxy required");
  assert.equal(getLocalizedNotMeasuredProxy("zh"), "未测量 — 需要输入代理");
  assert.equal(getLocalizedNotMeasuredProxy("zh-CN"), "未测量 — 需要输入代理");
});

test("getLocalizedVerdictMeta", () => {
  const viClean = getLocalizedVerdictMeta("Sạch", "vi");
  assert.equal(viClean.verdict, "Sạch");
  assert.equal(viClean.displayLabel, "Sạch");
  assert.equal(viClean.tone, "clean");

  const enClean = getLocalizedVerdictMeta("Sạch", "en");
  assert.equal(enClean.verdict, "Sạch");
  assert.equal(enClean.displayLabel, "Clean");
  assert.equal(enClean.tone, "clean");

  const zhClean = getLocalizedVerdictMeta("Sạch", "zh");
  assert.equal(zhClean.verdict, "Sạch");
  assert.equal(zhClean.displayLabel, "纯净");
  assert.equal(zhClean.tone, "clean");

  // Fair / Tạm
  assert.equal(getLocalizedVerdictMeta("Tạm", "en").displayLabel, "Fair");
  assert.equal(getLocalizedVerdictMeta("Tạm", "zh").displayLabel, "一般");

  // Suspicious / Nghi ngờ
  assert.equal(getLocalizedVerdictMeta("Nghi ngờ", "en").displayLabel, "Suspicious");
  assert.equal(getLocalizedVerdictMeta("Nghi ngờ", "zh").displayLabel, "可疑");

  // Bad / Bẩn
  assert.equal(getLocalizedVerdictMeta("Bẩn", "en").displayLabel, "Bad");
  assert.equal(getLocalizedVerdictMeta("Bẩn", "zh").displayLabel, "恶意");

  // Insufficient Data / Chưa đủ dữ liệu
  assert.equal(getLocalizedVerdictMeta("Chưa đủ dữ liệu", "en").displayLabel, "Insufficient Data");
  assert.equal(getLocalizedVerdictMeta("Chưa đủ dữ liệu", "zh").displayLabel, "数据不足");
  assert.equal(getLocalizedVerdictMeta(null, "zh-CN").displayLabel, "数据不足");

  // English input maps to canonical verdict
  assert.equal(getLocalizedVerdictMeta("Clean", "zh").displayLabel, "纯净");
});

test("getLocalizedSignalMeta", () => {
  assert.equal(getLocalizedSignalMeta("Clean", "en").label, "Clean");
  assert.equal(getLocalizedSignalMeta("Suspicious", "en").label, "Suspicious");
  assert.equal(getLocalizedSignalMeta("Bad", "en").label, "Bad");
  assert.equal(getLocalizedSignalMeta("Unknown", "en").label, "Unknown");

  assert.equal(getLocalizedSignalMeta("Clean", "zh").label, "纯净");
  assert.equal(getLocalizedSignalMeta("Suspicious", "zh").label, "可疑");
  assert.equal(getLocalizedSignalMeta("Bad", "zh").label, "恶意");
  assert.equal(getLocalizedSignalMeta("Unknown", "zh").label, "未知");

  assert.equal(getLocalizedSignalMeta("Clean", "vi").label, "Sạch");
  assert.equal(getLocalizedSignalMeta(null, "vi").label, "Không rõ");
});

test("getLocalizedModuleLabel", () => {
  assert.equal(getLocalizedModuleLabel("validate", "vi"), "Kiểm tra IP");
  assert.equal(getLocalizedModuleLabel("validate", "en"), "IP Validation");
  assert.equal(getLocalizedModuleLabel("validate", "zh"), "IP验证");

  assert.equal(getLocalizedModuleLabel("geo", "en"), "Geolocation");
  assert.equal(getLocalizedModuleLabel("geo", "zh"), "地理位置");

  assert.equal(getLocalizedModuleLabel("asn", "en"), "ASN");
  assert.equal(getLocalizedModuleLabel("asn", "zh"), "ASN");

  assert.equal(getLocalizedModuleLabel("fraud", "en"), "Fraud");
  assert.equal(getLocalizedModuleLabel("fraud", "zh"), "欺诈检测");

  assert.equal(getLocalizedModuleLabel("abuse", "en"), "Abuse");
  assert.equal(getLocalizedModuleLabel("abuse", "zh"), "滥用报告");

  assert.equal(getLocalizedModuleLabel("threat_intel", "en"), "Threat Intel");
  assert.equal(getLocalizedModuleLabel("threat_intel", "zh"), "威胁情报");

  assert.equal(getLocalizedModuleLabel("dnsbl", "en"), "Blacklist");
  assert.equal(getLocalizedModuleLabel("dnsbl", "zh"), "黑名单");

  assert.equal(getLocalizedModuleLabel("exit_ip", "en"), "Exit IP");
  assert.equal(getLocalizedModuleLabel("exit_ip", "zh"), "出口IP");

  assert.equal(getLocalizedModuleLabel("leak", "en"), "Leak");
  assert.equal(getLocalizedModuleLabel("leak", "zh"), "泄漏检测");

  assert.equal(getLocalizedModuleLabel("speed", "en"), "Speed");
  assert.equal(getLocalizedModuleLabel("speed", "zh"), "测速");

  assert.equal(getLocalizedModuleLabel("scoring", "en"), "Scoring");
  assert.equal(getLocalizedModuleLabel("scoring", "zh"), "综合评分");
});

test("getLocalizedStatusLabel", () => {
  assert.equal(getLocalizedStatusLabel("pending", "en"), "Pending");
  assert.equal(getLocalizedStatusLabel("running", "en"), "Running");
  assert.equal(getLocalizedStatusLabel("done", "en"), "Done");
  assert.equal(getLocalizedStatusLabel("error", "en"), "Error");
  assert.equal(getLocalizedStatusLabel("skipped", "en"), "Skipped");

  assert.equal(getLocalizedStatusLabel("pending", "zh"), "等待中");
  assert.equal(getLocalizedStatusLabel("running", "zh"), "运行中");
  assert.equal(getLocalizedStatusLabel("done", "zh"), "完成");
  assert.equal(getLocalizedStatusLabel("error", "zh"), "错误");
  assert.equal(getLocalizedStatusLabel("skipped", "zh"), "已跳过");

  assert.equal(getLocalizedStatusLabel("done", "vi"), "Xong");
});

test("getLocalizedSkipReasonLabel", () => {
  assert.equal(getLocalizedSkipReasonLabel("missing_key", "en"), "Missing API key");
  assert.equal(getLocalizedSkipReasonLabel("requires_proxy", "en"), "Requires proxy");
  assert.equal(getLocalizedSkipReasonLabel("quota_exhausted", "en"), "Quota exhausted");
  assert.equal(getLocalizedSkipReasonLabel("disabled", "en"), "Disabled in settings");
  assert.equal(getLocalizedSkipReasonLabel(null, "en"), "Skipped");

  assert.equal(getLocalizedSkipReasonLabel("missing_key", "zh"), "缺少API密钥");
  assert.equal(getLocalizedSkipReasonLabel("requires_proxy", "zh"), "需要代理");
  assert.equal(getLocalizedSkipReasonLabel("quota_exhausted", "zh"), "配额耗尽");
  assert.equal(getLocalizedSkipReasonLabel("disabled", "zh"), "已在设置中禁用");
  assert.equal(getLocalizedSkipReasonLabel(null, "zh"), "已跳过");

  assert.equal(getLocalizedSkipReasonLabel("missing_key", "vi"), "thiếu API key");
  assert.equal(getLocalizedSkipReasonLabel(null, "vi"), "bỏ qua");
});

test("getLocalizedCategoryLabel", () => {
  assert.equal(getLocalizedCategoryLabel("geo", "en"), "Geo");
  assert.equal(getLocalizedCategoryLabel("local_db", "en"), "Local DB");

  assert.equal(getLocalizedCategoryLabel("geo", "zh"), "地理位置");
  assert.equal(getLocalizedCategoryLabel("fraud", "zh"), "欺诈检测");
  assert.equal(getLocalizedCategoryLabel("local_db", "zh"), "本地数据库");
});

test("getLocalizedIpTypeLabel", () => {
  assert.equal(getLocalizedIpTypeLabel("residential", "en"), "Residential");
  assert.equal(getLocalizedIpTypeLabel("datacenter", "en"), "Datacenter / Hosting");
  assert.equal(getLocalizedIpTypeLabel("mobile", "en"), "Mobile");
  assert.equal(getLocalizedIpTypeLabel(null, "en"), DASH);

  assert.equal(getLocalizedIpTypeLabel("residential", "zh"), "住宅IP");
  assert.equal(getLocalizedIpTypeLabel("datacenter", "zh"), "数据中心 / 机房");
  assert.equal(getLocalizedIpTypeLabel("mobile", "zh"), "移动网络");
  assert.equal(getLocalizedIpTypeLabel(null, "zh"), DASH);

  assert.equal(getLocalizedIpTypeLabel("residential", "vi"), "Residential");
});

test("getLocalizedDnsblGroupLabel", () => {
  assert.equal(getLocalizedDnsblGroupLabel("commercial", "en"), "Commercial");
  assert.equal(getLocalizedDnsblGroupLabel("community", "en"), "Community");
  assert.equal(getLocalizedDnsblGroupLabel("specialist", "en"), "Specialist");

  assert.equal(getLocalizedDnsblGroupLabel("commercial", "zh"), "商业级");
  assert.equal(getLocalizedDnsblGroupLabel("community", "zh"), "社区级");
  assert.equal(getLocalizedDnsblGroupLabel("specialist", "zh"), "专业级");

  assert.equal(getLocalizedDnsblGroupLabel("commercial", "vi"), "Thương mại");
  assert.equal(getLocalizedDnsblGroupLabel(null, "vi"), DASH);
});

test("getLocalizedHealthLabel", () => {
  assert.equal(getLocalizedHealthLabel("green", "en"), "Good");
  assert.equal(getLocalizedHealthLabel("yellow", "en"), "Degraded / Slow");
  assert.equal(getLocalizedHealthLabel("red", "en"), "Down");
  assert.equal(getLocalizedHealthLabel("unknown", "en"), "Unknown");

  assert.equal(getLocalizedHealthLabel("green", "zh"), "正常");
  assert.equal(getLocalizedHealthLabel("yellow", "zh"), "缓慢 / 暂时异常");
  assert.equal(getLocalizedHealthLabel("red", "zh"), "故障");
  assert.equal(getLocalizedHealthLabel("unknown", "zh"), "未知");

  assert.equal(getLocalizedHealthLabel("green", "vi"), "Tốt");
});

test("getLocalizedErrorKindLabel and getLocalizedShortError", () => {
  assert.equal(getLocalizedErrorKindLabel("timeout", "en"), "timeout");
  assert.equal(getLocalizedErrorKindLabel("quota", "en"), "quota exhausted");
  assert.equal(getLocalizedErrorKindLabel("no_key", "en"), "missing API key");
  assert.equal(getLocalizedErrorKindLabel(null, "en"), "unknown error");

  assert.equal(getLocalizedErrorKindLabel("timeout", "zh"), "请求超时");
  assert.equal(getLocalizedErrorKindLabel("quota", "zh"), "配额耗尽");
  assert.equal(getLocalizedErrorKindLabel("no_key", "zh"), "缺少API密钥");
  assert.equal(getLocalizedErrorKindLabel(null, "zh"), "未知错误");

  assert.equal(getLocalizedShortError({ kind: "timeout", status: 408 }, "en"), "timeout 408");
  assert.equal(getLocalizedShortError({ kind: "timeout", status: 408 }, "zh"), "请求超时 408");
  assert.equal(getLocalizedShortError(null, "en"), DASH);
});

test("getLocalizedSpreadMeta", () => {
  const enHigh = getLocalizedSpreadMeta("high", "en");
  assert.equal(enHigh?.label, "Sources converged < 50 km");
  assert.equal(enHigh?.tone, "clean");

  const zhHigh = getLocalizedSpreadMeta("high", "zh");
  assert.equal(zhHigh?.label, "数据源聚合 < 50 km");
  assert.equal(zhHigh?.tone, "clean");

  const viHigh = getLocalizedSpreadMeta("high", "vi");
  assert.equal(viHigh?.label, "Nguồn chụm < 50 km");

  assert.equal(getLocalizedSpreadMeta(null, "en"), null);
});

test("getLocalizedCacheNote", () => {
  const ts = "2026-10-25T14:30:00Z";
  assert.equal(getLocalizedCacheNote(ts, "vi").startsWith("từ cache, check lúc "), true);
  assert.equal(getLocalizedCacheNote(ts, "en").startsWith("from cache, checked at "), true);
  assert.equal(getLocalizedCacheNote(ts, "zh").startsWith("来自缓存，检测于 "), true);
});

test("getLocalizedYesNo", () => {
  assert.equal(getLocalizedYesNo(true, "en"), "Yes");
  assert.equal(getLocalizedYesNo(false, "en"), "No");
  assert.equal(getLocalizedYesNo(null, "en"), DASH);
  assert.equal(getLocalizedYesNo(null, "en", "N/A"), "N/A");

  assert.equal(getLocalizedYesNo(true, "zh"), "是");
  assert.equal(getLocalizedYesNo(false, "zh"), "否");
  assert.equal(getLocalizedYesNo(null, "zh"), DASH);

  assert.equal(getLocalizedYesNo(true, "vi"), "Có");
  assert.equal(getLocalizedYesNo(false, "vi"), "Không");
});

test("enhanced legacy helpers support lang parameter", () => {
  const ts = "2026-10-25T14:30:00Z";
  assert.equal(cacheNote(ts, "en").startsWith("from cache, checked at "), true);
  assert.equal(cacheNote(ts, "zh").startsWith("来自缓存，检测于 "), true);
  assert.equal(cacheNote(ts).startsWith("từ cache, check lúc "), true);

  assert.equal(yesNo(true, "en"), "Yes");
  assert.equal(yesNo(false, "en"), "No");
  assert.equal(yesNo(true, "zh"), "是");
  assert.equal(yesNo(false, "zh"), "否");
  assert.equal(yesNo(true), "Có");
  assert.equal(yesNo(null, "en", "N/A"), "N/A");

  assert.equal(spreadLabel("high", "en")?.label, "Sources converged < 50 km");
  assert.equal(spreadLabel("high", "zh")?.label, "数据源聚合 < 50 km");
  assert.equal(spreadLabel("high")?.label, "Nguồn chụm < 50 km");

  assert.equal(shortError({ kind: "timeout", status: 408 }, "en"), "timeout 408");
  assert.equal(shortError({ kind: "timeout", status: 408 }, "zh"), "请求超时 408");
  assert.equal(shortError({ kind: "timeout", status: 408 }), "timeout 408");

  assert.equal(skipReasonLabel("missing_key", "en"), "Missing API key");
  assert.equal(skipReasonLabel("missing_key", "zh"), "缺少API密钥");
  assert.equal(skipReasonLabel("missing_key"), "thiếu API key");

  assert.equal(errorKindLabel("timeout", "en"), "timeout");
  assert.equal(errorKindLabel("timeout", "zh"), "请求超时");
  assert.equal(errorKindLabel("timeout"), "timeout");
});

test("getLocalizedProviderReason localizes provider and backend notes", () => {
  const staleNoteVi = "DB geo cũ > 60 ngày: maxmind — trừ điểm tin cậy (§7.3)";
  assert.equal(
    getLocalizedProviderReason(staleNoteVi, "en"),
    "Geo DB older than 60 days: maxmind — confidence penalty applied (§7.3)",
  );
  assert.equal(
    getLocalizedProviderReason(staleNoteVi, "zh"),
    "地理数据库超过 60 天未更新: maxmind — 已扣减置信度 (§7.3)",
  );
  assert.equal(getLocalizedProviderReason(staleNoteVi, "vi"), staleNoteVi);

  const alertVi = "CẢNH BÁO ĐỎ: các nguồn lệch > 2000 km (§7.7)";
  assert.equal(
    getLocalizedProviderReason(alertVi, "en"),
    "RED ALERT: sources deviate > 2000 km (§7.7)",
  );
  assert.equal(
    getLocalizedProviderReason(alertVi, "zh"),
    "红色警报: 各源偏差 > 2000 km (§7.7)",
  );

  const anycastVi = "IP anycast — không chốt thành phố (§7.5)";
  assert.equal(
    getLocalizedProviderReason(anycastVi, "en"),
    "Anycast IP — city unresolved (§7.5)",
  );
  assert.equal(
    getLocalizedProviderReason(anycastVi, "zh"),
    "Anycast任播IP — 未锁定城市 (§7.5)",
  );
});

