import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_LANGUAGE,
  SUPPORTED_LANGUAGES,
  STORAGE_LOCALE_KEY,
  LOCALE_CHANGE_EVENT,
  DICTIONARY,
  VI_DICTIONARY,
  EN_DICTIONARY,
  ZH_DICTIONARY,
  getTranslation,
  tLang,
  getVerdictTranslation,
  getSignalTranslation,
  getModuleTranslation,
  getStatusTranslation,
  getSkipReasonTranslation,
  getErrorKindTranslation,
  getIpTypeTranslation,
  getDnsblGroupTranslation,
  getSpreadMetaTranslation,
} from "./i18n.ts";

test("supported languages configuration", () => {
  assert.equal(DEFAULT_LANGUAGE, "vi");
  assert.equal(STORAGE_LOCALE_KEY, "ip_checker_locale");
  assert.equal(LOCALE_CHANGE_EVENT, "ip_checker_locale_changed");
  assert.equal(SUPPORTED_LANGUAGES.length, 3);

  const codes = SUPPORTED_LANGUAGES.map((l) => l.code);
  assert.deepEqual(codes, ["vi", "en", "zh"]);
});

test("all required sections exist in all 3 dictionaries", () => {
  const sections = [
    "common",
    "header",
    "input",
    "verdict",
    "progress",
    "modules",
    "skip_reasons",
    "error_kinds",
    "overview",
    "ip_types",
    "location",
    "reputation",
    "blacklist",
    "network",
    "leak_speed",
    "evidence",
    "history",
    "settings",
    "export",
    "banners",
    "report",
    "cards",
  ];

  for (const lang of ["vi", "en", "zh"]) {
    const dict = DICTIONARY[lang];
    assert.ok(dict, `Dictionary for ${lang} must exist`);

    for (const section of sections) {
      assert.ok(
        dict[section],
        `Section ${section} in language ${lang} must exist`,
      );
      assert.equal(
        typeof dict[section],
        "object",
        `Section ${section} must be an object`,
      );
    }
  }
});

test("Vietnamese exact terms compliance", () => {
  assert.equal(VI_DICTIONARY.verdict.sach, "Sạch");
  assert.equal(VI_DICTIONARY.verdict.tam, "Tạm");
  assert.equal(VI_DICTIONARY.verdict.nghi_ngo, "Nghi ngờ");
  assert.equal(VI_DICTIONARY.verdict.ban, "Bẩn");
  assert.equal(VI_DICTIONARY.verdict.chua_du, "Chưa đủ dữ liệu");
  assert.equal(VI_DICTIONARY.verdict.not_checked, "chưa check");

  assert.equal(
    VI_DICTIONARY.leak_speed.not_measured_proxy,
    "Chưa đo được — cần nhập proxy",
  );
  assert.equal(
    VI_DICTIONARY.header.subtitle,
    "đa nguồn · đối chiếu vị trí · blacklist trực tiếp",
  );

  assert.equal(VI_DICTIONARY.modules.validate, "Kiểm tra IP");
  assert.equal(VI_DICTIONARY.modules.geo, "Định vị");
  assert.equal(VI_DICTIONARY.modules.scoring, "Chấm điểm");

  assert.equal(VI_DICTIONARY.skip_reasons.missing_key, "thiếu API key");
  assert.equal(VI_DICTIONARY.skip_reasons.requires_proxy, "cần nhập proxy");
  assert.equal(VI_DICTIONARY.skip_reasons.quota_exhausted, "hết quota");

  assert.equal(
    VI_DICTIONARY.location.spread_high,
    "Nguồn chụm < 50 km",
  );
  assert.equal(
    VI_DICTIONARY.location.spread_disputed,
    "Tranh chấp",
  );
});

test("English professional terms compliance", () => {
  assert.equal(EN_DICTIONARY.verdict.sach, "Clean");
  assert.equal(EN_DICTIONARY.verdict.tam, "Fair");
  assert.equal(EN_DICTIONARY.verdict.nghi_ngo, "Suspicious");
  assert.equal(EN_DICTIONARY.verdict.ban, "Bad");
  assert.equal(EN_DICTIONARY.verdict.chua_du, "Insufficient Data");
  assert.equal(EN_DICTIONARY.verdict.not_checked, "not checked");

  assert.equal(
    EN_DICTIONARY.header.subtitle,
    "multi-source · geo-triangulation · direct blacklist",
  );
  assert.equal(
    EN_DICTIONARY.leak_speed.not_measured_proxy,
    "Not measured — proxy required",
  );
});

test("Chinese natural and professional terms compliance", () => {
  assert.equal(ZH_DICTIONARY.verdict.sach, "纯净");
  assert.equal(ZH_DICTIONARY.verdict.tam, "一般");
  assert.equal(ZH_DICTIONARY.verdict.nghi_ngo, "可疑");
  assert.equal(ZH_DICTIONARY.verdict.ban, "恶意");
  assert.equal(ZH_DICTIONARY.verdict.chua_du, "数据不足");
  assert.equal(ZH_DICTIONARY.verdict.not_checked, "未检测");

  assert.equal(
    ZH_DICTIONARY.header.subtitle,
    "多源对比 · 位置三角校准 · 实时黑名单",
  );
  assert.equal(
    ZH_DICTIONARY.leak_speed.not_measured_proxy,
    "未测量 — 需要输入代理",
  );
});

test("getTranslation dot path resolution", () => {
  assert.equal(getTranslation("vi", "common.ok"), "OK");
  assert.equal(getTranslation("en", "common.ok"), "OK");
  assert.equal(getTranslation("zh", "common.ok"), "确定");

  assert.equal(getTranslation("vi", "verdict.sach"), "Sạch");
  assert.equal(getTranslation("en", "verdict.sach"), "Clean");
  assert.equal(getTranslation("zh", "verdict.sach"), "纯净");

  assert.equal(getTranslation("vi", "overview.country_geo"), "Quốc gia (geo)");
  assert.equal(getTranslation("en", "overview.country_geo"), "Country (Geo)");
  assert.equal(getTranslation("zh", "overview.country_geo"), "国家/地区 (地理)");
});

test("getTranslation flat key resolution fallback", () => {
  assert.equal(getTranslation("vi", "ok"), "OK");
  assert.equal(getTranslation("zh", "ok"), "确定");
  assert.equal(getTranslation("zh", "sach"), "纯净");
});

test("template parameter interpolation", () => {
  assert.equal(
    getTranslation("vi", "header.providers_good", { count: 8 }),
    "8 provider tốt",
  );
  assert.equal(
    getTranslation("en", "header.providers_good", { count: 8 }),
    "8 providers healthy",
  );
  assert.equal(
    getTranslation("zh", "header.providers_good", { count: 8 }),
    "8 个正常",
  );

  assert.equal(
    getTranslation("vi", "progress.modules_count", { done: 12, total: 13 }),
    "12/13 module",
  );
  assert.equal(
    getTranslation("zh", "progress.modules_count", { done: 12, total: 13 }),
    "12/13 个模块",
  );
});

test("fallback to Vietnamese when key is missing in another language", () => {
  // If a key doesn't exist, it should fallback to VI or key
  assert.equal(
    getTranslation("en", "non_existent_key_xyz"),
    "non_existent_key_xyz",
  );
});

test("domain specific translation mappers", () => {
  // Verdict
  assert.equal(getVerdictTranslation("vi", "Sạch"), "Sạch");
  assert.equal(getVerdictTranslation("en", "Sạch"), "Clean");
  assert.equal(getVerdictTranslation("zh", "Sạch"), "纯净");

  assert.equal(getVerdictTranslation("vi", "Chưa đủ dữ liệu"), "Chưa đủ dữ liệu");
  assert.equal(getVerdictTranslation("en", "Chưa đủ dữ liệu"), "Insufficient Data");
  assert.equal(getVerdictTranslation("zh", "Chưa đủ dữ liệu"), "数据不足");

  // Signal
  assert.equal(getSignalTranslation("vi", "Clean"), "Sạch");
  assert.equal(getSignalTranslation("en", "Clean"), "Clean");
  assert.equal(getSignalTranslation("zh", "Clean"), "纯净");

  // Module
  assert.equal(getModuleTranslation("vi", "dnsbl"), "Blacklist");
  assert.equal(getModuleTranslation("en", "dnsbl"), "DNSBL Blacklist");
  assert.equal(getModuleTranslation("zh", "dnsbl"), "黑名单 (DNSBL)");

  // Status
  assert.equal(getStatusTranslation("vi", "running"), "Đang chạy");
  assert.equal(getStatusTranslation("en", "running"), "Running");
  assert.equal(getStatusTranslation("zh", "running"), "运行中");

  // Skip reason
  assert.equal(getSkipReasonTranslation("vi", "quota_exhausted"), "hết quota");
  assert.equal(getSkipReasonTranslation("en", "quota_exhausted"), "quota exhausted");
  assert.equal(getSkipReasonTranslation("zh", "quota_exhausted"), "配额耗尽");

  // Error kind
  assert.equal(getErrorKindTranslation("vi", "circuit_open"), "provider tạm ngắt");
  assert.equal(getErrorKindTranslation("en", "circuit_open"), "circuit open");
  assert.equal(getErrorKindTranslation("zh", "circuit_open"), "服务已熔断");

  // IP Type
  assert.equal(getIpTypeTranslation("vi", "residential"), "Residential");
  assert.equal(getIpTypeTranslation("en", "residential"), "Residential");
  assert.equal(getIpTypeTranslation("zh", "residential"), "原生住宅 (Residential)");

  // DNSBL Group
  assert.equal(getDnsblGroupTranslation("vi", "spamhaus"), "Spamhaus");
  assert.equal(getDnsblGroupTranslation("en", "spamhaus"), "Spamhaus");
  assert.equal(getDnsblGroupTranslation("zh", "spamhaus"), "Spamhaus");
  assert.equal(getDnsblGroupTranslation("vi", "commercial"), "Thương mại");
  assert.equal(getDnsblGroupTranslation("en", "commercial"), "Commercial");
  assert.equal(getDnsblGroupTranslation("zh", "commercial"), "商业级");
  assert.equal(getDnsblGroupTranslation("zh", "community"), "社区级");
  assert.equal(getDnsblGroupTranslation("zh", "specialist"), "专业级");

  // Spread Meta
  const viSpread = getSpreadMetaTranslation("vi", "high");
  assert.ok(viSpread);
  assert.equal(viSpread.label, "Nguồn chụm < 50 km");

  const enSpread = getSpreadMetaTranslation("en", "high");
  assert.ok(enSpread);
  assert.equal(enSpread.label, "Sources cluster < 50 km");

  const zhSpread = getSpreadMetaTranslation("zh", "high");
  assert.ok(zhSpread);
  assert.equal(zhSpread.label, "各源聚合 < 50 km");
});

test("tLang alias produces identical output", () => {
  assert.equal(tLang("vi", "common.cancel"), getTranslation("vi", "common.cancel"));
  assert.equal(tLang("en", "common.cancel"), getTranslation("en", "common.cancel"));
  assert.equal(tLang("zh", "common.cancel"), getTranslation("zh", "common.cancel"));
});

test("banners, report, and cards section keys", () => {
  assert.equal(getTranslation("vi", "banners.input_not_scannable"), "Không check được input này");
  assert.equal(getTranslation("en", "banners.input_not_scannable"), "Cannot check this input");
  assert.equal(getTranslation("zh", "banners.input_not_scannable"), "无法检测此输入");

  assert.equal(getTranslation("vi", "banners.cache_note_title", { time: "12:00" }), "Kết quả từ cache (12:00)");
  assert.equal(getTranslation("en", "banners.cache_note_title", { time: "12:00" }), "Cached result (12:00)");
  assert.equal(getTranslation("zh", "banners.cache_note_title", { time: "12:00" }), "本地缓存结果 (12:00)");

  assert.equal(getTranslation("vi", "report.summary_title"), "BÁO CÁO TÓM TẮT IP CHECKER");
  assert.equal(getTranslation("en", "report.summary_title"), "IP CHECKER SUMMARY REPORT");
  assert.equal(getTranslation("zh", "report.summary_title"), "IP CHECKER 综合检测报告");

  assert.equal(getTranslation("vi", "cards.proxy_only_hint"), "proxy only");
  assert.equal(getTranslation("en", "cards.proxy_only_hint"), "proxy only");
  assert.equal(getTranslation("zh", "cards.proxy_only_hint"), "仅代理模式");
});

