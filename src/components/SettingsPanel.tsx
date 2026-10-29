/**
 * SettingsPanel — §3.3 SettingsPanel.
 *
 * Required contents:
 * - one API-key input per provider, `type="password"`, and the stored key is
 *   NEVER echoed back (the backend only ever sends `has_key` + a label);
 * - per-group DNSBL toggles;
 * - provider timeout, export directory;
 * - Geo DB version + update date;
 * - provider health dots (§5.5).
 * - Language selection (§i18n): Tiếng Việt, English, 简体中文.
 *
 * Everything is edited in a local draft and only written on "Lưu", so a typo in
 * one field never half-applies the settings. Keys entered here are handed to the
 * backend once and cleared from component state immediately (Credential Manager
 * owns them, §2.1 / §10.1).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  DnsblGroup,
  GeoDbVersion,
  ProviderHealth,
  Settings,
} from "../lib/types";
import { Banner, Empty, HealthDot, Panel, Section } from "./ui/parts";
import {
  cx,
  DNSBL_GROUP_LABELS,
  DASH,
  fmtDate,
  getLocalizedDnsblGroupLabel,
  getLocalizedHealthLabel,
  HEALTH_LABELS,
  valueOrDash,
} from "./ui/meta";
import { useI18n, type Language, SUPPORTED_LANGUAGES } from "../lib/i18n";

export interface SettingsPanelProps {
  settings: Settings | null;
  health: ProviderHealth[];
  geoDbVersions: GeoDbVersion[];
  appVersion?: string | null;
  /** Persist the edited settings; resolves when written. */
  onSave: (settings: Settings) => Promise<void> | void;
  /** Pick an export directory via the OS dialog. */
  onPickExportDir: () => Promise<string | null> | void;
  /** Read a new key from the user and store it in Credential Manager. */
  onSaveKey: (provider: string, secret: string) => Promise<void> | void;
  /** Delete the stored key. */
  onClearKey: (provider: string) => Promise<void> | void;
  onClose: () => void;
  saving?: boolean;
  error?: string | null;
}

const DNSBL_GROUPS: DnsblGroup[] = ["spamhaus", "commercial", "community", "specialist"];
const OPTIONAL_KEY_PROVIDERS = new Set(["greynoise", "proxycheck"]);

const HEALTH_BADGE: Record<ProviderHealth["state"], string> = {
  green: "chip--clean",
  yellow: "chip--temp",
  red: "chip--bad",
  unknown: "chip--unknown",
};

export function SettingsPanel({
  settings,
  health,
  geoDbVersions,
  appVersion,
  onSave,
  onPickExportDir,
  onSaveKey,
  onClearKey,
  onClose,
  saving,
  error,
}: SettingsPanelProps) {
  const { lang, setLang, t } = useI18n();
  const [draft, setDraft] = useState<Settings | null>(settings);
  const [keyInputs, setKeyInputs] = useState<Record<string, string>>({});
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [onlyKeyRequired, setOnlyKeyRequired] = useState<boolean>(true);
  const [providerFilter, setProviderFilter] = useState<string>("");

  /**
   * Re-sync when the parent loads settings after the panel opened — but never
   * throw away what the user already edited. `loadSettings()` runs after saving
   * or clearing an API key, and the old unconditional `setDraft(settings)`
   * silently discarded every unsaved field in the panel.
   */
  const prevSettingsRef = useRef<Settings | null>(settings);
  useEffect(() => {
    const previous = prevSettingsRef.current;
    prevSettingsRef.current = settings;
    setDraft((current) => {
      const untouched = !current || !previous || JSON.stringify(current) === JSON.stringify(previous);
      if (untouched || !settings) return settings;
      const byProvider = new Map(settings.providers.map((p) => [p.provider, p]));
      return {
        ...current,
        providers: current.providers.map((item) => {
          const fresh = byProvider.get(item.provider);
          return fresh
            ? { ...item, has_key: fresh.has_key, key_label: fresh.key_label }
            : item;
        }),
      };
    });
  }, [settings]);

  const dirty = useMemo(() => {
    if (!draft || !settings) return false;
    return JSON.stringify(draft) !== JSON.stringify(settings);
  }, [draft, settings]);

  const patch = useCallback((updater: (current: Settings) => Settings) => {
    setDraft((current) => (current ? updater(current) : current));
  }, []);

  const toggleGroup = useCallback(
    (group: DnsblGroup, enabled: boolean) => {
      patch((current) => ({
        ...current,
        dnsbl_groups: current.dnsbl_groups.some((item) => item.group === group)
          ? current.dnsbl_groups.map((item) => (item.group === group ? { ...item, enabled } : item))
          : [...current.dnsbl_groups, { group, enabled }],
      }));
    },
    [patch],
  );

  const groupEnabled = useCallback(
    (group: DnsblGroup): boolean => {
      const found = draft?.dnsbl_groups.find((item) => item.group === group);
      return found ? found.enabled : true;
    },
    [draft],
  );

  const toggleProvider = useCallback(
    (provider: string, enabled: boolean) => {
      patch((current) => ({
        ...current,
        providers: current.providers.map((item) =>
          item.provider === provider ? { ...item, enabled } : item,
        ),
      }));
    },
    [patch],
  );

  const saveKey = useCallback(
    async (provider: string) => {
      const secret = keyInputs[provider];
      if (!secret || secret.trim().length === 0) return;
      setBusyKey(provider);
      try {
        await onSaveKey(provider, secret);
        // Never keep the secret in UI state after handing it over.
        setKeyInputs((current) => ({ ...current, [provider]: "" }));
      } finally {
        setBusyKey(null);
      }
    },
    [keyInputs, onSaveKey],
  );

  const pickDir = useCallback(async () => {
    const picked = await onPickExportDir();
    if (picked) patch((current) => ({ ...current, export_dir: picked }));
  }, [onPickExportDir, patch]);

  const staleDbs = geoDbVersions.filter((item) => item.stale);

  return (
    <Panel
      title={t("settings.title")}
      hint={
        <span className="row" style={{ gap: 6 }}>
          <span className="mono">v{appVersion ?? DASH}</span>
          <button
            type="button"
            className="btn btn--sm btn--ghost"
            onClick={onClose}
            title={t("settings.close")}
          >
            ✕ {t("settings.close")}
          </button>
        </span>
      }
      footer={
        <>
          <span>
            {dirty ? t("settings.unsaved_changes") : t("settings.synced")}
            {saving ? ` · ${t("settings.saving")}` : ""}
          </span>
          <span className="row" style={{ gap: 6 }}>
            <button
              type="button"
              className="btn btn--sm btn--ghost"
              onClick={() => setDraft(settings)}
              disabled={!dirty || saving}
            >
              {t("settings.revert")}
            </button>
            <button
              type="button"
              className="btn btn--sm btn--primary"
              onClick={() => draft && onSave(draft)}
              disabled={!dirty || saving}
            >
              {t("settings.save")}
            </button>
          </span>
        </>
      }
      bodyClassName="panel__body--tight"
    >
      {!draft ? (
        <Empty>{t("settings.no_config")}</Empty>
      ) : (
        <div className="settings">
          {error ? (
            <Banner
              tone="error"
              title={t("settings.failed_save")}
              detail={error}
            />
          ) : null}

          {/* ---- Language selection (§i18n) ---- */}
          <Section title={t("settings.language")}>
            <div className="row" style={{ gap: 8, alignItems: "center" }}>
              <label htmlFor="ui-language-select" className="settings__label" style={{ minWidth: 120 }}>
                {t("settings.language")}
              </label>
              <select
                id="ui-language-select"
                className="input input--sm"
                style={{ maxWidth: 240 }}
                value={lang}
                onChange={(e) => {
                  const nextLang = e.target.value as Language;
                  setLang(nextLang);
                  patch((current) => ({ ...current, ui_language: nextLang }));
                }}
                aria-label={t("settings.select_language")}
              >
                {SUPPORTED_LANGUAGES.map((item) => (
                  <option key={item.code} value={item.code}>
                    {item.flag} {item.nativeName} ({item.name})
                  </option>
                ))}
              </select>
            </div>
            <div className="tiny muted">
              {t("settings.language_hint")}
            </div>
          </Section>

          {/* ---- API keys (never echoed) ---- */}
          <Section title={t("settings.api_keys")}>
            <Banner
              tone="info"
              title={t("settings.key_security_title")}
              detail={t("settings.key_security_detail")}
            />
            <div className="row row--between row--wrap" style={{ marginBottom: 6 }}>
              <input
                className="input input--sm"
                type="search"
                value={providerFilter}
                onChange={(e) => setProviderFilter(e.target.value)}
                placeholder={t("settings.search_provider_placeholder")}
                style={{ maxWidth: 260 }}
                aria-label={t("settings.search_provider_label")}
              />
              <label className="check">
                <input
                  type="checkbox"
                  checked={onlyKeyRequired}
                  onChange={(e) => setOnlyKeyRequired(e.target.checked)}
                />
                {t("settings.only_key_required")}
              </label>
            </div>
            <div>
              {draft.providers.length === 0 ? (
                <Empty>
                  {t("settings.no_providers")}
                </Empty>
              ) : (
                draft.providers
                  .filter((item) => {
                    const row = health.find((entry) => entry.provider === item.provider);
                    const optionalKey = OPTIONAL_KEY_PROVIDERS.has(item.provider);
                    if (onlyKeyRequired && health.length > 0 && row && !row.requires_key && !optionalKey) {
                      return false;
                    }
                    if (providerFilter.trim()) {
                      return item.provider.toLowerCase().includes(providerFilter.trim().toLowerCase());
                    }
                    return true;
                  })
                  .map((item) => {
                    const row = health.find((entry) => entry.provider === item.provider);
                    const needsKey = row ? row.requires_key : true;
                    const optionalKey = OPTIONAL_KEY_PROVIDERS.has(item.provider);
                    const supportsKey = needsKey || optionalKey;
                    const healthLabel = getLocalizedHealthLabel(row?.state ?? "unknown", lang);
                    return (
                      <div key={item.provider} className="settings__row" style={{ alignItems: "center" }}>
                        <span className="keyrow__name" title={item.provider}>
                          <HealthDot state={row?.state ?? "unknown"} label={healthLabel} />
                          <span className="keyrow__label">{item.provider}</span>
                          {!supportsKey ? (
                            <span className="chip chip--info">
                              {t("settings.no_key_needed")}
                            </span>
                          ) : item.has_key ? (
                            <span className="chip chip--clean">
                              {t("settings.key_configured")}
                            </span>
                          ) : optionalKey ? (
                            <span className="chip chip--info">
                              {t("settings.optional_key")}
                            </span>
                          ) : (
                            <span className="chip chip--unknown">
                              {t("settings.no_key")}
                            </span>
                          )}
                          {row?.quota_exhausted ? (
                            <span className="chip chip--temp" title={`Reset: ${valueOrDash(row.quota_reset_at)}`}>
                              {t("settings.quota_exhausted")}
                            </span>
                          ) : null}
                        </span>

                        {supportsKey ? (
                          <span className="row" style={{ gap: 6, minWidth: 0 }}>
                            <input
                              className="input input--sm"
                              type="password"
                              autoComplete="new-password"
                              spellCheck={false}
                              value={keyInputs[item.provider] ?? ""}
                              placeholder={
                                item.provider === "scamalytics"
                                  ? (item.has_key ? `${t("settings.enter_new_key")} (user:key)` : "username:api_key")
                                  : item.has_key
                                    ? t("settings.enter_new_key")
                                    : optionalKey
                                      ? t("settings.optional_key_hint")
                                      : t("settings.paste_api_key")
                              }
                              onChange={(event) =>
                                setKeyInputs((current) => ({ ...current, [item.provider]: event.target.value }))
                              }
                              onKeyDown={(event) => {
                                if (event.key === "Enter") {
                                  event.preventDefault();
                                  void saveKey(item.provider);
                                }
                              }}
                              aria-label={
                                lang === "en"
                                  ? `API key for ${item.provider}`
                                  : lang === "zh"
                                  ? `${item.provider} 的 API 密钥`
                                  : `API key cho ${item.provider}`
                              }
                            />
                            <button
                              type="button"
                              className="btn btn--sm"
                              onClick={() => void saveKey(item.provider)}
                              disabled={busyKey === item.provider || !(keyInputs[item.provider] ?? "").trim()}
                            >
                              {busyKey === item.provider
                                ? "…"
                                : t("settings.save_key")}
                            </button>
                            {item.has_key ? (
                              <button
                                type="button"
                                className="btn btn--sm btn--danger"
                                onClick={() => void onClearKey(item.provider)}
                                title={t("settings.delete_key_title")}
                              >
                                {t("common.clear")}
                              </button>
                            ) : null}
                          </span>
                        ) : (
                          <span className="tiny muted">
                            {t("settings.free_source")}
                          </span>
                        )}

                        <span className="keyrow__state">
                          <label className="check">
                            <input
                              type="checkbox"
                              checked={item.enabled}
                              onChange={(event) => toggleProvider(item.provider, event.target.checked)}
                            />
                            {t("settings.enable")}
                          </label>
                        </span>
                      </div>
                    );
                  })
              )}
            </div>
          </Section>

          {/* ---- DNSBL groups ---- */}
          <Section title={t("settings.dnsbl_groups")}>
            <div className="row row--wrap">
              {DNSBL_GROUPS.map((group) => (
                <label key={group} className="check">
                  <input
                    type="checkbox"
                    checked={groupEnabled(group)}
                    onChange={(event) => toggleGroup(group, event.target.checked)}
                  />
                  {getLocalizedDnsblGroupLabel(group, lang)}
                </label>
              ))}
              <label
                className="check"
                title={t("settings.toggle_dnsbl_module")}
              >
                <input
                  type="checkbox"
                  checked={draft.dnsbl_enabled}
                  onChange={(event) =>
                    patch((current) => ({ ...current, dnsbl_enabled: event.target.checked }))
                  }
                />
                {t("settings.enable_blacklist_module")}
              </label>
            </div>
            <div className="tiny muted">
              {t("settings.dnsbl_votes_note")}
            </div>
          </Section>

          {/* ---- timeouts / concurrency ---- */}
          <Section title={t("settings.timeout")}>
            <div className="settings__grid">
              <span className="settings__label">
                {t("settings.timeout")} (ms)
                <NumberField
                  className="input input--sm input--num"
                  min={1000}
                  max={30000}
                  step={500}
                  value={draft.default_timeout_ms}
                  onCommit={(next) => patch((current) => ({ ...current, default_timeout_ms: next }))}
                />
              </span>
              <span className="settings__label">
                {t("settings.max_concurrency")}
                <NumberField
                  className="input input--sm input--num"
                  min={1}
                  max={32}
                  value={draft.max_concurrency}
                  onCommit={(next) => patch((current) => ({ ...current, max_concurrency: next }))}
                />
              </span>
              <span className="settings__label">
                {t("settings.failure_threshold")}
                <NumberField
                  className="input input--sm input--num"
                  min={1}
                  max={20}
                  value={draft.circuit_failure_threshold}
                  onCommit={(next) => patch((current) => ({ ...current, circuit_failure_threshold: next }))}
                />
              </span>
              <span className="settings__label">
                {t("settings.cooldown_minutes")}
                <NumberField
                  className="input input--sm input--num"
                  min={1}
                  max={120}
                  value={draft.circuit_cooldown_minutes}
                  onCommit={(next) => patch((current) => ({ ...current, circuit_cooldown_minutes: next }))}
                />
              </span>
            </div>
          </Section>

          {/* ---- export dir ---- */}
          <Section title={t("settings.export_directory")}>
            <div className="row" style={{ gap: 8 }}>
              <input
                className="input input--sm"
                value={draft.export_dir}
                onChange={(event) => patch((current) => ({ ...current, export_dir: event.target.value }))}
                placeholder="%USERPROFILE%\\Documents\\ip-checker"
                spellCheck={false}
                aria-label={t("settings.export_directory")}
              />
              <button type="button" className="btn btn--sm btn--ghost" onClick={() => void pickDir()}>
                {t("settings.browse")}
              </button>
            </div>
            <div className="tiny muted">
              {t("settings.export_dir_hint")}
            </div>
          </Section>

          {/* ---- geo DB ---- */}
          <Section title={t("settings.geo_db_versions")}>
            {geoDbVersions.length === 0 ? (
              <Empty>
                {t("settings.no_local_db")}
              </Empty>
            ) : (
              <table className="tbl tbl--compact">
                <thead>
                  <tr>
                    <th>Database</th>
                    <th>Version</th>
                    <th>{t("settings.updated_col")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {geoDbVersions.map((db) => (
                    <tr key={db.db_name} className={db.stale ? "tbl__row--warn" : undefined}>
                      <td className="tbl__name">{db.db_name}</td>
                      <td className="mono tiny">{valueOrDash(db.version)}</td>
                      <td className="mono tiny">{fmtDate(db.updated_at)}</td>
                      <td className="tiny">
                        {db.stale ? (
                          <span className="text-temp">
                            {t("settings.stale_db_badge")}
                          </span>
                        ) : (
                          <span className="text-clean">ok</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {staleDbs.length > 0 ? (
              <div className="tiny text-temp">
                {t("settings.stale_db_warning", { count: staleDbs.length })}
              </div>
            ) : null}
          </Section>

          {/* ---- provider health ---- */}
          <Section
            title={t("settings.provider_health_title")}
          >
            {health.length === 0 ? (
              <Empty>
                {t("settings.no_health_data")}
              </Empty>
            ) : (
              <div className="tblwrap" style={{ maxHeight: 150 }}>
                <table className="tbl tbl--compact">
                  <thead>
                    <tr>
                      <th>Provider</th>
                      <th>Health</th>
                      <th className="tbl__num">Success</th>
                      <th className="tbl__num">Latency</th>
                      <th className="tbl__num">Weight</th>
                      <th>{t("settings.notes_col")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {health.map((row) => (
                      <tr key={row.provider} className={cx(row.circuit_open && "tbl__row--error")}>
                        <td className="tbl__name">{row.provider}</td>
                        <td>
                          <span className={cx("chip", HEALTH_BADGE[row.state])}>
                            <HealthDot state={row.state} />
                            {getLocalizedHealthLabel(row.state, lang)}
                          </span>
                        </td>
                        <td className="tbl__num">{Math.round(row.success_rate)}%</td>
                        <td className="tbl__num">
                          {row.latency_avg_ms === null ? DASH : `${Math.round(row.latency_avg_ms)} ms`}
                        </td>
                        <td
                          className="tbl__num"
                          title={t("settings.effective_weight_hint")}
                        >
                          {row.effective_weight.toFixed(2)}
                        </td>
                        <td className="tiny">
                          {row.circuit_open ? (
                            <span className="text-bad">
                              {t("settings.circuit_open_until", { time: valueOrDash(row.circuit_open_until) })}
                            </span>
                          ) : row.requires_key && !row.has_key ? (
                            <span className="text-temp">
                              {lang === "en" ? "missing key" : lang === "zh" ? "缺少密钥" : "thiếu key"}
                            </span>
                          ) : row.quota_exhausted ? (
                            <span className="text-temp">
                              {t("settings.quota_exhausted")}
                            </span>
                          ) : (
                            <span className="muted">{row.last_error ? row.last_error : "—"}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          {/* ---- misc toggles ---- */}
          <Section title={t("settings.other_title")}>
            <div className="row row--wrap">
              <label className="check">
                <input
                  type="checkbox"
                  checked={draft.save_history}
                  onChange={(event) => patch((current) => ({ ...current, save_history: event.target.checked }))}
                />
                {t("settings.save_history_default")}
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={draft.leak_check_enabled}
                  onChange={(event) =>
                    patch((current) => ({ ...current, leak_check_enabled: event.target.checked }))
                  }
                />
                {t("settings.check_leak_proxy")}
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={draft.speed_check_enabled}
                  onChange={(event) =>
                    patch((current) => ({ ...current, speed_check_enabled: event.target.checked }))
                  }
                />
                {t("settings.check_speed_proxy")}
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={draft.auto_update_check}
                  onChange={(event) =>
                    patch((current) => ({ ...current, auto_update_check: event.target.checked }))
                  }
                />
                {t("settings.auto_update")}
              </label>
            </div>
            <div className="tiny muted">
              app_data_dir: <span className="mono">{valueOrDash(draft.app_data_dir)}</span> ·{" "}
              {t("settings.log_retention", { days: draft.log_retention_days })}
            </div>
          </Section>
        </div>
      )}
    </Panel>
  );
}

/** Number input helper: keeps the old value when the field is empty/NaN. */
function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const trimmed = raw.trim();
  if (trimmed === "") return fallback;
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

interface NumberFieldProps {
  value: number;
  min: number;
  max: number;
  step?: number;
  className?: string;
  disabled?: boolean;
  onCommit: (value: number) => void;
}

/**
 * Numeric setting field with a text draft.
 */
function NumberField({ value, min, max, step, className, disabled, onCommit }: NumberFieldProps) {
  const [text, setText] = useState(String(value));
  const [focused, setFocused] = useState(false);

  useEffect(() => {
    if (!focused) setText(String(value));
  }, [value, focused]);

  const commit = useCallback(() => {
    const next = clampNumber(text, min, max, value);
    setText(String(next));
    if (next !== value) onCommit(next);
  }, [max, min, onCommit, text, value]);

  return (
    <input
      className={className}
      type="number"
      min={min}
      max={max}
      step={step}
      value={text}
      disabled={disabled}
      onFocus={() => setFocused(true)}
      onChange={(event) => setText(event.target.value)}
      onBlur={() => {
        setFocused(false);
        commit();
      }}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
          (event.currentTarget as HTMLInputElement).blur();
        }
      }}
    />
  );
}

export default SettingsPanel;
