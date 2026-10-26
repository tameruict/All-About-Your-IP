/**
 * HEADER — §3.2: "IP CHECKER // TERMINAL | Provider health: ● ● ○".
 *
 * The header is one of only two places allowed to show a scanline (§3.1).
 * It also hosts the global banners' right-hand slots: app version, offline
 * state and the button that opens Settings.
 */

import type { ProviderHealth } from "../lib/types";
import { useI18n, type Language } from "../lib/i18n";
import { cx } from "./ui/meta";

export interface AppHeaderProps {
  /** Provider health rows; only a summary dot row is rendered here (§5.5). */
  health: ProviderHealth[];
  /** App/build version string, when the backend knows it. */
  appVersion?: string | null;
  /** True while a check is streaming. */
  scanning: boolean;
  /** True when the Tauri IPC bridge is missing (plain-browser dev). */
  bridgeMissing: boolean;
  onToggleSettings: () => void;
  settingsOpen: boolean;
}

/** Condenses health rows into green / yellow / red counters. */
function summarise(health: ProviderHealth[]) {
  let green = 0;
  let yellow = 0;
  let red = 0;
  let unknown = 0;
  for (const provider of health) {
    if (!provider.enabled) continue;
    switch (provider.state) {
      case "green":
        green += 1;
        break;
      case "yellow":
        yellow += 1;
        break;
      case "red":
        red += 1;
        break;
      default:
        unknown += 1;
    }
  }
  return { green, yellow, red, unknown, total: green + yellow + red + unknown };
}

export function AppHeader({
  health,
  appVersion,
  scanning,
  bridgeMissing,
  onToggleSettings,
  settingsOpen,
}: AppHeaderProps) {
  const { lang, setLang, t } = useI18n();
  const summary = summarise(health);
  const hasHealth = summary.total > 0;

  const languages: { code: Language; label: string; title: string }[] = [
    { code: "vi", label: "VI", title: "Tiếng Việt" },
    { code: "en", label: "EN", title: "English" },
    { code: "zh", label: "ZH", title: "简体中文" },
  ];

  return (
    <header className="hdr">
      <div className="hdr__title">
        <h1>{t("header.title")}</h1>
        <span className="hdr__sub">{t("header.subtitle")}</span>
      </div>

      <div className="hdr__right">
        {scanning ? <span className="chip chip--plain">{t("header.scanning")}</span> : null}

        {bridgeMissing ? (
          <span className="chip chip--bad" title={t("header.no_ipc_hint")}>
            {t("header.no_ipc")}
          </span>
        ) : null}

        <div className="hdr__meta" title={t("header.health_tooltip")}>
          <span className="hdr__label">{t("header.provider_health")}</span>
          {hasHealth ? (
            <span className="row">
              {summary.green > 0 ? (
                <span className={cx("dotrow")} title={t("header.providers_good", { count: summary.green })}>
                  <span className="dot dot--green" />
                  <span className="dotrow__name num">{summary.green}</span>
                </span>
              ) : null}
              {summary.yellow > 0 ? (
                <span className="dotrow" title={t("header.providers_slow", { count: summary.yellow })}>
                  <span className="dot dot--yellow" />
                  <span className="dotrow__name num">{summary.yellow}</span>
                </span>
              ) : null}
              {summary.red > 0 ? (
                <span className="dotrow" title={t("header.providers_error", { count: summary.red })}>
                  <span className="dot dot--red" />
                  <span className="dotrow__name num">{summary.red}</span>
                </span>
              ) : null}
              {summary.unknown > 0 ? (
                <span className="dotrow" title={t("header.providers_unknown", { count: summary.unknown })}>
                  <span className="dot dot--unknown" />
                  <span className="dotrow__name num">{summary.unknown}</span>
                </span>
              ) : null}
            </span>
          ) : (
            <span className="row">
              <span className="dot dot--unknown" />
              <span className="dot dot--unknown" />
              <span className="dot dot--unknown" />
              <span className="dotrow__name">{bridgeMissing ? t("verdict.not_checked") : t("reputation.no_data")}</span>
            </span>
          )}
        </div>

        {appVersion ? <span className="hdr__meta mono">v{appVersion}</span> : null}

        {/* Compact Language Switcher */}
        <div className="row" style={{ gap: 2 }} role="group" aria-label={t("header.lang_select")}>
          {languages.map((l) => (
            <button
              key={l.code}
              type="button"
              className={cx("btn", "btn--sm", lang === l.code ? "btn--primary" : "btn--ghost")}
              onClick={() => setLang(l.code)}
              title={l.title}
              style={{ padding: "2px 6px", fontSize: "10px", minWidth: 26 }}
            >
              {l.label}
            </button>
          ))}
        </div>

        <button
          type="button"
          className={cx("btn", "btn--sm", settingsOpen && "btn--primary")}
          onClick={onToggleSettings}
          aria-expanded={settingsOpen}
        >
          {t("header.settings")}
        </button>
      </div>
    </header>
  );
}

export default AppHeader;
