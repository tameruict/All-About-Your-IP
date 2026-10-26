/**
 * InputConsole — §3.2 row 2 + §3.3.
 *
 * Required behaviour:
 * - validate as the user types (red when malformed) — §3.3, test §13.3;
 * - auto-detect IP-only vs proxy-check from `IP:port` (§1.2);
 * - protocol dropdown only appears when a port is present;
 * - "Lưu vào lịch sử" checkbox, default ON;
 * - Scan disabled while scanning (and while the input is invalid).
 *
 * Proxy credentials are transient (§8.4 / types.ts): they live in this
 * component's state only and are wiped as soon as the scan starts.
 */

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";

import type { ProxyCredentials, ProxyProtocol } from "../lib/types";
import {
  extractProxyParts,
  isScannable,
  isUsableProxyTarget,
  parseInput,
  type ParsedInput,
} from "./ui/ipInput";
import { cx, getLocalizedInputMessage, PROTOCOL_LABELS } from "./ui/meta";
import { useI18n } from "../lib/i18n";

export interface ScanRequest {
  input: string;
  mode: "ip_only" | "proxy";
  protocol: ProxyProtocol | null;
  credentials: ProxyCredentials | null;
  saveToHistory: boolean;
  run_leak_check?: boolean;
  run_speed_check?: boolean;
  timeout_ms?: number | null;
}

export interface InputConsoleProps {
  /** True while a check is streaming. */
  scanning: boolean;
  /** Disabled when the Tauri bridge is unavailable. */
  disabled?: boolean;
  onSubmit: (request: ScanRequest) => void;
  /** Called when the parsed value becomes a private/reserved IP (§3.4 banner). */
  onParsedChange?: (parsed: ParsedInput) => void;
  /** Prefill (used by "Check lại" from the history panel). */
  initialValue?: string;
  initialProtocol?: ProxyProtocol | null;
}

const PROTOCOLS: ProxyProtocol[] = ["http", "https", "socks5", "socks4"];

export function InputConsole({
  scanning,
  disabled,
  onSubmit,
  onParsedChange,
  initialValue = "",
  initialProtocol = "http",
}: InputConsoleProps) {
  const { lang, t } = useI18n();
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [raw, setRaw] = useState(initialValue);
  const [protocol, setProtocol] = useState<ProxyProtocol>(initialProtocol ?? "http");
  const [saveToHistory, setSaveToHistory] = useState(true);
  const [credOpen, setCredOpen] = useState(false);
  const [username, setunknown-user] = useState("");
  const [password, setPassword] = useState("");
  const [clipboardAvailable, setClipboardAvailable] = useState(false);

  useEffect(() => {
    if (typeof navigator !== "undefined" && Boolean(navigator.clipboard?.readText)) {
      setClipboardAvailable(true);
    }
  }, []);

  /**
   * Global shortcut: Ctrl+K / Cmd+K focuses the input and selects content.
   */
  useEffect(() => {
    const handleGlobalKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && (event.key === "k" || event.key === "K")) {
        event.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener("keydown", handleGlobalKeyDown);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown);
  }, []);

  /**
   * The field used to seed from `initialValue` once and never again, so loading
   * a cache row or pressing "Check lại" left the PREVIOUS query in the box.
   * Follow the prop when it changes, but never clobber what the user typed.
   */
  const parseIpInput = parseInput;
  const lastSeedRef = useRef<string>(initialValue);
  useEffect(() => {
    if (initialValue === lastSeedRef.current) return;
    lastSeedRef.current = initialValue;
    setRaw((current) => (current.trim() === initialValue.trim() ? current : initialValue));
    onParsedChange?.(parseIpInput(initialValue));
  }, [initialValue, onParsedChange, parseIpInput]);

  /**
   * Announce invalid input once, 500 ms after the user stops typing. The visible
   * message used to be `role="status"`, so every keystroke in "8.8.8.8" fired a
   * new announcement — five sentences, mostly "không hợp lệ".
   */
  const [announce, setAnnounce] = useState("");

  const parsed = useMemo(() => parseInput(raw), [raw]);
  const isInvalid = parsed.kind === "invalid";
  const canScan = isScannable(parsed) && !scanning && !disabled;

  useEffect(() => {
    if (parsed.kind !== "invalid") {
      setAnnounce("");
      return;
    }
    const timer = window.setTimeout(() => setAnnounce(getLocalizedInputMessage(parsed, lang)), 500);
    return () => window.clearTimeout(timer);
  }, [parsed, lang]);

  const handleClear = useCallback(() => {
    setRaw("");
    setunknown-user("");
    setPassword("");
    setCredOpen(false);
    onParsedChange?.(parseInput(""));
  }, [onParsedChange]);

  const update = useCallback(
    (next: string) => {
      const extracted = extractProxyParts(next);
      if (extracted.credentials) {
        setunknown-user(extracted.credentials.username);
        setPassword(extracted.credentials.password);
        setCredOpen(true);
      }
      if (extracted.protocol) {
        setProtocol(extracted.protocol);
      }
      const cleanVal =
        extracted.credentials || extracted.protocol ? extracted.cleanedInput : next;
      setRaw(cleanVal);
      onParsedChange?.(parseInput(cleanVal));
    },
    [onParsedChange],
  );

  const onPaste = useCallback(
    (event: React.ClipboardEvent<HTMLInputElement>) => {
      const text = event.clipboardData.getData("text");
      if (!text) return;
      const extracted = extractProxyParts(text);
      if (
        extracted.credentials ||
        extracted.protocol ||
        (extracted.cleanedInput && extracted.cleanedInput !== text.trim())
      ) {
        event.preventDefault();
        if (extracted.credentials) {
          setunknown-user(extracted.credentials.username);
          setPassword(extracted.credentials.password);
          setCredOpen(true);
        }
        if (extracted.protocol) {
          setProtocol(extracted.protocol);
        }
        const cleanVal = extracted.cleanedInput;
        setRaw(cleanVal);
        onParsedChange?.(parseInput(cleanVal));
      }
    },
    [onParsedChange],
  );

  const submit = useCallback(() => {
    const current = parseInput(raw);
    if (!isScannable(current) || scanning || disabled) return;

    const credentials: ProxyCredentials | null =
      current.kind === "proxy" && (username.length > 0 || password.length > 0)
        ? { username, password }
        : null;

    onSubmit({
      input: raw.trim(),
      mode: current.kind === "proxy" ? "proxy" : "ip_only",
      protocol: current.kind === "proxy" ? protocol : null,
      credentials,
      saveToHistory,
    });

    // Credentials never outlive the request (§8.4).
    setunknown-user("");
    setPassword("");
    setCredOpen(false);
  }, [disabled, onSubmit, password, protocol, raw, saveToHistory, scanning, username]);

  const handlePasteAndScan = useCallback(async () => {
    if (scanning || disabled) return;
    try {
      if (!navigator.clipboard?.readText) return;
      const clipboardText = await navigator.clipboard.readText();
      const trimmed = clipboardText.trim();
      if (!trimmed) return;

      const extracted = extractProxyParts(trimmed);
      let curunknown-user = username;
      let curPassword = password;
      let curProtocol = protocol;

      if (extracted.credentials) {
        curunknown-user = extracted.credentials.username;
        curPassword = extracted.credentials.password;
        setunknown-user(curunknown-user);
        setPassword(curPassword);
        setCredOpen(true);
      }
      if (extracted.protocol) {
        curProtocol = extracted.protocol;
        setProtocol(curProtocol);
      }

      const cleanVal = extracted.cleanedInput;
      setRaw(cleanVal);
      const parsedNow = parseInput(cleanVal);
      onParsedChange?.(parsedNow);

      if (isScannable(parsedNow)) {
        const credentials: ProxyCredentials | null =
          parsedNow.kind === "proxy" && (curunknown-user.length > 0 || curPassword.length > 0)
            ? { username: curunknown-user, password: curPassword }
            : null;

        onSubmit({
          input: cleanVal.trim(),
          mode: parsedNow.kind === "proxy" ? "proxy" : "ip_only",
          protocol: parsedNow.kind === "proxy" ? curProtocol : null,
          credentials,
          saveToHistory,
        });

        setunknown-user("");
        setPassword("");
        setCredOpen(false);
      }
    } catch (err) {
      console.warn("Clipboard read failed:", err);
    }
  }, [disabled, onParsedChange, onSubmit, password, protocol, saveToHistory, scanning, username]);

  const onKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    } else if (event.key === "Escape") {
      event.preventDefault();
      handleClear();
    }
  };

  const message = getLocalizedInputMessage(parsed, lang);
  // `isScannable` is the single source of truth: a reserved IP *with* a port is
  // a usable proxy (§1.2), so it must not paint the field as an error.
  const accepted = isScannable(parsed);
  const messageTone = isInvalid
    ? "console__msg--error"
    : accepted
      ? "console__msg--ok"
      : parsed.kind === "empty"
        ? ""
        : "console__msg--error";

  return (
    <div className="console">
      <div className="console__row">
        <label className="console__prompt" htmlFor={inputId} aria-hidden="true">
          &gt;_
        </label>

        <div className="console__field">
          <input
            ref={inputRef}
            id={inputId}
            className={cx(
              "console__input",
              isInvalid && "console__input--invalid",
              !isInvalid && accepted ? "console__input--valid" : undefined,
            )}
            value={raw}
            onChange={(event) => update(event.target.value)}
            onPaste={onPaste}
            onKeyDown={onKeyDown}
            placeholder={t("input.placeholder")}
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            inputMode="text"
            aria-invalid={isInvalid || (!accepted && parsed.kind !== "empty")}
            aria-describedby={`${inputId}-msg`}
            /* Stays editable during a run: disabling it for 30–60 s gave the
               user nothing to do and no way to prepare the next query. */
            title={t("input.tip_ctrl_k")}
          />
          {raw.length === 0 ? (
            <span
              className="console__kbd-badge"
              onClick={() => inputRef.current?.focus()}
              title={t("input.tip_ctrl_k")}
            >
              Ctrl+K
            </span>
          ) : (
            <button
              type="button"
              className="console__clear-btn"
              onClick={handleClear}
              title={t("input.clear")}
              aria-label={t("input.clear")}
            >
              ✕
            </button>
          )}
        </div>

        {/* Protocol only matters in proxy-check mode (§3.3). */}
        {parsed.kind === "proxy" ? (
          <div className="console__mode">
            <label className="sr-only" htmlFor={`${inputId}-proto`}>
              {lang === "en" ? "Proxy protocol" : lang === "zh" ? "代理协议" : "Giao thức proxy"}
            </label>
            <select
              id={`${inputId}-proto`}
              className="select"
              value={protocol}
              onChange={(event) => setProtocol(event.target.value as ProxyProtocol)}
              disabled={scanning}
              title={lang === "en" ? "Proxy protocol" : lang === "zh" ? "代理协议" : "Giao thức của proxy"}
            >
              {PROTOCOLS.map((item) => (
                <option key={item} value={item}>
                  {PROTOCOL_LABELS[item]}
                </option>
              ))}
            </select>
            <button
              type="button"
              className={cx("btn", "btn--sm", "btn--ghost")}
              onClick={() => setCredOpen((open) => !open)}
              aria-expanded={credOpen}
              disabled={scanning}
              title={t("input.proxy_auth")}
            >
              {credOpen
                ? lang === "en"
                  ? "Hide Proxy Auth"
                  : lang === "zh"
                  ? "隐藏代理认证"
                  : `Ẩn ${t("input.proxy_auth")}`
                : t("input.proxy_auth")}
            </button>
          </div>
        ) : null}

        <div className="console__mode">
          <span
            className={cx(
              "chip",
              parsed.kind === "empty" && "chip--muted",
              parsed.kind === "ip_only" && "chip--plain",
              parsed.kind === "proxy" && "chip--plain",
              isInvalid && "chip--bad",
            )}
            title={
              lang === "en"
                ? "Mode auto-detected from your input"
                : lang === "zh"
                ? "根据输入内容自动识别模式"
                : "Chế độ được tự nhận từ nội dung bạn nhập"
            }
          >
            {parsed.kind === "proxy"
              ? t("input.mode_proxy")
              : parsed.kind === "ip_only"
                ? t("input.mode_ip")
                : parsed.reservedReason
                  ? t("input.reserved_ip")
                  : isInvalid
                    ? t("input.invalid_ip")
                    : t("verdict.not_checked")}
          </span>
        </div>

        {clipboardAvailable ? (
          <button
            type="button"
            className="btn btn--ghost"
            onClick={handlePasteAndScan}
            disabled={scanning || disabled}
            title={t("input.paste")}
          >
            {t("input.paste")}
          </button>
        ) : null}

        <button
          type="button"
          className="btn btn--primary"
          onClick={submit}
          disabled={!canScan}
          title={!canScan && !scanning ? t("input.invalid_ip") : t("input.scan")}
        >
          {scanning ? t("input.scanning") : t("input.scan")}
        </button>
      </div>

      {credOpen && parsed.kind === "proxy" ? (
        <div className="console__row">
          <label className="sr-only" htmlFor={`${inputId}-user`}>
            {lang === "en" ? "Proxy username" : lang === "zh" ? "代理用户名" : "unknown-user proxy"}
          </label>
          <input
            id={`${inputId}-user`}
            className="input input--sm"
            style={{ maxWidth: 200 }}
            value={username}
            onChange={(event) => setunknown-user(event.target.value)}
            placeholder={t("input.username")}
            autoComplete="off"
            spellCheck={false}
            disabled={scanning}
          />
          <label className="sr-only" htmlFor={`${inputId}-pass`}>
            {lang === "en" ? "Proxy password" : lang === "zh" ? "代理密码" : "Password proxy"}
          </label>
          <input
            id={`${inputId}-pass`}
            className="input input--sm"
            style={{ maxWidth: 200 }}
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder={t("input.password")}
            autoComplete="off"
            spellCheck={false}
            disabled={scanning}
          />
          <span className="tiny muted">
            {lang === "en"
              ? "Credentials are never saved to history."
              : lang === "zh"
              ? "凭证不会保存至历史记录。"
              : "Không lưu credential vào lịch sử."}
          </span>
        </div>
      ) : null}

      <div className="console__meta">
        <div id={`${inputId}-msg`} className={cx("console__msg", messageTone)}>
          {message}
        </div>

        {/* Debounced, polite: only the transition into an error is read aloud. */}
        <span className="sr-only" role="status" aria-live="polite">
          {announce}
        </span>

        <div className="console__shortcuts" title={t("input.tip_ctrl_k")}>
          <span className="kbd-hint">{t("input.tip_ctrl_k")}</span>
        </div>

        <label
          className="check"
          title={
            lang === "en"
              ? `${t("input.save_history")} — credentials are never saved to history.`
              : lang === "zh"
              ? `${t("input.save_history")} — 绝不保存凭证到历史记录。`
              : `${t("input.save_history")} — Không lưu credential vào lịch sử.`
          }
        >
          <input
            type="checkbox"
            checked={saveToHistory}
            onChange={(event) => setSaveToHistory(event.target.checked)}
            disabled={scanning}
          />
          {t("input.save_history")}
        </label>
      </div>
    </div>
  );
}

export default InputConsole;
