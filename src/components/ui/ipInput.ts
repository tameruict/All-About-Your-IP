/**
 * Client-side input validation — a *fast* mirror of the Rust validator
 * (`src-tauri/src/validator.rs`, spec §3.3 "validate IP ngay khi gõ").
 *
 * The backend stays authoritative: it re-validates and returns
 * `CommandError.kind === "private_ip"` for reserved ranges (§3.4). This module
 * only decides whether the Scan button is enabled and what the red message says.
 */

import type { ProxyCredentials, ProxyProtocol } from "../../lib/types";

export type ParsedInputKind = "empty" | "invalid" | "ip_only" | "proxy";

export interface ParsedInput {
  kind: ParsedInputKind;
  /** Canonical IPv4/IPv6 literal, when the host part parsed. */
  ip: string | null;
  /** Port for proxy mode. */
  port: number | null;
  ipVersion: 4 | 6 | null;
  /** Vietnamese message for the console line. */
  message: string;
  /** True only when the address is public / globally routable. */
  isPublic: boolean;
  /** Why it is not public, e.g. "loopback", "private (RFC1918)". */
  reservedReason: string | null;
  /** Extracted proxy credentials if present in the raw input */
  credentials?: ProxyCredentials | null;
  /** Extracted proxy protocol if present in the raw input */
  protocol?: ProxyProtocol | null;
  /** Cleaned display host:port or ip string */
  cleanedInput?: string;
}

const MAX_INPUT = 120;

/* ------------------------------------------------------------------ */
/* IPv4                                                                */
/* ------------------------------------------------------------------ */

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseIpv4(value: string): number[] | null {
  const m = IPV4_RE.exec(value);
  if (!m) return null;
  const octets = m.slice(1).map((part) => Number(part));
  if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  // Reject leading zeros: "010.0.0.1" is ambiguous (octal in some parsers).
  for (let i = 1; i <= 4; i += 1) {
    const part = m[i];
    if (part.length > 1 && part.startsWith("0")) return null;
  }
  return octets;
}

/** Best-effort parsing of the dotted forms that users actually type. */
export function parseIpv4Strict(value: string): string | null {
  const octets = parseIpv4(value.trim());
  return octets ? octets.join(".") : null;
}

/* ------------------------------------------------------------------ */
/* IPv6                                                                */
/* ------------------------------------------------------------------ */

/**
 * Structural IPv6 check: at most 8 groups of 1–4 hex digits, "::" used once,
 * optional trailing dotted-quad. Good enough for immediate feedback — the
 * Rust validator owns correctness.
 */
export function isIpv6Literal(value: string): boolean {
  let s = value.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!s.includes(":")) return false;
  if (/[^0-9a-fA-F:.]/.test(s)) return false;

  const doubleColonCount = s.split("::").length - 1;
  if (doubleColonCount > 1) return false;

  const hasIpv4Tail = s.includes(".");
  if (hasIpv4Tail) {
    const lastColon = s.lastIndexOf(":");
    const tail = s.slice(lastColon + 1);
    if (!parseIpv4(tail)) return false;
    s = `${s.slice(0, lastColon + 1)}0:0`;
  }

  const parts = s.split(":");
  if (doubleColonCount === 0 && parts.length !== 8) return false;
  if (doubleColonCount === 1 && parts.length > 8) return false;

  return parts.every((part) => part.length === 0 || /^[0-9a-fA-F]{1,4}$/.test(part));
}

/* ------------------------------------------------------------------ */
/* Reserved / private ranges (§1.3, §3.4, §7.1)                        */
/* ------------------------------------------------------------------ */

interface ReservedRange {
  /** First three octets are matched as prefix + bit length. */
  base: string;
  bits: number;
  reason: string;
}

const IPV4_RESERVED: ReservedRange[] = [
  { base: "0.0.0.0", bits: 8, reason: "dải 0.0.0.0/8 (không hợp lệ)" },
  { base: "10.0.0.0", bits: 8, reason: "private (RFC1918 10.0.0.0/8)" },
  { base: "100.64.0.0", bits: 10, reason: "CGNAT (RFC6598 100.64.0.0/10)" },
  { base: "127.0.0.0", bits: 8, reason: "loopback (127.0.0.0/8)" },
  { base: "169.254.0.0", bits: 16, reason: "link-local (169.254.0.0/16)" },
  { base: "172.16.0.0", bits: 12, reason: "private (RFC1918 172.16.0.0/12)" },
  { base: "192.0.0.0", bits: 24, reason: "IETF protocol assignments (192.0.0.0/24)" },
  { base: "192.0.2.0", bits: 24, reason: "tài liệu / TEST-NET-1 (192.0.2.0/24)" },
  { base: "192.168.0.0", bits: 16, reason: "private (RFC1918 192.168.0.0/16)" },
  { base: "198.18.0.0", bits: 15, reason: "benchmark (198.18.0.0/15)" },
  { base: "198.51.100.0", bits: 24, reason: "tài liệu / TEST-NET-2 (198.51.100.0/24)" },
  { base: "203.0.113.0", bits: 24, reason: "tài liệu / TEST-NET-3 (203.0.113.0/24)" },
  { base: "224.0.0.0", bits: 4, reason: "multicast (224.0.0.0/4)" },
  { base: "240.0.0.0", bits: 4, reason: "reserved (240.0.0.0/4)" },
  { base: "255.255.255.255", bits: 32, reason: "broadcast" },
];

function ipv4ToInt(value: string): number | null {
  const octets = parseIpv4(value);
  if (!octets) return null;
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function matchMask(value: number, base: string, bits: number): boolean {
  const baseInt = ipv4ToInt(base);
  if (baseInt === null) return false;
  if (bits === 32) return value === baseInt;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (baseInt & mask);
}

/** Returns a Vietnamese reason when the IPv4 is not publicly routable. */
export function ipv4ReservedReason(value: string): string | null {
  const asInt = ipv4ToInt(value);
  if (asInt === null) return "không phải IPv4 hợp lệ";
  for (const range of IPV4_RESERVED) {
    if (matchMask(asInt, range.base, range.bits)) return range.reason;
  }
  return null;
}

/** IPv6 reserved check: loopback ::1, unspecified ::, ULA fc00::/7, link-local fe80::/10. */
export function ipv6ReservedReason(value: string): string | null {
  const s = value.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (s === "::1") return "loopback (::1)";
  if (s === "::") return "unspecified (::)";
  if (/^f[cd][0-9a-f]{0,2}:/.test(s)) return "unique local (fc00::/7)";
  if (/^fe[89ab][0-9a-f]?:/.test(s)) return "link-local (fe80::/10)";
  if (/^ff[0-9a-f]{0,2}:/.test(s)) return "multicast (ff00::/8)";
  if (/^64:ff9b:/.test(s)) return "NAT64 prefix (64:ff9b::/96)";
  if (/^2001:db8:/.test(s)) return "tài liệu (2001:db8::/32)";
  return null;
}

/* ------------------------------------------------------------------ */
/* Whole-input parse                                                   */
/* ------------------------------------------------------------------ */

const EMPTY_RESULT: ParsedInput = {
  kind: "empty",
  ip: null,
  port: null,
  ipVersion: null,
  message: "",
  isPublic: false,
  reservedReason: null,
  credentials: null,
  protocol: null,
  cleanedInput: "",
};

export interface ExtractedProxy {
  host: string;
  portText: string | null;
  protocol: ProxyProtocol | null;
  credentials: ProxyCredentials | null;
  cleanedInput: string;
}

/** Detects a trailing ":port", handling the bracketed IPv6 form "[::1]:8080". */
export function splitHostPort(raw: string): { host: string; portText: string | null } {
  const trimmed = raw.trim();

  const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(trimmed);
  if (bracketed) return { host: bracketed[1], portText: bracketed[2] ?? null };

  // A bare IPv6 has >= 2 colons and no port: only treat the tail as a port
  // when exactly one colon exists (IPv4:port) or the tail is a decimal after
  // a bracketed host (handled above).
  const colonCount = (trimmed.match(/:/g) || []).length;
  if (colonCount === 1) {
    const idx = trimmed.lastIndexOf(":");
    return { host: trimmed.slice(0, idx), portText: trimmed.slice(idx + 1) };
  }
  return { host: trimmed, portText: null };
}

/**
 * Extracts proxy host, port, protocol and credentials from common formats:
 * - `scheme://username:password@ip:port`
 * - `scheme://ip:port`
 * - `scheme://ip`
 * - `username:password@ip:port`
 * - `ip:port:username:password`
 * - `[ipv6]:port:username:password`
 * - `ip:port`
 * - `ip`
 */
export function extractProxyParts(raw: string): ExtractedProxy {
  let s = raw.trim();
  let protocol: ProxyProtocol | null = null;
  let credentials: ProxyCredentials | null = null;

  // 1. Detect and strip scheme if present (e.g. socks5://, http://)
  const schemeMatch = /^([a-zA-Z0-9]+):\/\/(.*)$/.exec(s);
  if (schemeMatch) {
    const rawScheme = schemeMatch[1].toLowerCase();
    if (rawScheme === "http") protocol = "http";
    else if (rawScheme === "https") protocol = "https";
    else if (rawScheme === "socks5" || rawScheme === "socks") protocol = "socks5";
    else if (rawScheme === "socks4") protocol = "socks4";
    s = schemeMatch[2].trim();
  }

  // 2. Detect `username:password@ip:port` (credentials before @)
  const atIndex = s.lastIndexOf("@");
  if (atIndex > 0) {
    const userPart = s.slice(0, atIndex);
    s = s.slice(atIndex + 1).trim();
    const colonIdx = userPart.indexOf(":");
    if (colonIdx >= 0) {
      credentials = {
        username: userPart.slice(0, colonIdx),
        password: userPart.slice(colonIdx + 1),
      };
    } else {
      credentials = {
        username: userPart,
        password: "",
      };
    }
  }

  // 3. Detect `ip:port:username:password` (4 colon-separated parts)
  if (!credentials) {
    // 3a. Bracketed IPv6 form: [::1]:8080:username:password
    const bracketMatch = /^\[([^\]]+)\]:(\d{1,5}):([^:]+):(.*)$/.exec(s);
    if (bracketMatch) {
      const host = bracketMatch[1];
      const portText = bracketMatch[2];
      credentials = {
        username: bracketMatch[3],
        password: bracketMatch[4],
      };
      return {
        host,
        portText,
        protocol,
        credentials,
        cleanedInput: `[${host}]:${portText}`,
      };
    }

    // 3b. IPv4 form: 1.2.3.4:8080:username:password
    const parts = s.split(":");
    if (parts.length >= 4 && parseIpv4Strict(parts[0]) !== null && /^\d{1,5}$/.test(parts[1])) {
      const host = parts[0];
      const portText = parts[1];
      credentials = {
        username: parts[2],
        password: parts.slice(3).join(":"),
      };
      return {
        host,
        portText,
        protocol,
        credentials,
        cleanedInput: `${host}:${portText}`,
      };
    }
  }

  // 4. Default host & port splitting
  const { host, portText } = splitHostPort(s);
  const isBracketed = s.startsWith("[");
  const cleanedInput =
    portText !== null && portText !== ""
      ? host.includes(":") && !isBracketed
        ? `[${host}]:${portText}`
        : `${isBracketed ? `[${host}]` : host}:${portText}`
      : isBracketed
        ? `[${host}]`
        : host;

  return {
    host,
    portText,
    protocol,
    credentials,
    cleanedInput,
  };
}

/**
 * Parses whatever is in the console field.
 *
 * `IP`             → kind "ip_only"
 * `IP:port`        → kind "proxy"
 * malformed        → kind "invalid" with a Vietnamese message
 */
export function parseInput(raw: string): ParsedInput {
  const value = raw.trim();
  if (value.length === 0) return EMPTY_RESULT;

  if (value.length > MAX_INPUT) {
    return { ...EMPTY_RESULT, kind: "invalid", message: "Chuỗi nhập quá dài." };
  }

  const { host, portText, protocol, credentials, cleanedInput } = extractProxyParts(value);
  if (host.length === 0) {
    return { ...EMPTY_RESULT, kind: "invalid", message: "Thiếu địa chỉ IP trước dấu hai chấm." };
  }

  const ipv4 = parseIpv4Strict(host);
  const ipv6 = !ipv4 && isIpv6Literal(host) ? host.replace(/^\[|\]$/g, "") : null;

  if (!ipv4 && !ipv6) {
    return {
      ...EMPTY_RESULT,
      kind: "invalid",
      message: "Không phải IPv4 hoặc IPv6 hợp lệ. Ví dụ: 8.8.8.8 hoặc 1.2.3.4:8080",
    };
  }

  const ip = ipv4 ?? ipv6!;
  const ipVersion: 4 | 6 = ipv4 ? 4 : 6;

  let port: number | null = null;
  if (portText !== null && portText !== "") {
    if (!/^\d{1,5}$/.test(portText)) {
      return { ...EMPTY_RESULT, ip, ipVersion, kind: "invalid", message: "Port phải là số (1–65535)." };
    }
    const parsedPort = Number(portText);
    if (parsedPort < 1 || parsedPort > 65535) {
      return { ...EMPTY_RESULT, ip, ipVersion, kind: "invalid", message: "Port phải trong khoảng 1–65535." };
    }
    port = parsedPort;
  } else if (portText !== null) {
    return { ...EMPTY_RESULT, ip, ipVersion, kind: "invalid", message: "Thiếu số port sau dấu hai chấm." };
  }

  const reservedReason = ipVersion === 4 ? ipv4ReservedReason(ip) : ipv6ReservedReason(ip);
  const isPublic = reservedReason === null;

  if (!isPublic) {
    // A loopback / private address WITH a port is a legitimate proxy target:
    // ssh -D, Tor, Burp all listen on 127.0.0.1. The reserved-range verdict
    // answers "does this address have reputational data to look up", not
    // "can we dial through it". Conflating the two made the Scan button refuse
    // a perfectly good local proxy while the backend was already accepting it
    // (`validator::proxy_host_is_usable`), so the whole proxy mode was dead at
    // the front door — §1.2's second mode never ran.
    if (port !== null && isDialable(ip)) {
      return {
        kind: "proxy",
        ip,
        port,
        ipVersion,
        isPublic: true,
        reservedReason: null,
        message: `Proxy-check: ${ip}:${port} — sẽ đo IP thoát, leak và tốc độ.`,
        protocol,
        credentials,
        cleanedInput,
      };
    }
    if (port !== null) {
      // Reserved address that cannot carry a TCP stream (0.0.0.0, multicast,
      // broadcast). The backend refuses these in `proxy_host_is_usable`, so the
      // console must refuse them too — otherwise Scan lights up and the check
      // dies with a backend error instead of an inline explanation.
      return {
        kind: "proxy",
        ip,
        port,
        ipVersion,
        isPublic: false,
        reservedReason,
        message: `Không dial được tới ${ip}:${port} (${reservedReason}) — dùng địa chỉ unicast.`,
        protocol,
        credentials,
        cleanedInput,
      };
    }
    return {
      kind: "ip_only",
      ip,
      port: null,
      ipVersion,
      isPublic,
      reservedReason,
      message: `IP ${reservedReason} — không check được. Cần IP public.`,
      protocol,
      credentials,
      cleanedInput,
    };
  }

  if (port !== null) {
    return {
      kind: "proxy",
      ip,
      port,
      ipVersion,
      isPublic,
      reservedReason: null,
      message: `Proxy-check: ${ip}:${port} — sẽ đo IP thoát, leak và tốc độ.`,
      protocol,
      credentials,
      cleanedInput,
    };
  }

  return {
    kind: "ip_only",
    ip,
    port: null,
    ipVersion,
    isPublic,
    reservedReason: null,
    message: "IP-only: check geo, ASN, fraud, blacklist, mạng. Leak và tốc độ cần proxy.",
    protocol,
    credentials,
    cleanedInput,
  };
}

/**
 * Can this address carry a TCP connection at all?
 *
 * Mirror of `validator::proxy_host_is_usable` (Rust). Only the addresses that
 * can never be a destination are refused: `0.0.0.0` / `::` mean "any interface"
 * to a listener, multicast and broadcast have no TCP stream. Everything else —
 * including all of RFC1918 and loopback — is dialable, which is exactly what
 * `ssh -D`, Tor and Burp rely on.
 *
 * Keep this in sync with the Rust side; `tests/harness/x12-usability-parity.mjs`
 * is the gate that fails when the two disagree.
 */
export function isDialable(ip: string): boolean {
  const v4 = parseIpv4(ip);
  if (v4) {
    const [a, b, c, d] = v4;
    if (a === 0 && b === 0 && c === 0 && d === 0) return false; // 0.0.0.0
    if (a >= 224 && a <= 239) return false; // 224.0.0.0/4 multicast
    if (a === 255 && b === 255 && c === 255 && d === 255) return false; // broadcast
    return true;
  }
  const v6 = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (v6 === "::" || v6 === "::0") return false; // unspecified
  if (/^ff/.test(v6)) return false; // ff00::/8 multicast
  // `::ffff:0.0.0.0` is the v6 spelling of 0.0.0.0.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v6);
  if (mapped) return isDialable(mapped[1]);
  return true;
}

/**
 * §1.2 — a proxy is dialed, not looked up. Reserved/loopback ranges are fine
 * for the former and meaningless for the latter, so proxy targets are always
 * scannable as long as the port parses and the address is dialable.
 *
 * Backend counterpart: `validator::proxy_host_is_usable()`. The two must agree;
 * `tests/harness/x12-usability-parity.mjs` enforces that.
 */
export function isUsableProxyTarget(parsed: ParsedInput): boolean {
  return parsed.kind === "proxy" && parsed.port !== null && parsed.isPublic;
}

/**
 * Convenience for the Scan button and the console styling.
 *
 * Two different questions are folded here on purpose, and they are NOT the same
 * one: `isUsableProxyTarget` answers "may we scan this through a proxy", while
 * `isPublic` answers "is there reputation data to look up". For `ip_only` they
 * coincide; for `proxy` they are opposite. Keeping the proxy case first is what
 * lets `127.0.0.1:1080` scan while `127.0.0.1` (no port) stays blocked (§13.2).
 */
export function isScannable(parsed: ParsedInput): boolean {
  if (isUsableProxyTarget(parsed)) return true;
  return parsed.kind === "ip_only" && parsed.isPublic;
}
