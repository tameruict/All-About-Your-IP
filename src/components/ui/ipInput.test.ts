/**
 * Parity tests for the input parser — §1.2 (two modes), §3.3 (validate as you
 * type), §3.4 / §13.2 (private IPs are not checkable targets).
 *
 * These are plain `node --test` cases so they run without adding a test runner
 * to the Tauri build (`npm run test:frontend`). The important case is the pair
 * `127.0.0.1:1080` vs `127.0.0.1`: the first must scan, the second must stay
 * blocked. Collapsing them is what broke proxy mode three times.
 *
 * Backend counterpart: `src-tauri/src/validator.rs::proxy_host_is_usable`.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  isDialable,
  isScannable,
  isUsableProxyTarget,
  parseInput,
} from "./ipInput.ts";

/* ------------------------------------------------------------------ */
/* The six cases the delivery is pinned on                             */
/* ------------------------------------------------------------------ */

test("127.0.0.1:1080 is a scannable proxy target", () => {
  const parsed = parseInput("127.0.0.1:1080");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.port, 1080);
  assert.equal(isScannable(parsed), true, "loopback proxy phải scan được (§1.2)");
  assert.equal(isUsableProxyTarget(parsed), true);
  assert.match(parsed.message, /^Proxy-check: 127\.0\.0\.1:1080/);
});

test("127.0.0.1 without a port stays blocked (§13.2)", () => {
  const parsed = parseInput("127.0.0.1");
  assert.equal(parsed.kind, "ip_only");
  assert.equal(isScannable(parsed), false, "loopback IP-only vẫn phải bị chặn");
  assert.equal(isUsableProxyTarget(parsed), false);
  assert.match(parsed.message, /loopback/i, "banner loopback (127.0.0.0/8) phải còn");
  assert.ok(parsed.reservedReason, "reservedReason phải được giữ để App.tsx hiện banner");
});

test("10.0.0.5:8080 is a scannable proxy target", () => {
  const parsed = parseInput("10.0.0.5:8080");
  assert.equal(parsed.kind, "proxy");
  assert.equal(isScannable(parsed), true);
  assert.match(parsed.message, /Proxy-check: 10\.0\.0\.5:8080/);
});

test("0.0.0.0:1080 follows the backend and is refused", () => {
  const parsed = parseInput("0.0.0.0:1080");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.port, 1080);
  // validator::proxy_host_is_usable rejects the unspecified address, so the
  // front-end must reject it too — otherwise Scan lights up and the check dies
  // with a backend error instead of an inline explanation.
  assert.equal(isDialable("0.0.0.0"), false);
  assert.equal(isScannable(parsed), false);
  assert.equal(isUsableProxyTarget(parsed), false);
});

test("192.168.1.1 without a port stays blocked", () => {
  const parsed = parseInput("192.168.1.1");
  assert.equal(parsed.kind, "ip_only");
  assert.equal(isScannable(parsed), false);
  assert.match(parsed.message, /private/i);
});

test("8.8.8.8 is a scannable IP-only target", () => {
  const parsed = parseInput("8.8.8.8");
  assert.equal(parsed.kind, "ip_only");
  assert.equal(isScannable(parsed), true);
  assert.equal(parsed.isPublic, true);
});

/* ------------------------------------------------------------------ */
/* Dialability — mirror of validator::proxy_host_is_usable             */
/* ------------------------------------------------------------------ */

test("isDialable matches the Rust rule for the sample set", () => {
  // Unicast in any range: dialable, including every RFC1918 / loopback block.
  for (const ip of ["8.8.8.8", "127.0.0.1", "10.0.0.5", "192.168.1.1", "::1", "2001:db8::1"]) {
    assert.equal(isDialable(ip), true, `${ip} phải dial được`);
  }
  // Never a TCP destination.
  for (const ip of ["0.0.0.0", "255.255.255.255", "224.0.0.1", "239.255.255.250", "::", "::ffff:0.0.0.0"]) {
    assert.equal(isDialable(ip), false, `${ip} không được coi là dialable`);
  }
});

/* ------------------------------------------------------------------ */
/* Regression guards                                                   */
/* ------------------------------------------------------------------ */

test("a private proxy keeps reservedReason = null so no banner is raised", () => {
  const parsed = parseInput("127.0.0.1:1080");
  assert.equal(parsed.reservedReason, null);
  assert.equal(parsed.isPublic, true, "proxy mode không hỏi danh tiếng ⇒ coi như usable");
});

test("an IPv6 loopback proxy is accepted with brackets", () => {
  const parsed = parseInput("[::1]:1080");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ipVersion, 6);
  assert.equal(isScannable(parsed), true);
});

test("a malformed port is still invalid, not a proxy", () => {
  const parsed = parseInput("127.0.0.1:99999");
  assert.equal(parsed.kind, "invalid");
  assert.equal(isScannable(parsed), false);
});

test("a reserved address without a port never becomes scannable", () => {
  for (const ip of ["10.0.0.5", "192.168.1.1", "169.254.1.1", "100.64.0.1", "[::1]"]) {
    assert.equal(isScannable(parseInput(ip)), false, `${ip} (no port) phải bị chặn`);
  }
});

/* ------------------------------------------------------------------ */
/* Smart proxy parser formats                                          */
/* ------------------------------------------------------------------ */

test("parses ip:port:username:password format", () => {
  const parsed = parseInput("103.152.112.5:8080:user123:my_secret_pass");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ip, "103.152.112.5");
  assert.equal(parsed.port, 8080);
  assert.equal(parsed.cleanedInput, "103.152.112.5:8080");
  assert.deepEqual(parsed.credentials, { username: "user123", password: "my_secret_pass" });
  assert.equal(isScannable(parsed), true);
});

test("parses ip:port:username:password with colon in password", () => {
  const parsed = parseInput("1.2.3.4:1080:alice:pass:word:123");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ip, "1.2.3.4");
  assert.equal(parsed.port, 1080);
  assert.equal(parsed.cleanedInput, "1.2.3.4:1080");
  assert.deepEqual(parsed.credentials, { username: "alice", password: "pass:word:123" });
});

test("parses username:password@ip:port format", () => {
  const parsed = parseInput("admin:super_secret@8.8.8.8:3128");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ip, "8.8.8.8");
  assert.equal(parsed.port, 3128);
  assert.equal(parsed.cleanedInput, "8.8.8.8:3128");
  assert.deepEqual(parsed.credentials, { username: "admin", password: "super_secret" });
  assert.equal(isScannable(parsed), true);
});

test("parses scheme://username:password@ip:port format (socks5, http, etc.)", () => {
  const parsed = parseInput("socks5://alice:secret99@1.1.1.1:1080");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ip, "1.1.1.1");
  assert.equal(parsed.port, 1080);
  assert.equal(parsed.protocol, "socks5");
  assert.equal(parsed.cleanedInput, "1.1.1.1:1080");
  assert.deepEqual(parsed.credentials, { username: "alice", password: "secret99" });
  assert.equal(isScannable(parsed), true);
});

test("parses scheme://ip:port format", () => {
  const parsed = parseInput("http://192.168.1.1:8080");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ip, "192.168.1.1");
  assert.equal(parsed.port, 8080);
  assert.equal(parsed.protocol, "http");
  assert.equal(parsed.cleanedInput, "192.168.1.1:8080");
  assert.equal(parsed.credentials, null);
  assert.equal(isScannable(parsed), true);
});

test("parses bracketed ipv6 proxy with credentials [::1]:8080:user:pass", () => {
  const parsed = parseInput("[::1]:8080:john:doe_pass");
  assert.equal(parsed.kind, "proxy");
  assert.equal(parsed.ip, "::1");
  assert.equal(parsed.port, 8080);
  assert.equal(parsed.ipVersion, 6);
  assert.equal(parsed.cleanedInput, "[::1]:8080");
  assert.deepEqual(parsed.credentials, { username: "john", password: "doe_pass" });
  assert.equal(isScannable(parsed), true);
});

