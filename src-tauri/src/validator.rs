//! IP validation — IPv4 / IPv6 parsing, private / bogon detection, proxy input splitting.
//!
//! Phase 0: minimal but real implementation. Nothing here touches the network.
//! Spec refs: §3.4 (private/loopback must short-circuit), §1.2 (input forms), §8.4.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::models::{CheckMode, ProxyCredentials, ProxyProtocol};

/// Fully parsed user input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInput {
    /// Bare IP (no port).
    pub ip: IpAddr,
    /// Detected mode: `IpOnly` when no port was given, `Proxy` otherwise.
    pub mode: CheckMode,
    /// Proxy port when present.
    pub port: Option<u16>,
    /// Protocol hint supplied by the caller; the UI passes it explicitly.
    pub protocol: Option<ProxyProtocol>,
    /// True for loopback / private / link-local / reserved ranges (§3.4).
    pub is_private: bool,
    /// 4 or 6.
    pub ip_version: u8,
    /// Why the input was rejected as unusable, if it was.
    pub problem: Option<String>,
    /// Transient proxy credentials extracted from input if present (§8.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<ProxyCredentials>,
}

/// Strip scheme if present (`http://`, `https://`, `socks5://`, `socks4://`)
/// and return the remaining string along with the detected protocol.
fn extract_scheme(input: &str) -> (&str, Option<ProxyProtocol>) {
    let lower = input.to_ascii_lowercase();
    if lower.starts_with("socks5h://") {
        (&input[10..], Some(ProxyProtocol::Socks5))
    } else if lower.starts_with("socks5://") {
        (&input[9..], Some(ProxyProtocol::Socks5))
    } else if lower.starts_with("socks4a://") {
        (&input[10..], Some(ProxyProtocol::Socks4))
    } else if lower.starts_with("socks4://") {
        (&input[9..], Some(ProxyProtocol::Socks4))
    } else if lower.starts_with("https://") {
        (&input[8..], Some(ProxyProtocol::Https))
    } else if lower.starts_with("http://") {
        (&input[7..], Some(ProxyProtocol::Http))
    } else {
        (input, None)
    }
}

/// Parse a credential substring `"user:pass"` or `"user"` into [`ProxyCredentials`].
fn parse_credentials(s: &str) -> Option<ProxyCredentials> {
    if s.is_empty() {
        return None;
    }
    let (user, pass) = match s.split_once(':') {
        Some((u, p)) => (u, p),
        None => (s, ""),
    };
    if user.is_empty() && pass.is_empty() {
        None
    } else {
        Some(ProxyCredentials {
            username: user.to_string(),
            password: pass.to_string(),
        })
    }
}

/// Intermediate container for parsed components.
struct ParsedComponents {
    ip: Option<IpAddr>,
    port: Option<u16>,
    credentials: Option<ProxyCredentials>,
    problem: Option<String>,
}

/// Parse input that has had scheme stripped, checking for `@` or `host:port:user:pass`.
fn parse_host_port_creds(raw: &str) -> ParsedComponents {
    let raw = raw.trim().trim_end_matches('/');

    // 1. user:pass@host:port or user@host:port
    if let Some((cred_part, host_port_part)) = raw.rsplit_once('@') {
        let creds = parse_credentials(cred_part);
        let inner = parse_host_and_port(host_port_part);
        return ParsedComponents {
            ip: inner.ip,
            port: inner.port,
            credentials: creds.or(inner.credentials),
            problem: inner.problem,
        };
    }

    // 2. host:port, host:port:user:pass, bare IP, bracketed IPv6
    parse_host_and_port(raw)
}

/// Parse host, optional port, and optional trailing credentials (`host:port:user:pass`).
fn parse_host_and_port(raw: &str) -> ParsedComponents {
    let raw = raw.trim().trim_end_matches('/');

    // Bare IP (IPv4 or IPv6)
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return ParsedComponents {
            ip: Some(ip),
            port: None,
            credentials: None,
            problem: None,
        };
    }

    // Bracketed IPv6: [2001:db8::1]:8080 or [2001:db8::1]:8080:user:pass or [2001:db8::1]
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((host_str, tail)) = rest.split_once(']') {
            let host_ip = host_str.parse::<IpAddr>().ok();
            if host_ip.is_none() {
                return ParsedComponents {
                    ip: None,
                    port: None,
                    credentials: None,
                    problem: Some(format!("Địa chỉ IPv6 không hợp lệ: {host_str}")),
                };
            }

            if tail.is_empty() {
                return ParsedComponents {
                    ip: host_ip,
                    port: None,
                    credentials: None,
                    problem: None,
                };
            }

            if let Some(tail_content) = tail.strip_prefix(':') {
                let mut parts = tail_content.splitn(3, ':');
                let port_raw = parts.next().unwrap_or("");
                let port = port_raw.parse::<u16>().ok();
                if port.is_none() {
                    return ParsedComponents {
                        ip: host_ip,
                        port: None,
                        credentials: None,
                        problem: Some("Thiếu hoặc sai cổng proxy".to_string()),
                    };
                }

                let creds = match parts.next() {
                    Some(user) => {
                        let pass = parts.next().unwrap_or("");
                        parse_credentials(&format!("{user}:{pass}"))
                    }
                    None => None,
                };

                return ParsedComponents {
                    ip: host_ip,
                    port,
                    credentials: creds,
                    problem: None,
                };
            }

            return ParsedComponents {
                ip: host_ip,
                port: None,
                credentials: None,
                problem: Some("Thiếu hoặc sai cổng proxy".to_string()),
            };
        }

        return ParsedComponents {
            ip: None,
            port: None,
            credentials: None,
            problem: Some("Thiếu dấu ']' trong địa chỉ IPv6".to_string()),
        };
    }

    // Colon-separated: host:port or host:port:user:pass
    if raw.contains(':') {
        let parts: Vec<&str> = raw.splitn(4, ':').collect();
        if parts.len() >= 2 {
            let host_raw = parts[0];
            let port_raw = parts[1];
            let host_ip = host_raw.parse::<IpAddr>().ok();
            let port = port_raw.parse::<u16>().ok();

            if let (Some(ip), Some(p)) = (host_ip, port) {
                let creds = if parts.len() >= 3 {
                    let user = parts[2];
                    let pass = if parts.len() == 4 { parts[3] } else { "" };
                    parse_credentials(&format!("{user}:{pass}"))
                } else {
                    None
                };

                return ParsedComponents {
                    ip: Some(ip),
                    port: Some(p),
                    credentials: creds,
                    problem: None,
                };
            }

            if host_ip.is_none() {
                if parts.len() == 2 || port.is_some() {
                    return ParsedComponents {
                        ip: None,
                        port: None,
                        credentials: None,
                        problem: Some(format!("Địa chỉ IP không hợp lệ: {host_raw}")),
                    };
                }
                return ParsedComponents {
                    ip: None,
                    port: None,
                    credentials: None,
                    problem: Some(format!("Địa chỉ IP không hợp lệ: {raw}")),
                };
            }

            return ParsedComponents {
                ip: None,
                port: None,
                credentials: None,
                problem: Some(format!("Cổng proxy không hợp lệ: {port_raw}")),
            };
        }
    }

    ParsedComponents {
        ip: None,
        port: None,
        credentials: None,
        problem: Some(format!("Địa chỉ IP không hợp lệ: {raw}")),
    }
}

/// Parse `"1.2.3.4"`, `"1.2.3.4:8080"`, `"[2001:db8::1]:8080"` or `"2001:db8::1"`.
/// Also supports scheme prefixes (`http://`, `https://`, `socks5://`, `socks4://`)
/// and credentials formats (`user:pass@host:port`, `host:port:user:pass`).
///
/// The function never fails: unusable input comes back with `problem` set and
/// `is_private = true` so the orchestrator can short-circuit without calling
/// any provider (§3.4 test case 2 and 3).
pub fn parse_input(input: &str, protocol: Option<ProxyProtocol>) -> ParsedInput {
    let raw = input.trim();
    let (without_scheme, detected_proto) = extract_scheme(raw);
    let protocol = protocol.or(detected_proto);

    let parsed = parse_host_port_creds(without_scheme);
    let ip = parsed.ip;
    let port = parsed.port;
    let credentials = parsed.credentials;
    let problem = parsed.problem;

    let is_private = ip.map(is_private_or_reserved).unwrap_or(true);
    let mode = if ip.is_none() {
        CheckMode::Unknown
    } else if port.is_some() {
        CheckMode::Proxy
    } else {
        CheckMode::IpOnly
    };

    ParsedInput {
        // A placeholder keeps the struct total; callers must check `problem`.
        ip: ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        mode,
        port,
        protocol,
        is_private,
        ip_version: match ip {
            Some(IpAddr::V4(_)) => 4,
            Some(IpAddr::V6(_)) => 6,
            None => 0,
        },
        problem,
        credentials,
    }
}

/// Loopback, private, link-local, CGNAT, multicast, documentation and
/// otherwise reserved space. Per §3.4 the UI must stop and explain, not call APIs.
pub fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
                // 192.0.0.0/24, 198.18.0.0/15 benchmark, 240.0.0.0/4 reserved
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19))
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // documentation 2001:db8::/32
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
                || is_v6_mapped_private(v6)
        }
    }
}

/// `::ffff:192.168.1.1` must inherit the IPv4 verdict.
fn is_v6_mapped_private(v6: Ipv6Addr) -> bool {
    match v6.to_ipv4_mapped() {
        Some(v4) => is_private_or_reserved(IpAddr::V4(v4)),
        None => false,
    }
}

/// §1.2 / §8.4 — can this address be *dialled* as a proxy?
///
/// This is a **different question** from [`is_private_or_reserved`]. That one
/// answers "is this a real Internet address worth looking up in reputation
/// databases", which is the right gate for IP-only mode. Here the address is
/// the **proxy to connect to**, and a loopback proxy is the single most common
/// setup there is: `ssh -D 1080`, Tor's SOCKS port, Burp, a local mitmproxy,
/// even this project's own test proxy.
///
/// Rejecting `127.0.0.1:1080` as "a private IP" silently downgraded the check
/// to IP-only, skipped every proxy module, and measured the user's own
/// connection while the UI claimed a proxy was in use — a privacy failure
/// dressed up as input validation.
///
/// Only addresses that cannot possibly carry a TCP connection are refused.
pub fn proxy_host_is_usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // 0.0.0.0 means "any interface" to a listener, never a destination.
            !v4.is_unspecified()
                // 224.0.0.0/4 — no TCP streams.
                && !v4.is_multicast()
                // 255.255.255.255
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_multicast()
                // `::ffff:0.0.0.0` is the v6 spelling of 0.0.0.0.
                && !matches!(v6.to_ipv4_mapped(), Some(v4) if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast())
        }
    }
}

/// §3.4 — should this input stop the check before any provider is called?
///
/// Loopback / private / reserved addresses are not checkable **in IP-only
/// mode**: there is no reputation data for `192.168.1.1` and asking would waste
/// every provider's quota. In proxy mode that same address is the proxy, so it
/// is not a reason to stop — see [`proxy_host_is_usable`].
pub fn should_short_circuit(parsed: &ParsedInput) -> bool {
    match parsed.mode {
        CheckMode::IpOnly => parsed.is_private || parsed.problem.is_some(),
        CheckMode::Proxy => parsed.problem.is_some() || !proxy_host_is_usable(parsed.ip),
        // Nothing parsed: the caller reports `problem` verbatim.
        CheckMode::Unknown => true,
    }
}

/// IPv4 → reversed label for DNSBL lookups (`1.2.3.4` → `4.3.2.1`). §5.3
pub fn reverse_ipv4(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

/// IPv6 nibble-reversed label for DNSBL lookups (§5.3, RFC 5782 style).
pub fn reverse_ipv6(ip: Ipv6Addr) -> String {
    let mut nibbles: Vec<char> = Vec::with_capacity(32);
    for segment in ip.segments() {
        for shift in [12, 8, 4, 0] {
            let nibble = (segment >> shift) & 0xf;
            nibbles.push(std::char::from_digit(nibble as u32, 16).unwrap_or('0'));
        }
    }
    nibbles.reverse();
    nibbles.into_iter().map(|c| c.to_string()).collect::<Vec<_>>().join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_ipv4() {
        let p = parse_input("8.8.8.8", None);
        assert!(p.problem.is_none());
        assert_eq!(p.mode, CheckMode::IpOnly);
        assert!(!p.is_private);
        assert_eq!(p.ip_version, 4);
    }

    #[test]
    fn parses_proxy_form() {
        let p = parse_input("1.2.3.4:8080", Some(ProxyProtocol::Socks5));
        assert!(p.problem.is_none());
        assert_eq!(p.mode, CheckMode::Proxy);
        assert_eq!(p.port, Some(8080));
    }

    #[test]
    fn rejects_private_and_garbage() {
        assert!(parse_input("192.168.1.1", None).is_private);
        assert!(parse_input("999.999.999.999", None).problem.is_some());
        assert!(parse_input("abc", None).problem.is_some());
    }

    #[test]
    fn reverses_for_dnsbl() {
        assert_eq!(reverse_ipv4("1.2.3.4".parse().unwrap()), "4.3.2.1");
    }

    // ------------------------------------------------------------------
    // §8.4 — a loopback proxy is legitimate, not an uncheckable IP
    // ------------------------------------------------------------------

    #[test]
    fn local_proxy_is_accepted_in_proxy_mode() {
        // Regression: `127.0.0.1:1080` used to be classified as a "private IP",
        // which short-circuited the whole scan, skipped every proxy module and
        // left the UI measuring the user's own connection.
        let p = parse_input("127.0.0.1:1080", Some(ProxyProtocol::Socks5));
        assert_eq!(p.mode, CheckMode::Proxy);
        assert!(
            p.is_private,
            "127.0.0.1 vẫn là địa chỉ private — đó là điều bình thường với proxy"
        );
        assert!(
            proxy_host_is_usable(p.ip),
            "proxy loopback PHẢI dùng được: ssh -D, Tor, Burp đều ở đây"
        );
        assert!(
            !should_short_circuit(&p),
            "không được dừng sớm: đây là proxy, không phải IP cần tra"
        );
    }

    #[test]
    fn private_ip_still_short_circuits_in_ip_only_mode() {
        // The original §3.4 rule must survive for the case it was written for.
        let p = parse_input("192.168.1.1", None);
        assert_eq!(p.mode, CheckMode::IpOnly);
        assert!(p.is_private);
        assert!(
            should_short_circuit(&p),
            "IP-only mode: IP private thì dừng, không gọi API nào"
        );
    }

    #[test]
    fn common_local_proxies_are_all_usable() {
        // Every address a user realistically types as a proxy.
        for (raw, protocol) in [
            ("127.0.0.1:1080", ProxyProtocol::Socks5),
            ("127.0.0.1:9050", ProxyProtocol::Socks5),   // Tor
            ("127.0.0.1:8080", ProxyProtocol::Http),     // Burp / mitmproxy
            ("127.0.0.1:7890", ProxyProtocol::Http),     // Clash
            ("192.168.1.10:1080", ProxyProtocol::Socks5), // LAN proxy
            ("10.0.0.5:3128", ProxyProtocol::Http),      // Squid on LAN
            ("[::1]:1080", ProxyProtocol::Socks5),       // loopback v6
        ] {
            let p = parse_input(raw, Some(protocol));
            assert!(p.problem.is_none(), "{raw} phải parse được");
            assert_eq!(p.mode, CheckMode::Proxy, "{raw} phải là proxy mode");
            assert!(
                proxy_host_is_usable(p.ip),
                "{raw} phải dùng được làm proxy"
            );
            assert!(!should_short_circuit(&p), "{raw} không được dừng sớm");
        }
    }

    #[test]
    fn unusable_proxy_addresses_are_rejected() {
        // 0.0.0.0 is a listen-all wildcard, multicast has no TCP, broadcast is
        // not a host. Dialling any of those cannot work.
        for raw in ["0.0.0.0:1080", "224.0.0.1:1080", "255.255.255.255:1080"] {
            let p = parse_input(raw, Some(ProxyProtocol::Socks5));
            assert!(
                !proxy_host_is_usable(p.ip),
                "{raw} không thể là đích kết nối — phải bị từ chối"
            );
            assert!(should_short_circuit(&p), "{raw} phải dừng với lỗi rõ ràng");
        }
    }

    #[test]
    fn garbage_proxy_input_still_reports_a_problem() {
        let p = parse_input("127.0.0.1:99999", Some(ProxyProtocol::Socks5));
        assert!(p.problem.is_some(), "cổng ngoài 0–65535 phải bị bắt");
        assert!(should_short_circuit(&p));
    }

    #[test]
    fn parses_scheme_prefixes_and_sets_protocol() {
        let cases = [
            ("http://1.2.3.4:8080", ProxyProtocol::Http, "1.2.3.4", 8080),
            ("https://1.2.3.4:8443", ProxyProtocol::Https, "1.2.3.4", 8443),
            ("socks5://1.2.3.4:1080", ProxyProtocol::Socks5, "1.2.3.4", 1080),
            ("socks4://1.2.3.4:1080", ProxyProtocol::Socks4, "1.2.3.4", 1080),
            ("HTTP://1.2.3.4:8080", ProxyProtocol::Http, "1.2.3.4", 8080),
            ("SOCKS5://1.2.3.4:1080", ProxyProtocol::Socks5, "1.2.3.4", 1080),
            ("http://[2001:db8::1]:8080", ProxyProtocol::Http, "2001:db8::1", 8080),
        ];

        for (raw, expected_proto, expected_ip, expected_port) in cases {
            let p = parse_input(raw, None);
            assert!(p.problem.is_none(), "failed to parse {raw}: {:?}", p.problem);
            assert_eq!(p.mode, CheckMode::Proxy);
            assert_eq!(p.protocol, Some(expected_proto));
            assert_eq!(p.ip.to_string(), expected_ip);
            assert_eq!(p.port, Some(expected_port));
        }
    }

    #[test]
    fn caller_protocol_overrides_detected_scheme() {
        // If protocol was already set by caller, it is preserved
        let p = parse_input("http://1.2.3.4:8080", Some(ProxyProtocol::Socks5));
        assert!(p.problem.is_none());
        assert_eq!(p.protocol, Some(ProxyProtocol::Socks5));
        assert_eq!(p.port, Some(8080));
    }

    #[test]
    fn parses_user_pass_at_host_port() {
        let p = parse_input("admin:secret123@1.2.3.4:8080", None);
        assert!(p.problem.is_none(), "error: {:?}", p.problem);
        assert_eq!(p.mode, CheckMode::Proxy);
        assert_eq!(p.ip.to_string(), "1.2.3.4");
        assert_eq!(p.port, Some(8080));
        assert_eq!(
            p.credentials,
            Some(ProxyCredentials {
                username: "admin".to_string(),
                password: "secret123".to_string(),
            })
        );

        // With scheme
        let p2 = parse_input("socks5://alice:p@ss:w0rd@127.0.0.1:1080", None);
        assert!(p2.problem.is_none(), "error: {:?}", p2.problem);
        assert_eq!(p2.mode, CheckMode::Proxy);
        assert_eq!(p2.protocol, Some(ProxyProtocol::Socks5));
        assert_eq!(p2.ip.to_string(), "127.0.0.1");
        assert_eq!(p2.port, Some(1080));
        assert_eq!(
            p2.credentials,
            Some(ProxyCredentials {
                username: "alice".to_string(),
                password: "p@ss:w0rd".to_string(),
            })
        );

        // Bracketed IPv6
        let p3 = parse_input("user:pass@[2001:db8::1]:9050", Some(ProxyProtocol::Socks5));
        assert!(p3.problem.is_none(), "error: {:?}", p3.problem);
        assert_eq!(p3.mode, CheckMode::Proxy);
        assert_eq!(p3.ip.to_string(), "2001:db8::1");
        assert_eq!(p3.port, Some(9050));
        assert_eq!(
            p3.credentials,
            Some(ProxyCredentials {
                username: "user".to_string(),
                password: "pass".to_string(),
            })
        );
    }

    #[test]
    fn parses_host_port_user_pass() {
        let p = parse_input("1.2.3.4:8080:user:pass", None);
        assert!(p.problem.is_none(), "error: {:?}", p.problem);
        assert_eq!(p.mode, CheckMode::Proxy);
        assert_eq!(p.ip.to_string(), "1.2.3.4");
        assert_eq!(p.port, Some(8080));
        assert_eq!(
            p.credentials,
            Some(ProxyCredentials {
                username: "user".to_string(),
                password: "pass".to_string(),
            })
        );

        // With scheme
        let p2 = parse_input("http://45.67.89.10:3128:proxyuser:complex:pass:word", None);
        assert!(p2.problem.is_none(), "error: {:?}", p2.problem);
        assert_eq!(p2.mode, CheckMode::Proxy);
        assert_eq!(p2.protocol, Some(ProxyProtocol::Http));
        assert_eq!(p2.ip.to_string(), "45.67.89.10");
        assert_eq!(p2.port, Some(3128));
        assert_eq!(
            p2.credentials,
            Some(ProxyCredentials {
                username: "proxyuser".to_string(),
                password: "complex:pass:word".to_string(),
            })
        );

        // Bracketed IPv6 host:port:user:pass
        let p3 = parse_input("[2001:db8::1]:8080:alice:secret", None);
        assert!(p3.problem.is_none(), "error: {:?}", p3.problem);
        assert_eq!(p3.mode, CheckMode::Proxy);
        assert_eq!(p3.ip.to_string(), "2001:db8::1");
        assert_eq!(p3.port, Some(8080));
        assert_eq!(
            p3.credentials,
            Some(ProxyCredentials {
                username: "alice".to_string(),
                password: "secret".to_string(),
            })
        );
    }

    #[test]
    fn handles_trailing_slash_and_whitespace() {
        let p = parse_input("  http://127.0.0.1:8080/  ", None);
        assert!(p.problem.is_none());
        assert_eq!(p.mode, CheckMode::Proxy);
        assert_eq!(p.ip.to_string(), "127.0.0.1");
        assert_eq!(p.port, Some(8080));
        assert_eq!(p.protocol, Some(ProxyProtocol::Http));
    }
}
