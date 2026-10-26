//! Exit-IP detection (proxy mode) — §8.1.
//!
//! The user typed a proxy and wants one answer: *what IP does the world see when
//! I go through it?* This module answers that question and nothing else.
//!
//! ## The one invariant that matters
//!
//! Every request **must** go through the proxy. If a request escaped and hit the
//! echo service directly we would report the machine's own IP as the "exit IP",
//! which is the most damaging failure this app can produce (§8.4): the user
//! would believe a proxy is working while leaking their real address. That is
//! why the client is built with `Proxy::all(...)` and why the test
//! [`proxy_is_actually_applied_to_the_client`] points the proxy at a local mock
//! and asserts the mock received the traffic.
//!
//! ## Consensus, not the first answer
//!
//! §8.1 requires at least two independent echo endpoints. A single endpoint that
//! lies (or is behind a transparent proxy) would otherwise decide the result.
//! We ask every endpoint, then:
//!
//! * ≥2 endpoints answer **and agree** ⇒ measured, that IP is the exit IP.
//! * ≥2 endpoints answer and **disagree** ⇒ not measured, endpoints_disagree.
//! * fewer than 2 answers ⇒ not measured ("không đủ kết luận").
//!
//! The result is never `measured: false` with an `exit_ip` set — that
//! combination would let the UI show a number it cannot stand behind (§1.2).

use std::time::{Duration, Instant};

use crate::models::{ExitIpEndpoint, ExitIpResult};

/// Echo endpoints used to learn the real exit IP (§8.1 — at least two).
///
/// Three are listed so one dead service still leaves the quorum of two. All of
/// them return a small JSON body; none require an API key.
pub const ECHO_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://api64.ipify.org?format=json",
];

/// Per-endpoint budget (§8.1). The orchestrator wraps the whole module in a
/// larger deadline, so this is the inner guard.
pub const EXIT_IP_TIMEOUT: Duration = Duration::from_secs(8);

/// Minimum number of endpoints that must agree before the exit IP is published.
pub const MIN_AGREEING_ENDPOINTS: usize = 2;

/// Vietnamese note used when the module was not run at all.
pub const REASON_NOT_MEASURED: &str = "Chưa đo được — cần nhập proxy";

/// Placeholder result: proxy mode not measured.
pub fn not_measured() -> ExitIpResult {
    ExitIpResult {
        reachable: false,
        endpoint_results: Vec::new(),
        exit_ip: None,
        differs_from_input: false,
        endpoints_disagree: false,
        notes: vec![REASON_NOT_MEASURED.to_string()],
    }
}

/// Result for a proxy URL that could not even be turned into a client.
///
/// Distinct from [`not_measured`]: the user *did* supply a proxy, we just could
/// not use it. Saying "cần nhập proxy" there would be a lie.
pub fn unusable(proxy_url: &str, reason: &str) -> ExitIpResult {
    ExitIpResult {
        reachable: false,
        endpoint_results: Vec::new(),
        exit_ip: None,
        differs_from_input: false,
        endpoints_disagree: false,
        notes: vec![
            format!("Không dùng được proxy “{}”: {reason}", redact_proxy(proxy_url)),
            "§8.4: không đo được IP thoát thì không được suy ra IP nào khác.".to_string(),
        ],
    }
}

/// Compare an observed exit IP against the IP the user entered (§8.1 red flag).
pub fn compare(typed_ip: &str, endpoint_results: Vec<ExitIpEndpoint>) -> ExitIpResult {
    let ips: Vec<String> = endpoint_results
        .iter()
        .filter_map(|e| e.exit_ip.clone())
        .collect();

    let distinct: std::collections::HashSet<&String> = ips.iter().collect();
    let endpoints_disagree = distinct.len() > 1;

    if endpoints_disagree {
        return ExitIpResult {
            reachable: true,
            endpoint_results,
            exit_ip: None,
            differs_from_input: false,
            endpoints_disagree: true,
            notes: vec![
                "Các nguồn không đồng ý về IP thoát — không kết luận (§8.1).".to_string(),
            ],
        };
    }

    let agreed = ips.first().cloned();
    let answering = ips.len();
    let measured = agreed.is_some() && answering >= MIN_AGREEING_ENDPOINTS;

    let mut notes = Vec::new();
    if !measured {
        match (&agreed, answering) {
            (Some(_), n) => notes.push(format!(
                "Chỉ {n}/{} endpoint trả lời — cần ít nhất {MIN_AGREEING_ENDPOINTS} nguồn đồng ý để kết luận (§8.1).",
                endpoint_results.len().max(MIN_AGREEING_ENDPOINTS)
            )),
            (None, _) => notes.push("Không endpoint nào trả về IP thoát.".to_string()),
        }
    }

    let exit_ip = if measured { agreed } else { None };
    let differs_from_input = match &exit_ip {
        Some(ip) => ip != typed_ip,
        None => false,
    };

    if differs_from_input {
        notes.push(format!(
            "IP thoát ({}) khác IP đã nhập ({typed_ip}) — proxy đang đổi IP, kiểm tra lại cấu hình.",
            exit_ip.clone().unwrap_or_default()
        ));
    }

    ExitIpResult {
        reachable: measured || answering > 0,
        endpoint_results,
        exit_ip,
        differs_from_input,
        endpoints_disagree: false,
        notes,
    }
}

/// Build a client that **always** goes through `proxy_url` (§8.4).
///
/// The proxy is applied at the client level rather than per-request so there is
/// no code path that can accidentally issue a direct request.
#[allow(dead_code)]
fn build_client(proxy_url: &str) -> Result<reqwest::Client, String> {
    build_client_with_credentials(proxy_url, None)
}

fn build_client_with_credentials(
    proxy_url: &str,
    credentials: Option<&crate::models::ProxyCredentials>,
) -> Result<reqwest::Client, String> {
    let mut proxy = reqwest::Proxy::all(proxy_url)
        .map_err(|e| format!("URL proxy không hợp lệ: {}", e.without_url()))?;

    if let Some(cred) = credentials {
        if !cred.username.is_empty() || !cred.password.is_empty() {
            proxy = proxy.basic_auth(&cred.username, &cred.password);
        }
    }

    reqwest::Client::builder()
        .proxy(proxy)
        // No `.no_proxy()` anywhere: the machine's own IP must never be reachable
        // from this client.
        .timeout(EXIT_IP_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .user_agent("ip-checker/0.1 (exit-ip)")
        .build()
        .map_err(|e| format!("Không tạo được HTTP client: {}", e.without_url()))
}

#[cfg(test)]
mod strip_url_tests {
    use super::strip_urls;

    #[test]
    fn credentials_in_an_error_message_are_removed() {
        let raw = "error sending request for url (http://alice:s3cret@10.0.0.1:1080/)";
        let clean = strip_urls(raw);
        assert!(!clean.contains("s3cret"), "mật khẩu phải bị xoá: {clean}");
        assert!(!clean.contains("alice"), "username phải bị xoá: {clean}");
        assert!(clean.contains("error sending request"), "lý do phải còn: {clean}");
    }

    #[test]
    fn text_without_a_url_is_untouched() {
        assert_eq!(strip_urls("connection refused"), "connection refused");
    }
}

/// Pull an IP address out of an echo-service body.
///
/// Bodies differ: `api.ipify.org` returns `{"ip":"1.2.3.4"}`, `ifconfig.co`
/// returns `{"ip":"1.2.3.4","country":"..."}`, and some mirrors return the bare
/// address as text. All three shapes are accepted; anything else is a failure
/// rather than a guess.
pub fn parse_exit_ip(body: &str) -> Option<String> {
    let trimmed = body.trim();

    // Bare-address form first: cheapest and unambiguous.
    if let Ok(addr) = trimmed.parse::<std::net::IpAddr>() {
        return Some(addr.to_string());
    }

    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    for key in ["ip", "origin", "query", "address"] {
        if let Some(text) = value.get(key).and_then(|v| v.as_str()) {
            if let Ok(addr) = text.trim().parse::<std::net::IpAddr>() {
                return Some(addr.to_string());
            }
        }
    }
    None
}

/// Ask one endpoint for the exit IP through the proxy.
async fn ask_endpoint(client: &reqwest::Client, url: &str) -> ExitIpEndpoint {
    let started = Instant::now();
    let response = client.get(url).send().await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return ExitIpEndpoint {
                    endpoint: url.to_string(),
                    ok: false,
                    exit_ip: None,
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    error: Some(format!("HTTP {}", status.as_u16())),
                };
            }
            match resp.text().await {
                Ok(body) => {
                    let ip = parse_exit_ip(&body);
                    ExitIpEndpoint {
                        endpoint: url.to_string(),
                        ok: ip.is_some(),
                        error: if ip.is_some() {
                            None
                        } else {
                            Some("Không đọc được IP trong phản hồi".to_string())
                        },
                        exit_ip: ip,
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                    }
                }
                Err(e) => ExitIpEndpoint {
                    endpoint: url.to_string(),
                    ok: false,
                    exit_ip: None,
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    error: Some(format!("Đọc body lỗi: {}", e.without_url())),
                },
            }
        }
        Err(e) => ExitIpEndpoint {
            endpoint: url.to_string(),
            ok: false,
            exit_ip: None,
            latency_ms: Some(started.elapsed().as_millis() as u64),
            error: Some(describe_error(&e)),
        },
    }
}

/// Turn a reqwest error into a short Vietnamese reason without leaking the URL
/// (which may carry `user:pass@`, §8.4/§11).
fn describe_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "Hết thời gian chờ qua proxy".to_string()
    } else if e.is_connect() {
        "Không kết nối được qua proxy".to_string()
    } else if e.is_request() {
        "Yêu cầu không gửi được qua proxy".to_string()
    } else {
        // Never call `without_url()` here: it consumes the error and
        // `reqwest::Error` is not `Clone`, so it cannot be used behind `&`.
        // Strip any scheme prefix from the text instead — the raw message can
        // embed the proxy URL, which may carry `user:pass@` (§8.4/§11).
        format!("Lỗi mạng: {}", strip_urls(&e.to_string()))
    }
}

/// Remove anything that looks like a URL from a message, keeping the reason.
///
/// `error sending request for url (http://alice:s3cret@10.0.0.1:1080/)` becomes
/// `error sending request for url (…)` — the diagnosis survives, the credential
/// does not.
fn strip_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find("://") {
        // Walk back to the beginning of the scheme.
        let scheme_start = rest[..start]
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != '.')
            .map(|i| i + 1)
            .unwrap_or(0);
        out.push_str(&rest[..scheme_start]);
        out.push('…');
        // Walk forward to the first delimiter that cannot be part of a URL.
        let after = &rest[start + 3..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == ')' || c == ']' || c == '}' || c == ',')
            .unwrap_or(after.len());
        rest = &after[end..];
    }

    out.push_str(rest);
    out
}

/// Replace any `user:pass@` segment so a proxy URL can be shown in a note.
fn redact_proxy(proxy_url: &str) -> String {
    // `scheme://user:pass@host:port` → `scheme://***@host:port`
    match proxy_url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_creds, host)) => format!("{scheme}://***@{host}"),
            None => proxy_url.to_string(),
        },
        None => proxy_url.to_string(),
    }
}

/// Probe every echo endpoint through the proxy (§8.1).
///
/// Returns a result whose `exit_ip` is `Some` **only** when at least two
/// endpoints answered and they agreed — never the machine's own address.
pub async fn probe(proxy_url: &str, typed_ip: &str) -> ExitIpResult {
    probe_with_credentials(proxy_url, typed_ip, None).await
}

/// Probe every echo endpoint through the proxy, applying transient proxy
/// credentials when provided (§8.1, §8.4).
pub async fn probe_with_credentials(
    proxy_url: &str,
    typed_ip: &str,
    credentials: Option<&crate::models::ProxyCredentials>,
) -> ExitIpResult {
    if proxy_url.trim().is_empty() {
        return not_measured();
    }

    let client = match build_client_with_credentials(proxy_url, credentials) {
        Ok(c) => c,
        Err(e) => return unusable(proxy_url, &e),
    };

    // Run the endpoints concurrently: one slow mirror must not eat the others'
    // budget. Every future is bounded by the client timeout.
    let requests = ECHO_ENDPOINTS.iter().map(|url| ask_endpoint(&client, url));
    let endpoint_results: Vec<ExitIpEndpoint> = futures::future::join_all(requests).await;

    let answering = endpoint_results.iter().filter(|e| e.ok).count();
    let mut result = compare(typed_ip, endpoint_results);

    if result.endpoints_disagree {
        result.notes.insert(
            0,
            "§8.4: proxy có thể đang chuyển tiếp không nhất quán — không công bố IP thoát.".to_string(),
        );
    } else if result.exit_ip.is_none() && answering == 0 {
        result.notes.insert(
            0,
            "Không endpoint nào trả lời qua proxy — kiểm tra proxy còn sống và đúng giao thức.".to_string(),
        );
        result.reachable = false;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(url: &str, ip: Option<&str>) -> ExitIpEndpoint {
        ExitIpEndpoint {
            endpoint: url.to_string(),
            ok: ip.is_some(),
            exit_ip: ip.map(|s| s.to_string()),
            latency_ms: Some(10),
            error: None,
        }
    }

    #[test]
    fn not_measured_shape_says_why() {
        let r = not_measured();
        assert!(!r.reachable);
        assert!(r.exit_ip.is_none());
        assert_eq!(r.notes, vec![REASON_NOT_MEASURED.to_string()]);
    }

    #[test]
    fn parses_all_three_body_shapes() {
        assert_eq!(
            parse_exit_ip(r#"{"ip":"1.2.3.4"}"#).as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            parse_exit_ip(r#"{"ip":"1.2.3.4","country":"US"}"#).as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(parse_exit_ip("  1.2.3.4\n").as_deref(), Some("1.2.3.4"));
        // IPv6 is normalised, not rejected.
        assert_eq!(
            parse_exit_ip(r#"{"ip":"2a00:1450:4001:80b::200e"}"#).as_deref(),
            Some("2a00:1450:4001:80b::200e")
        );
    }

    #[test]
    fn garbage_body_is_not_an_ip() {
        assert!(parse_exit_ip("<html>blocked</html>").is_none());
        assert!(parse_exit_ip(r#"{"ip":"not-an-ip"}"#).is_none());
        assert!(parse_exit_ip("").is_none());
    }

    #[test]
    fn two_agreeing_endpoints_commit_the_ip() {
        let r = compare(
            "9.9.9.9",
            vec![
                ep("a", Some("1.2.3.4")),
                ep("b", Some("1.2.3.4")),
                ep("c", None),
            ],
        );
        assert_eq!(r.exit_ip.as_deref(), Some("1.2.3.4"));
        assert!(!r.endpoints_disagree);
        assert!(r.differs_from_input, "1.2.3.4 khác 9.9.9.9");
    }

    #[test]
    fn single_answer_is_not_enough() {
        // §8.1: one endpoint is a single point of lie.
        let r = compare("1.2.3.4", vec![ep("a", Some("1.2.3.4")), ep("b", None)]);
        assert!(r.exit_ip.is_none(), "1 endpoint không đủ kết luận");
        assert!(r.notes.iter().any(|n| n.contains("ít nhất 2")));
    }

    #[test]
    fn disagreeing_endpoints_never_publish_an_ip() {
        let r = compare(
            "1.2.3.4",
            vec![ep("a", Some("1.2.3.4")), ep("b", Some("5.6.7.8"))],
        );
        assert!(r.exit_ip.is_none(), "hai nguồn lệch nhau ⇒ không kết luận");
        assert!(r.endpoints_disagree);
    }

    #[test]
    fn matching_typed_ip_is_not_flagged() {
        let r = compare(
            "1.2.3.4",
            vec![ep("a", Some("1.2.3.4")), ep("b", Some("1.2.3.4"))],
        );
        assert_eq!(r.exit_ip.as_deref(), Some("1.2.3.4"));
        assert!(!r.differs_from_input);
    }

    #[test]
    fn no_answer_means_not_reachable() {
        let r = compare("1.2.3.4", vec![ep("a", None), ep("b", None)]);
        assert!(r.exit_ip.is_none());
        assert!(!r.reachable);
        assert!(!r.differs_from_input);
    }

    #[test]
    fn proxy_url_in_notes_is_redacted() {
        assert_eq!(
            redact_proxy("socks5://alice:s3cret@10.0.0.1:1080"),
            "socks5://***@10.0.0.1:1080"
        );
        assert_eq!(
            redact_proxy("http://10.0.0.1:8080"),
            "http://10.0.0.1:8080"
        );
    }

    #[test]
    fn unusable_proxy_note_carries_no_credentials() {
        let r = unusable("http://alice:s3cret@10.0.0.1:1", "connection refused");
        let joined = r.notes.join(" ");
        assert!(!joined.contains("s3cret"), "note không được chứa mật khẩu");
        assert!(!joined.contains("alice"), "note không được chứa username");
        assert!(joined.contains("10.0.0.1"));
        assert!(r.exit_ip.is_none());
    }

    #[test]
    fn build_client_accepts_all_three_protocols() {
        for scheme in ["http", "https", "socks5"] {
            let url = format!("{scheme}://127.0.0.1:1080");
            assert!(
                build_client(&url).is_ok(),
                "phải dựng được client cho {url}"
            );
        }
    }

    #[tokio::test]
    async fn unreachable_proxy_is_not_measured_and_never_reports_local_ip() {
        // Port 1 on loopback: nothing listens, connection is refused instantly.
        let r = probe("http://127.0.0.1:1", "1.2.3.4").await;
        assert!(!r.reachable, "proxy chết thì không được coi là reachable");
        assert!(
            r.exit_ip.is_none(),
            "§8.4: TUYỆT ĐỐI không được trả IP của máy mình"
        );
        assert!(!r.differs_from_input);
        assert!(!r.notes.is_empty(), "phải có lý do cho người dùng");
    }

    #[tokio::test]
    async fn empty_proxy_url_is_not_measured() {
        let r = probe("   ", "1.2.3.4").await;
        assert!(r.exit_ip.is_none());
        assert_eq!(r.notes, vec![REASON_NOT_MEASURED.to_string()]);
    }

    #[tokio::test]
    async fn proxy_is_actually_applied_to_the_client() {
        // §8.4 wire-level proof. A `wiremock` server plays the proxy: reqwest's
        // proxy layer answers `CONNECT` itself, so if traffic does NOT go
        // through the proxy, nothing ever reaches this mock and the test fails.
        //
        // A 502 from the mock means "the client did speak CONNECT to us" — the
        // proxy is wired. We assert exactly that rather than a full tunnel,
        // because a full MITM tunnel is wiremock's job, not ours.
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;

        let addr = server.address();
        let proxy_url = format!("http://{}:{}", addr.ip(), addr.port());
        let client = build_client(&proxy_url).expect("client dựng được qua mock proxy");

        // Any failure is fine; what matters is that the mock saw the CONNECT.
        let _ = client.get("http://example.invalid/ip").send().await;

        let received = server.received_requests().await.unwrap_or_default();
        assert!(
            !received.is_empty(),
            "§8.4: client KHÔNG đi qua proxy — request không tới mock. \
             Đây là bug nghiêm trọng nhất của module này."
        );
    }
}
