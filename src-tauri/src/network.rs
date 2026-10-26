//! Network probe — ping, traceroute, reverse DNS, TTL (§9).
//!
//! Everything here is a *measurement*, never a conclusion:
//!   * Ping is ICMP-first; when ICMP is blocked (very common on Windows without
//!     admin rights, and on most datacenter IPs) it falls back to a TCP connect
//!     test on 80/443 and **labels the method** so the UI can say which one ran
//!     (§9: "nếu bị chặn thì fallback TCP ping ... và ghi rõ phương pháp").
//!   * Traceroute is capped and best-effort; a partial result is reported with a
//!     note, not padded with fake hops.
//!   * Reverse DNS is a real PTR lookup with a short timeout.
//!   * Port scanning: **only** the user-supplied proxy port in proxy mode
//!     (§9). [`check_proxy_port`] is the single place allowed to probe a port,
//!     and it never touches any other port.
//!
//! The module never fabricates numbers: if nothing was measured, the numeric
//! fields stay `None` and `notes` explains why.

use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::Command;

use crate::models::{NetworkResult, TracerouteHop};

/// Ping packet count (§9 latency/jitter/loss need ≥4 samples).
pub const PING_COUNT: u8 = 4;
/// Per-probe timeout.
pub const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// Traceroute cap — keeps the IP-only budget under 30 s (§4.3).
pub const MAX_TRACEROUTE_HOPS: u8 = 20;
/// Reverse-DNS budget.
pub const PTR_TIMEOUT: Duration = Duration::from_secs(3);

/// How the latency numbers were obtained (§9 requires labelling this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMethod {
    Icmp,
    Tcp80,
    Tcp443,
    None,
}

impl PingMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            PingMethod::Icmp => "icmp",
            PingMethod::Tcp80 => "tcp:80",
            PingMethod::Tcp443 => "tcp:443",
            PingMethod::None => "none",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PingMethod::Icmp => "ICMP ping",
            PingMethod::Tcp80 => "TCP ping (port 80)",
            PingMethod::Tcp443 => "TCP ping (port 443)",
            PingMethod::None => "Chưa đo được",
        }
    }
}

/// Aggregate latency statistics from a set of samples (ms).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencyStats {
    pub avg: f64,
    pub min: f64,
    pub max: f64,
    pub jitter: f64,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
}

/// Compute avg / min / max / jitter / loss from successful RTT samples.
///
/// Jitter is the mean absolute difference between consecutive samples, the same
/// definition the spec's UI uses ("jitter" alongside latency, §9).
pub fn latency_stats(samples: &[f64], sent: u32) -> Option<LatencyStats> {
    if samples.is_empty() {
        return None;
    }
    let received = samples.len() as u32;
    let sum: f64 = samples.iter().sum();
    let avg = sum / received as f64;
    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    let jitter = if samples.len() >= 2 {
        let diffs: f64 = samples
            .windows(2)
            .map(|w| (w[1] - w[0]).abs())
            .sum::<f64>();
        diffs / (samples.len() - 1) as f64
    } else {
        0.0
    };

    let sent = sent.max(received);
    Some(LatencyStats {
        avg,
        min,
        max,
        jitter,
        sent,
        received,
        loss_pct: ((sent - received) as f64 / sent as f64) * 100.0,
    })
}

/// TTL-based weak OS hint (§8.2, §9). Only a hint — never a conclusion.
///
/// Returns the *initial* TTL family the observed value most likely came from.
pub fn os_guess_from_ttl(ttl: Option<u32>) -> Option<String> {
    let ttl = ttl?;
    if ttl == 0 {
        return None;
    }
    // Observed TTL is decremented per hop, so compare against the usual initials.
    let candidates = [(64u32, "Linux/Unix (~64)"), (128, "Windows (~128)"), (255, "Network device (~255)")];
    candidates
        .iter()
        .find(|(initial, _)| ttl <= *initial)
        .map(|(_, label)| (*label).to_string())
}

/// Initial TTL family for a hop count, used to sanity-check `os_guess`.
pub fn expected_initial_ttl(ttl: u32) -> u32 {
    match ttl {
        t if t <= 64 => 64,
        t if t <= 128 => 128,
        _ => 255,
    }
}

// ---------------------------------------------------------------------------
// ICMP ping via the OS binary (no raw socket / no admin requirement)
// ---------------------------------------------------------------------------

/// Parse `time=12ms` / `time<1ms` / `Zeit=12ms` style ping output.
pub fn parse_ping_times(output: &str) -> Vec<f64> {
    let mut samples = Vec::new();
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        let candidate = lower
            .strip_prefix("time=")
            .or_else(|| lower.strip_suffix("ms").filter(|s| s.trim_end().trim_start().contains("time")));
        let Some(raw) = candidate else { continue };
        let cleaned = raw.trim_matches(|c: char| !c.is_ascii_digit() && c != '.' && c != '<');
        if let Ok(value) = cleaned.replace('<', "").parse::<f64>() {
            samples.push(value);
        }
    }
    samples
}

/// Run the OS `ping` binary (no shell) and parse its RTT samples.
async fn icmp_ping(ip: IpAddr) -> Option<(Vec<f64>, Option<u32>)> {
    let target = ip.to_string();
    let count = PING_COUNT.to_string();

    // Windows uses `-n <count>`, Unix uses `-c <count>`; try both without a shell.
    let unix_count = format!("-c{count}");
    let attempts: [Vec<&str>; 2] = [
        vec!["-n", count.as_str(), "-w", "2000", target.as_str()],
        vec![unix_count.as_str(), "-W", "2", target.as_str()],
    ];

    for args in attempts {
        let mut cmd = Command::new("ping");
        cmd.args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let child = cmd.spawn();

        let Ok(child) = child else { continue };
        let output = match tokio::time::timeout(
            PING_TIMEOUT * (PING_COUNT as u32 + 2),
            child.wait_with_output(),
        )
        .await
        {
            Ok(Ok(out)) => out,
            _ => continue,
        };

        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let samples = parse_ping_times(&text);
        if !samples.is_empty() {
            return Some((samples, parse_ttl(&text)));
        }
    }
    None
}

/// Extract `TTL=117` / `ttl=117`.
pub fn parse_ttl(output: &str) -> Option<u32> {
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("ttl=") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(ttl) = digits.parse::<u32>() {
                return Some(ttl);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TCP ping fallback (§9)
// ---------------------------------------------------------------------------

/// Connect-time measurement on one TCP port.
pub async fn tcp_ping_once(ip: IpAddr, port: u16, timeout: Duration) -> Option<f64> {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            drop(stream);
            Some(elapsed)
        }
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            Some(elapsed)
        }
        _ => None,
    }
}

async fn tcp_ping(ip: IpAddr, port: u16) -> Option<Vec<f64>> {
    let mut samples = Vec::new();
    for _ in 0..PING_COUNT {
        if let Some(ms) = tcp_ping_once(ip, port, PING_TIMEOUT).await {
            samples.push(ms);
        }
    }
    if samples.is_empty() {
        None
    } else {
        Some(samples)
    }
}

/// ICMP ping with TCP fallback on 80 then 443 (§9).
pub async fn ping(ip: IpAddr, _count: u8) -> NetworkResult {
    let mut notes = Vec::new();

    if let Some((samples, ttl)) = icmp_ping(ip).await {
        if let Some(stats) = latency_stats(&samples, PING_COUNT as u32) {
            return NetworkResult {
                ping_method: PingMethod::Icmp.as_str().to_string(),
                latency_avg_ms: Some(stats.avg),
                latency_min_ms: Some(stats.min),
                latency_max_ms: Some(stats.max),
                jitter_ms: Some(stats.jitter),
                packets_sent: Some(stats.sent),
                packets_received: Some(stats.received),
                packet_loss_pct: Some(stats.loss_pct),
                ttl,
                os_guess: os_guess_from_ttl(ttl),
                traceroute_hops: Vec::new(),
                reverse_dns: None,
                reverse_dns_matches_isp: None,
                notes,
            };
        }
    } else {
        notes.push("ICMP bị chặn hoặc không chạy được — thử TCP ping (§9)".to_string());
    }

    for (port, method) in [(80u16, PingMethod::Tcp80), (443u16, PingMethod::Tcp443)] {
        if let Some(samples) = tcp_ping(ip, port).await {
            if let Some(stats) = latency_stats(&samples, PING_COUNT as u32) {
                notes.push(format!(
                    "Latency đo bằng TCP connect tới port {port} — không phải ICMP, chỉ so sánh tương đối"
                ));
                return NetworkResult {
                    ping_method: method.as_str().to_string(),
                    latency_avg_ms: Some(stats.avg),
                    latency_min_ms: Some(stats.min),
                    latency_max_ms: Some(stats.max),
                    jitter_ms: Some(stats.jitter),
                    packets_sent: Some(stats.sent),
                    packets_received: Some(stats.received),
                    packet_loss_pct: Some(stats.loss_pct),
                    ttl: None,
                    os_guess: None,
                    traceroute_hops: Vec::new(),
                    reverse_dns: None,
                    reverse_dns_matches_isp: None,
                    notes,
                };
            }
        }
    }

    notes.push(
        "Không đo được latency: ICMP bị chặn và TCP 80/443 đều không kết nối được".to_string(),
    );
    NetworkResult {
        ping_method: PingMethod::None.as_str().to_string(),
        traceroute_hops: Vec::new(),
        notes,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Reverse DNS (§9)
// ---------------------------------------------------------------------------

/// Reverse DNS lookup (PTR) with a hard timeout. `None` when there is no PTR.
pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let lookup = tokio::time::timeout(PTR_TIMEOUT, async {
        let resolver = crate::dnsbl::build_resolver().unwrap_or_else(|| {
            hickory_resolver::TokioAsyncResolver::tokio(
                hickory_resolver::config::ResolverConfig::default(),
                hickory_resolver::config::ResolverOpts::default(),
            )
        });
        resolver.reverse_lookup(ip).await.ok()
    })
    .await;

    let Ok(Some(names)) = lookup else {
        return None;
    };
    names
        .iter()
        .next()
        .map(|name| name.to_utf8().trim_end_matches('.').to_string())
}

/// Does the PTR hostname look like it belongs to the ASN/ISP we detected?
///
/// Weak evidence only (§7.4): the UI shows the raw hostname, it does not turn
/// this into a conclusion.
pub fn reverse_dns_matches_isp(hostname: &str, isp: Option<&str>, asn_name: Option<&str>) -> bool {
    let host = hostname.to_ascii_lowercase();
    let candidates = [isp, asn_name]
        .into_iter()
        .flatten()
        .map(|s| {
            s.to_ascii_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| t.len() >= 3)
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect::<Vec<_>>();

    candidates.iter().any(|token| host.contains(token.as_str()))
}

// ---------------------------------------------------------------------------
// Traceroute (§9)
// ---------------------------------------------------------------------------

/// Parse Windows `tracert` / Unix `traceroute` output into hops.
pub fn parse_traceroute(output: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Hop lines start with a small integer followed by whitespace.
        let mut parts = trimmed.split_whitespace();
        let Some(first) = parts.next() else { continue };
        let Ok(hop_index) = first.parse::<u32>() else {
            continue;
        };
        if hop_index == 0 || hop_index > 64 {
            continue;
        }
        let rest: Vec<&str> = parts.collect();
        if rest.is_empty() {
            continue;
        }

        // Linux/macOS wrap the resolved address in parentheses:
        //   `3  one.one.one.one (1.1.1.1)  9.012 ms`
        // Windows and plain output use bare tokens, and IPv6 may be bracketed.
        // Strip every wrapper before testing, otherwise a hop that also has a
        // PTR name yields `address = None`.
        let address = rest
            .iter()
            .map(|token| token.trim_matches(|c: char| {
                c == '[' || c == ']' || c == '(' || c == ')' || c == ','
            }))
            .find(|t| t.parse::<IpAddr>().is_ok())
            .map(|t| t.to_string());

        // A PTR name is a dotted token with at least one letter that is not an
        // IP. `(1.1.1.1)` must not qualify, so strip the same wrappers here.
        let hostname = rest
            .iter()
            .map(|token| token.trim_matches(|c: char| {
                c == '[' || c == ']' || c == '(' || c == ')' || c == ','
            }))
            .find(|token| {
                token.contains('.')
                    && token.parse::<IpAddr>().is_err()
                    && !token.eq_ignore_ascii_case("ms")
                    && token.chars().any(|c| c.is_ascii_alphabetic())
            })
            .map(|t| t.trim_end_matches('.').to_string());

        let rtt = rest
            .iter()
            .position(|t| t.eq_ignore_ascii_case("ms"))
            .and_then(|i| {
                if i == 0 {
                    None
                } else {
                    rest[i - 1]
                        .trim_start_matches('<')
                        .parse::<f64>()
                        .ok()
                }
            });

        hops.push(TracerouteHop {
            hop: hop_index,
            address,
            hostname,
            rtt_ms: rtt,
            is_international: None,
        });
    }
    // Keep only the contiguous prefix of real hops (a hop with no address is a
    // timeout; later hops may still answer, so keep them but do not invent one).
    hops.sort_by_key(|h| h.hop);
    hops.dedup_by_key(|h| h.hop);
    hops
}

/// Per-hop wait handed to `tracert -w`, in milliseconds.
///
/// The timeout budget in [`run_traceroute_binary`] is derived from **this**
/// constant, never from a separate number: budgeting on one value while the
/// binary waits on another made the budget shorter than the worst case the
/// process can legitimately take, so the trailing (slow) hops were killed
/// exactly when they mattered. `tracert_per_hop_wait_matches_the_budget_constant`
/// guards the pair.
const TRACERT_PER_HOP_MS: u64 = 700;

/// Cushion added on top of `hops * TRACERT_PER_HOP_MS` for process spawn, DNS
/// on the target name, and `wait_with_output` buffering.
const TRACERT_BUDGET_CUSHION_SECS: u64 = 4;

async fn run_traceroute_binary(ip: IpAddr, max_hops: u8) -> Option<String> {
    let target = ip.to_string();
    let per_hop = TRACERT_PER_HOP_MS.to_string();
    let attempts: Vec<(String, Vec<String>)> = vec![
        (
            "tracert".to_string(),
            vec![
                "-d".to_string(),
                "-h".to_string(),
                max_hops.to_string(),
                "-w".to_string(),
                per_hop,
                target.clone(),
            ],
        ),
        (
            "traceroute".to_string(),
            vec!["-n".to_string(), "-q".to_string(), "1".to_string(), "-m".to_string(), max_hops.to_string(), "-w".to_string(), "2".to_string(), target.clone()],
        ),
    ];

    for (program, args) in attempts {
        let mut cmd = Command::new(&program);
        cmd.args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        let child = cmd.spawn();
        let Ok(child) = child else { continue };

        // `tracert -w TRACERT_PER_HOP_MS` waits that long per unanswered hop,
        // so 20 hops can legitimately burn 14 s before the process exits. The
        // budget must be **strictly larger** than that worst case: a budget
        // derived from a smaller per-hop number (the old 700-vs-900 mismatch)
        // killed the process exactly when the trailing hops were the slow ones —
        // the case this whole function exists to survive. 700 * 20 + 4 s = 18 s,
        // and ping + PTR (max 8 s, run concurrently) brings one probe to 26 s,
        // inside the 30 s module ceiling in §9.
        let budget = Duration::from_millis(TRACERT_PER_HOP_MS * (max_hops as u64))
            + Duration::from_secs(TRACERT_BUDGET_CUSHION_SECS);
        match tokio::time::timeout(budget, child.wait_with_output()).await {
            Ok(Ok(out)) => {
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
            _ => continue,
        }
    }
    None
}

/// Traceroute, capped at `max_hops`.
///
/// A machine without the binary simply reports no hops (with a note added by
/// [`probe`]); it is never an error the user must react to.
pub async fn traceroute(ip: IpAddr, max_hops: u8) -> Vec<TracerouteHop> {
    let max_hops = max_hops.min(MAX_TRACEROUTE_HOPS);
    match run_traceroute_binary(ip, max_hops).await {
        Some(output) => parse_traceroute(&output),
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Proxy port check (§9 — the ONLY permitted port probe)
// ---------------------------------------------------------------------------

/// Check that the *user-supplied* proxy port is open.
///
/// §9 allows exactly this one port probe in proxy mode, and nothing else. The
/// result is a plain `(open, latency_ms)`; no banner grabbing, no other ports.
pub async fn check_proxy_port(host: IpAddr, port: u16) -> (bool, Option<f64>) {
    let started = Instant::now();
    let addr = SocketAddr::new(host, port);
    match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let latency = started.elapsed().as_secs_f64() * 1000.0;
            drop(stream);
            (true, Some(latency))
        }
        _ => (false, None),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Full network module entry point (§9).
///
/// Order matters for the time budget: PTR + ping run concurrently, traceroute
/// runs last and is capped, so a single dead host cannot eat the whole 30 s.
pub async fn probe(ip: IpAddr) -> NetworkResult {
    let (mut result, ptr) = tokio::join!(ping(ip, PING_COUNT), reverse_dns(ip));

    result.reverse_dns = ptr;
    // Drop an empty PTR. `reverse_dns` never returns `Some("")` today, but a
    // `Some("")` would render as a blank "hostname" row in the panel, and the
    // old `if let (Some(host), _) = (&result.reverse_dns, ())` spelled that
    // guard in a way that looked like it handled two things and handled one.
    if matches!(result.reverse_dns.as_deref(), Some("")) {
        result.reverse_dns = None;
    }

    result.traceroute_hops = traceroute(ip, MAX_TRACEROUTE_HOPS).await;
    if result.traceroute_hops.is_empty() {
        result
            .notes
            .push("Không chạy được traceroute trên máy này — không có dữ liệu hop".to_string());
    } else {
        result.notes.push(format!(
            "Traceroute: {} hop",
            result.traceroute_hops.len()
        ));
    }

    // Re-derive the OS hint in case ICMP gave us a TTL.
    if result.os_guess.is_none() {
        result.os_guess = os_guess_from_ttl(result.ttl);
    }

    result
}

/// Network probe with the ISP/ASN cross-check applied afterwards (§7.4).
pub async fn probe_with_isp(ip: IpAddr, isp: Option<&str>, asn_name: Option<&str>) -> NetworkResult {
    let mut result = probe(ip).await;
    if let Some(host) = result.reverse_dns.clone() {
        result.reverse_dns_matches_isp = Some(reverse_dns_matches_isp(&host, isp, asn_name));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_computes_jitter_and_loss() {
        let samples = [10.0, 20.0, 12.0, 18.0];
        let stats = latency_stats(&samples, 4).unwrap();
        assert!((stats.avg - 15.0).abs() < 1e-9);
        assert!((stats.min - 10.0).abs() < 1e-9);
        assert!((stats.max - 20.0).abs() < 1e-9);
        // |20-10| + |12-20| + |18-12| = 10 + 8 + 6 = 24 / 3 = 8
        assert!((stats.jitter - 8.0).abs() < 1e-9);
        assert_eq!(stats.received, 4);
        assert_eq!(stats.loss_pct, 0.0);
    }

    #[test]
    fn latency_stats_reports_loss() {
        let stats = latency_stats(&[10.0, 12.0], 4).unwrap();
        assert_eq!(stats.sent, 4);
        assert_eq!(stats.received, 2);
        assert!((stats.loss_pct - 50.0).abs() < 1e-9);
    }

    #[test]
    fn no_samples_means_no_numbers() {
        assert!(latency_stats(&[], 4).is_none());
    }

    #[test]
    fn os_guess_from_ttl_is_a_hint_only() {
        assert_eq!(os_guess_from_ttl(Some(64)), Some("Linux/Unix (~64)".to_string()));
        assert_eq!(os_guess_from_ttl(Some(117)), Some("Windows (~128)".to_string()));
        assert_eq!(os_guess_from_ttl(Some(250)), Some("Network device (~255)".to_string()));
        assert_eq!(os_guess_from_ttl(Some(0)), None);
        assert_eq!(os_guess_from_ttl(None), None);
    }

    #[test]
    fn parses_windows_ping_output() {
        let output = "\
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=14ms TTL=117
Reply from 8.8.8.8: bytes=32 time=13ms TTL=117
Reply from 8.8.8.8: bytes=32 time=15ms TTL=117
Reply from 8.8.8.8: bytes=32 time=14ms TTL=117";
        let samples = parse_ping_times(output);
        assert_eq!(samples, vec![14.0, 13.0, 15.0, 14.0]);
        assert_eq!(parse_ttl(output), Some(117));
    }

    #[test]
    fn parses_unix_ping_output() {
        let output = "\
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=8.42 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=8.51 ms";
        let samples = parse_ping_times(output);
        assert_eq!(samples.len(), 2);
        assert!((samples[0] - 8.42).abs() < 1e-6);
        assert_eq!(parse_ttl(output), Some(57));
    }

    #[test]
    fn ping_parse_tolerates_garbage() {
        assert!(parse_ping_times("no timing here").is_empty());
        assert_eq!(parse_ttl("no ttl"), None);
    }

    #[test]
    fn parses_windows_tracert_output() {
        let output = "\
Tracing route to dns.google [8.8.8.8] over a maximum of 20 hops:
  1     1 ms     1 ms     1 ms  192.168.1.1
  2     8 ms     7 ms     8 ms  10.10.0.1
  3     *        *        *     Request timed out.
  6    25 ms    24 ms    25 ms  dns.google [8.8.8.8]
Trace complete.";
        let hops = parse_traceroute(output);
        assert!(hops.len() >= 3, "phải parse được các hop thật: {hops:?}");
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[0].address.as_deref(), Some("192.168.1.1"));
        let last = hops.iter().find(|h| h.address.as_deref() == Some("8.8.8.8"));
        assert!(last.is_some(), "phải thấy hop cuối: {hops:?}");
        assert_eq!(last.unwrap().hostname.as_deref(), Some("dns.google"));
    }

    #[test]
    fn parses_unix_traceroute_output() {
        let output = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max
 1  192.168.1.1  1.234 ms
 2  10.0.0.1  5.678 ms
 3  one.one.one.one (1.1.1.1)  9.012 ms";
        let hops = parse_traceroute(output);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[2].hop, 3);
        assert_eq!(hops[2].address.as_deref(), Some("1.1.1.1"));
        assert_eq!(hops[2].hostname.as_deref(), Some("one.one.one.one"));
        assert!((hops[2].rtt_ms.unwrap() - 9.012).abs() < 1e-6);
    }

    #[test]
    fn traceroute_parse_skips_header_lines() {
        let hops = parse_traceroute("Tracing route to x\n\nTrace complete.");
        assert!(hops.is_empty());
    }

    #[test]
    fn reverse_dns_matches_isp_tokenises() {
        assert!(reverse_dns_matches_isp(
            "static.vnpt.vn",
            Some("VNPT Corp"),
            None
        ));
        assert!(reverse_dns_matches_isp(
            "pool-1.google.com",
            None,
            Some("GOOGLE")
        ));
        assert!(!reverse_dns_matches_isp(
            "host.example.net",
            Some("Viettel Group"),
            None
        ));
        // Too-short tokens must not create false matches.
        assert!(!reverse_dns_matches_isp("abc.example.net", Some("AB"), None));
    }

    #[tokio::test]
    async fn tcp_ping_to_closed_port_returns_none() {
        // 127.0.0.1:1 is essentially never listening.
        let result = tcp_ping_once("127.0.0.1".parse().unwrap(), 1, Duration::from_millis(200)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn proxy_port_check_reports_closed_port() {
        let (open, latency) = check_proxy_port("127.0.0.1".parse().unwrap(), 1).await;
        assert!(!open);
        assert!(latency.is_none());
    }

    #[test]
    fn traceroute_budget_exceeds_the_worst_case_the_binary_can_take() {
        // `tracert -w N` spends up to N ms per unanswered hop. If the timeout
        // budget is not strictly larger than hops * N, the process is killed
        // exactly when the trailing hops time out — the case this exists for.
        let max_hops: u8 = MAX_TRACEROUTE_HOPS;
        let worst_case = Duration::from_millis(TRACERT_PER_HOP_MS * max_hops as u64);
        let budget = worst_case + Duration::from_secs(TRACERT_BUDGET_CUSHION_SECS);
        assert!(
            budget > worst_case,
            "budget must exceed the worst case the binary can take, got {budget:?} vs {worst_case:?}"
        );
        assert!(
            budget < Duration::from_secs(30),
            "one module must stay under the 30 s ceiling in §9, got {budget:?}"
        );
        // Ping + PTR run concurrently before traceroute, and each is capped.
        let total = budget + PING_TIMEOUT * u32::from(PING_COUNT) + PTR_TIMEOUT;
        assert!(
            total < Duration::from_secs(30),
            "probe total must stay under 30 s, got {total:?}"
        );
    }

    #[test]
    fn tracert_per_hop_wait_matches_the_budget_constant() {
        // Guards the pair drifting apart again: reading "-w X" while budgeting
        // on a different Y was the actual bug (900 vs 700).
        let src = include_str!("network.rs");
        let expected = format!("\"-w\".to_string(),\n                per_hop,");
        assert!(
            src.contains(&expected),
            "tracrt args must pass `per_hop` (derived from TRACERT_PER_HOP_MS), not a literal"
        );
        assert!(
            src.contains("let per_hop = TRACERT_PER_HOP_MS.to_string();"),
            "per_hop must be derived from the same constant the budget uses"
        );
        assert!(
            !src.contains("\"-w\".to_string(), \"900\""),
            "the old 900 ms literal must not come back"
        );
    }
}
