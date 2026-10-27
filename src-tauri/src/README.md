# src-tauri/src

Component Package containing the core Rust backend of IP Checker, including the Tauri v2 IPC command surface, multi-source orchestration engine, mathematical scoring system, SQLite persistence, and diagnostic network subsystems.

## Interface

### IPC Commands (`commands.rs`)
Registered in `lib.rs` with `tauri::generate_handler!`:
- `check_ip(input, options)`: Executes complete blocking scan and returns `FullCheckResult`.
- `check_ip_stream(app, input, options)`: Executes streaming scan, emitting progress events over the `check-progress` Tauri event channel.
- `get_history(limit)`: Fetches past check summaries from the local SQLite audit log.
- `get_check_detail(check_id)`: Retrieves a specific historical check result with full evidence.
- `export_report(check_id, format, out_path)`: Exports sanitized audit report in JSON, CSV, or Markdown.
- `get_provider_health()`: Returns latency, success count, and circuit-breaker status across all providers.
- `save_settings(settings)` / `get_settings()`: Manages application configuration.
- `save_provider_key(provider, key)` / `clear_provider_key(provider)`: Securely manages API keys in Windows Credential Manager.
- `get_geo_db_versions()`: Returns version metadata for local offline MMDB/IP2Location databases.
- `open_external(app, url)`: Launches host browser for requested URL.

### Core Modules
- `orchestrator.rs`: Coordinates concurrent provider queries, DNSBL queries, ping tests, and streaming IPC events with timeout budgets.
- `scoring.rs`: Computes the 5-aspect weighted Clean Score (0–100) and Confidence Score (0–100%), enforces the 40% maximum provider weight rule, evaluates quorums, and applies conflict demotions.
- `validator.rs`: Strict input validator parsing IPv4, IPv6, and proxy strings, rejecting non-routable/private IP ranges (RFC 1918, RFC 5735, RFC 6890).
- `dnsbl.rs`: High-concurrency asynchronous DNSBL checking across 21+ real-time zones using `hickory-resolver`.
- `location.rs`: Multi-provider geolocation triangulation calculating Haversine distance, centroid, and divergence threshold flags.
- `network.rs`: Network latency ping (ICMP with TCP fallback), reverse DNS (PTR), and Anycast edge detection.
- `exit_ip.rs`: Discovers actual egress exit IP over HTTP/SOCKS5 proxy tunnels via echo endpoints.
- `browser_leak.rs`: WebRTC and browser leak testing via local socket binding.
- `speed.rs`: Measures TTFB and synthetic download throughput over active proxy connections.
- `cache.rs`: Thread-safe SQLite database manager for history records and cache retention.
- `config.rs`: Windows Credential Manager interface via `keyring` crate.
- `export.rs`: Audit report generator supporting JSON, CSV, and Markdown with automatic IP redaction options.
- `geo_db.rs`: Embedded offline MaxMind DB (`.mmdb`) and IP2Location reader.
- `models.rs`: Serde DTOs, domain structures, and enums (`Verdict`, `Signal`, `Category`, `ModuleStatus`).
- `state.rs`: Shared application state (`AppState`) managed by Tauri.

## Invariants

- Authoritative Validation: `validator.rs` validates every input before network calls; reserved or private addresses immediately return `Err(CommandError::PrivateIp)`.
- Audited Scoring Rules:
  - No single provider holds more than 40% weight within its evaluation aspect.
  - Quorum Enforcement: Requires at least 2 fraud providers, 3 blacklist providers, and 2 ASN sources; failure forces `provisional = true` and verdict `"Chưa đủ dữ liệu"`.
  - Single Strong Evidence Demotion: Authoritative Spamhaus SBL or active Tor exit listings automatically cap verdict at `"Nghi ngờ"`.
- Zero-Plaintext Keys: Third-party API credentials are stored exclusively in Windows Credential Manager (`service: com.ipchecker.app`), never written to SQLite or transmitted to frontend.
- Log Privacy: Diagnostic logging automatically sanitizes or redacts IP addresses and sensitive query strings.

## Side Effects

- Network Sockets: Opens outbound HTTPS connections, DNS queries (UDP/TCP port 53), ICMP echo sockets, and SOCKS5/HTTP proxy tunnels.
- File System: Reads and writes SQLite database (`ip-checker.db`) in application data directory; writes exported audit reports.
- OS Credential Store: Accesses Windows Credential Manager via native Win32 DPAPI / CredRead / CredWrite APIs.
- Tauri Runtime: Emits IPC events (`check-progress`) to frontend webview.

## Subdirectories & System Boundaries

- **Subdirectories**:
  - [`bin`](./bin/README.md): Headless CLI bridge binary (`probe.rs`).
  - [`providers`](./providers/README.md): Upstream intelligence provider adapters.
- **System Boundaries**:
  - Consumed by Tauri runtime (`tauri::Builder`).
  - Implements the backend counterpart of frontend contracts (`src/lib/types.ts`).

## Verification

```powershell
cargo check --lib --manifest-path src-tauri/Cargo.toml
```
