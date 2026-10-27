# providers

Component Package implementing external threat intelligence, geolocation, BGP/ASN, and fraud risk provider adapters, coordinated through a common asynchronous trait and registry.

## Interface

### `Provider` Trait (`mod.rs`)
Unified asynchronous contract implemented by all upstream intelligence adapters:
- `id(&self) -> &'static str`: Unique identifier matching registry definitions (e.g. `"scamalytics"`, `"ipqualityscore"`).
- `category(&self) -> Category`: Target evaluation aspect (`geo`, `asn`, `fraud`, `abuse`, `threat_intel`, `blacklist`).
- `upstream(&self) -> &'static str`: Root data origin identifier used for upstream deduplication.
- `requires_key(&self) -> bool`: Indicates if an authenticated API credential is required.
- `check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError>`: Dispatches request, normalizes vendor payload into standard `ProviderEvidence`, and assigns normalized `Signal` (`Clean`, `Suspicious`, `Bad`).
- `health(&self) -> Option<ProviderHealth>`: Returns operational latency and failure metrics.

### Registry (`registry.rs`)
- `ProviderRegistry`: Registry loader parsing `providers.yaml`, binding credential secrets from Windows Credential Manager, and managing provider lifecycles.

### Implemented Adapters
- **Geolocation & IP Metadata**:
  - `ip_api.rs`: IP-API JSON endpoint (lat/lon, ISP, AS, hosting/proxy flags).
  - `ipwho.rs`: IPWhois regional lookup.
  - `ipinfo.rs`: IPinfo.io geolocation and privacy attributes.
- **ASN & BGP Routing**:
  - `bgpview.rs`: BGPView ASN prefixes and upstream peer graphs.
  - `ripestat.rs`: RIPE NCC Stat RIR allocation records.
  - `team_cymru.rs`: Team Cymru DNS-based origin BGP resolution (`origin.asn.cymru.com`).
- **Fraud & Proxy Scoring**:
  - `ipqs.rs`: IPQualityScore commercial bot and proxy score.
  - `proxycheck.rs`: ProxyCheck.io real-time VPN and proxy risk flags.
  - `scamalytics.rs`: Scamalytics REST API fraud risk score.
- **Abuse & Threat Intelligence**:
  - `abuseipdb.rs`: AbuseIPDB attack history and abuse confidence rating.
  - `greynoise.rs`: GreyNoise internet background noise and malicious actor classification.

## Invariants

- Upstream Deduplication: Each adapter must supply an explicit `upstream` tag. Resellers or mirrors sharing an upstream collapse into a single vote in the scoring engine.
- Credential Redaction: API tokens are strictly kept in memory or retrieved from OS keyring; they must never be recorded in `ProviderEvidence::raw` or diagnostic logs.
- Fault Isolation: Network errors, rate limits (HTTP 429), or authentication failures return `Err(ProviderError)` and must never panic or terminate the orchestrator.
- Schema Robustness: Unrecognized keys in `providers.yaml` are ignored (`#[serde(default)]`), ensuring backwards-compatible registry updates.

## Side Effects

- Initiates outbound HTTPS requests to third-party vendor APIs.
- Queries external DNS resolvers for DNS-based intelligence (Team Cymru).
- Accesses Windows Credential Manager to retrieve configured API keys.

## Subdirectories & System Boundaries

- **Subdirectories**: None (leaf package).
- **System Boundaries**:
  - Consumed by `../orchestrator.rs`.
  - Driven by configuration in `../../providers.yaml`.
  - Depends on `../models.rs` for shared DTO definitions.

## Verification

```powershell
cargo check --lib --manifest-path src-tauri/Cargo.toml
```
