# components

Component Package containing high-level React UI cards, dashboard panels, data tables, and input controllers that compose the IP Checker dashboard.

## Interface

Exported dashboard and functional view components:
- `AppHeader`: Application header with branding, version indicator, language selector, and quick navigation.
- `VerdictHUD`: Real-time Clean Score (0–100) dial, Confidence Score (0–100%) dial, consensus verdict badge, quorum warning chips, and primary reason label.
- `OverviewCard`: High-level summary of IP classification (residential, hosting, mobile, proxy), ISP, Autonomous System, and location consensus.
- `ReputationCard`: Breakdown of the 5 scoring aspects, vendor risk scores (IPQS, Scamalytics, ProxyCheck), and threat classification.
- `NetworkCard`: Detailed BGP routing metadata, peer information, reverse DNS (PTR), ICMP ping latency, and Anycast edge detection.
- `GeoMapCard`: Leaflet-powered interactive map visualizing multi-provider geolocation coordinates, centroid triangulation, and divergence radius.
- `LeakSpeedCard`: WebRTC private/public IP leak detection, DNS resolver leak verification, and HTTP synthetic throughput / TTFB measurements (with fallback banner when running in IP-only mode).
- `BlacklistTable`: DNSBL blacklist results across 21+ real-time zones (Spamhaus, Barracuda, UCEPROTECT, DroneBL, etc.) with category filtering.
- `EvidenceTable`: Granular multi-source evidence audit log showing raw signals (`Clean`, `Suspicious`, `Bad`), response latency, and failure details.
- `ScanProgress`: Real-time multi-module execution progress bar and live status counters.
- `InputConsole`: Input interface supporting IPv4, IPv6, and Proxy URL formats (`host:port`, `user:pass@host:port`, `protocol://`), client-side syntax validation, and scan triggering.
- `HistoryPanel`: Persistent scan history drawer with click-to-load inspection, timestamps, and verdict badges.
- `SettingsPanel`: Configuration drawer for Windows Credential Manager API key storage, DNSBL group selection, concurrency limits, and export formats.

## Invariants

- Clean Score and Confidence Score are maintained as separate numerical values and are never combined into a single ambiguous percentage.
- In IP-Only mode, proxy-dependent metrics (DNS leak, WebRTC leak, HTTP speed) strictly render the explicit placeholder banner (`"Chưa đo được — cần nhập proxy"`) rather than synthetic or zero values.
- UI components consume pre-computed scores and signals emitted from the Rust backend via `src/lib/api.ts`; no scoring calculations are performed within frontend components.
- Components support dynamic multi-language localization (`vi`, `en`, `zh`) via `useI18n()` context.

## Side Effects

- Triggers backend IPC calls via `src/lib/api.ts` (`check_ip_stream`, `get_history`, `save_provider_key`, etc.).
- Mounts and updates Leaflet map DOM nodes in `GeoMapCard`.
- Writes user preferences and active inputs to local React state and component props.

## Subdirectories & System Boundaries

- **Subdirectories**:
  - [`ui`](./ui/README.md): Atomic UI presentation primitives, client-side input validation, and metadata resolvers.
- **System Boundaries**:
  - Consumed by `../App.tsx`.
  - Depends on `../lib/api.ts` for IPC actions, `../lib/types.ts` for contracts, and `../lib/i18n.ts` for localization.

## Verification

```bash
node --test src/components/ui/keyErrors.test.mjs src/components/ui/meta.test.mjs
```
