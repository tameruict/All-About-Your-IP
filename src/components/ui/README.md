# ui

Component Package containing atomic UI presentation primitives, client-side IP/proxy syntax validation, IPC credential error classification, and localized metadata mappings.

## Interface

### `parts.tsx`
Reusable layout and visual components:
- `Panel(props: PanelProps)`: Card container supporting titles, right-aligned hints, scrollable bodies, and footers.
- `Banner(props: BannerProps)`: Notification banner supporting `info | warn | error | conflict | muted` tones.
- `Kvp(props: KvpProps)`: Standardized key-value pair display with status coloring and copy triggers.
- `ToneBadge(props: ToneBadgeProps)`: Color-coded chip for verdicts, signals, and health states.
- `ExternalLink(props: ExternalLinkProps)`: External link component integrating with Tauri's shell opener.
- `ScoreRing(props: ScoreRingProps)`: SVG-based circular gauge for composite scores.
- `SkeletonBar(props: SkeletonBarProps)`: Shimmer placeholder for pending data modules.
- `RetryButton(props: RetryButtonProps)`: Targeted retry button for individual failed providers.

### `ipInput.ts`
Client-side input parsing engine mirroring backend validation rules:
- `classifyParsedInput(raw: string): ParsedInput`: Parses raw input string into IP-only or proxy modes, extracting host, port, credentials, protocol, IP version, and reservation reasons.
- `parseIpv4Strict(value: string): string | null`: Dotted-quad IPv4 parser with leading-zero rejection.
- `parseIpv6Strict(value: string): string | null`: Strict RFC 5952 IPv6 parser.
- `parseProxyStrict(value: string)`: Proxy endpoint parser handling `[host]:port`, `protocol://`, and inline auth.

### `meta.ts`
Localization and styling metadata:
- `normalizeLanguage(lang?: Language | null): "vi" | "en" | "zh"`: Locale normalizer defaulting to Vietnamese.
- `NOT_MEASURED_PROXY`: Constant string (`"Chưa đo được — cần nhập proxy"`) and localized variants.
- Visual mappers: `scoreTone(score)`, `confidenceTone(confidence)`, `cx(...classes)`.
- Label resolvers: `getLocalizedVerdictMeta`, `getLocalizedSignalMeta`, `getLocalizedModuleLabel`, `getLocalizedStatusLabel`, `getLocalizedSkipReasonLabel`, `getLocalizedCategoryLabel`, `getLocalizedIpTypeLabel`.

### `keyErrors.ts`
Error categorization for IPC credential vault operations:
- `classifyKeyError(err: KeyErrorLike): KeyErrorBranch`: Categorizes errors into `arg_mismatch`, `not_registered`, `no_ipc`, or `other`.
- Enforces strict evaluation order: argument mismatch is matched prior to command registration to prevent mislabeling wiring bugs.

## Invariants

- Client-side validation in `ipInput.ts` is purely advisory for responsive UX; the backend `src-tauri/src/validator.rs` remains the authoritative gatekeeper.
- Scoring is never computed in UI helpers; `meta.ts` strictly maps pre-computed backend values to display tokens and localized text.
- UI strings default to Vietnamese (`vi`) when no valid language code is provided or when translation keys are missing.
- When evaluating key errors, `ARG_MISMATCH_PATTERNS` are evaluated before `NOT_REGISTERED_PATTERNS` to prevent masking schema mismatches.

## Side Effects

- Pure UI rendering and in-memory parsing.
- `ExternalLink` delegates URL opening to the Tauri backend via `open_external` IPC command.

## Subdirectories & System Boundaries

- **Subdirectories**: None (leaf package).
- **System Boundaries**:
  - Consumed by `../` (`src/components/*`).
  - Relies on `../../lib/api.ts` for IPC communication and `../../lib/types.ts` for domain contracts.

## Verification

```bash
node --test src/components/ui/keyErrors.test.mjs src/components/ui/meta.test.mjs
```
