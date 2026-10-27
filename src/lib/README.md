# lib

Component Package containing typed Tauri v2 IPC command wrappers, shared domain type definitions, and the internationalization engine.

## Interface

### `api.ts`
Type-safe wrappers over Tauri v2 `@tauri-apps/api/core` invoke and event listeners:
- `isTauri(): boolean`: Verifies whether execution occurs inside the Tauri WebView runtime.
- `IpcError`: Standardized error wrapper encapsulating `kind`, `detail`, and `command` metadata.
- `checkIp(input, options)`: Synchronous full scan invocation.
- `checkIpStream(input, options, onProgress)`: Asynchronous streaming scan with IPC event subscription (`check-progress`). Returns an unlisten cleanup function.
- `getHistory(limit)`: Retrieves previous scan summaries from SQLite cache.
- `getCheckDetail(checkId)`: Retrieves complete historical audit snapshot.
- `exportReport(checkId, format, outPath)`: Triggers file export in JSON, CSV, or Markdown.
- `getProviderHealth()`: Queries real-time provider latency and circuit-breaker status.
- `saveSettings(settings)` / `getSettings()`: Reads and updates user application settings.
- `saveProviderKey(provider, key)` / `clearProviderKey(provider)`: Manages API keys stored in Windows Credential Manager.
- `getGeoDbVersions()`: Queries local offline MaxMind and IP2Location database versions.
- `openExternal(url)`: Invokes host shell to launch default system browser.

### `types.ts`
Authoritative TypeScript type contract mirroring Rust serde DTOs (1:1 with `src-tauri/src/models.rs`):
- **Core Enums**: `CheckMode`, `ProxyProtocol`, `Category`, `Signal`, `Verdict`, `ModuleStatus`, `SkipReason`, `IpType`.
- **Data Models**: `ProviderEvidence`, `ScoringResult`, `FullCheckResult`, `CheckSummary`, `CheckProgressEvent`, `Settings`, `ProviderHealth`, `CommandError`.

### `i18n.ts`
Comprehensive multi-language localization framework:
- Supported Locales: Vietnamese (`vi`, default), English (`en`), Chinese (`zh`).
- Functions: `useI18n()`, `t(key, params?)`, `getTranslation(lang, key, params?)`.
- Complete dictionary matrices across navigation, dashboard metrics, scoring aspects, error codes, and technical tooltips.

## Invariants

- All types in `types.ts` use strict `snake_case` properties to match backend Serde JSON output without client-side transformation.
- IPC command wrappers in `api.ts` translate all low-level communication exceptions into structured `IpcError` instances.
- UI localization preserves Vietnamese as the default fallback when strings are missing in selected secondary languages (`en`, `zh`).
- The module remains decoupled from React UI components, enabling headless testing with standard Node test harnesses.

## Side Effects

- Dispatches IPC commands across Tauri's webview bridge to the backend core.
- Registers and unregisters window event listeners (`listen` / `unlisten`).
- Accesses browser local storage when persisting UI language preferences.

## Subdirectories & System Boundaries

- **Subdirectories**: None (leaf package).
- **System Boundaries**:
  - Consumed by `../src/components/*` and `../src/App.tsx`.
  - Bridges the webview to the Rust backend (`src-tauri/src/commands.rs`).

## Verification

```bash
node --test src/lib/i18n.test.mjs
```
