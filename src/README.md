# src

Component Package containing the frontend application root, React state orchestration, design system styles, and subpackages for UI components and core services.

## Interface

### `main.tsx`
Client bootstrap module that initializes the React DOM root (`createRoot`) and wraps the hierarchy with `I18nProvider`.

### `App.tsx`
Root orchestrator component managing primary frontend application state:
- **Scan Lifecycle**: Manages active checks, stream listeners, cancellation, and error handling.
- **State Aggregation**: Aggregates streaming provider events (`CheckProgressEvent`) into `FullCheckResult` and updates the active `VerdictHUD`.
- **Panel Visibility**: Toggles drawer and modal views (`HistoryPanel`, `SettingsPanel`).
- **Keyboard Shortcuts**: Handles hotkeys for instant scanning (`Enter`), cancellation (`Escape`), and panel navigation.

## Invariants

- Renders within Tauri WebView in desktop mode, falling back to mock or disconnected messaging when opened in standard browser development mode.
- Scan state transitions strictly from `idle` -> `scanning` -> `complete` (or `error`).
- Streaming updates accumulate monotonically into the active result store without discarding partial evidence.

## Side Effects

- Mounts DOM tree into `index.html#root`.
- Subscribes to global window events and Tauri IPC event channels (`check-progress`).
- Interacts with system clipboard for copy actions.

## Subdirectories & System Boundaries

- **Subdirectories**:
  - [`components`](./components/README.md): High-level dashboard panels, cards, data tables, and atomic UI primitives.
  - [`lib`](./lib/README.md): Type contracts, Tauri IPC client wrappers, and internationalization dictionaries.
- **System Boundaries**:
  - Hosted inside Tauri v2 WebView window.
  - Communicates with Tauri Rust backend across IPC (`@tauri-apps/api/core`).

## Verification

```bash
node --test src/components/ui/meta.test.mjs src/lib/i18n.test.mjs
```
