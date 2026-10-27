# src-tauri

Component Package encapsulating the Tauri v2 desktop application backend, build configuration, native OS integration, and dependency manifests.

## Interface

### `tauri.conf.json`
Tauri configuration file defining desktop application parameters:
- Application identifier: `com.ipchecker.app`.
- Product name: `IP Checker`.
- Window specs: `1280x860` default resolution, dark background (`#050810`).
- Permissions: Enables dialog plugin (`tauri-plugin-dialog`) and `protocol-asset` security features.
- Bundle settings: Configures Windows NSIS installer parameters and portable executable generation.

### `Cargo.toml`
Rust workspace manifest:
- Library: `ip_checker_lib` (`staticlib`, `cdylib`, `rlib`).
- Default Binary: `ip-checker` (Tauri desktop executable).
- Diagnostic Binary: `probe` (`src/bin/probe.rs`).
- Key Dependencies: `tauri` v2, `tokio` (async runtime), `reqwest` (HTTP client with rustls-tls & socks support), `hickory-resolver` (async DNSBL client), `rusqlite` (bundled SQLite), `keyring` (Windows Credential Manager integration), `serde` / `serde_json`, `maxminddb`.

### `build.rs`
Build script triggering `tauri_build::build()` to compile Windows application resources, icons, and Tauri manifest bindings.

## Invariants

- Binary Selection: `default-run = "ip-checker"` is strictly enforced so that `cargo tauri build` packages the GUI application rather than the headless `probe` binary.
- Cargo feature `protocol-asset` is maintained in sync with `tauri.conf.json` security settings to prevent build-time validation failures.
- Zero-Plaintext Credential Policy: No API secrets or environment variables containing credentials may be baked into compiled release binaries.

## Side Effects

- Compiles native machine code targeting `x86_64-pc-windows-msvc`.
- Generates build output inside `target/` directory.
- Links against Windows system libraries (`Advapi32`, `Crypt32`, `User32`, `Kernel32`, `Iphlpapi`).

## Subdirectories & System Boundaries

- **Subdirectories**:
  - [`src`](./src/README.md): Rust source code tree containing commands, orchestrator, scoring engine, and providers.
- **System Boundaries**:
  - Bridges the frontend webview (`dist/`) to the Windows host operating system.
  - Bundled into portable executables and NSIS installers by Tauri CLI.

## Verification

```powershell
cargo check --manifest-path src-tauri/Cargo.toml
```
