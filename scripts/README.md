# scripts

Component Package containing build automation, procedural asset generation, and post-build verification tooling for the IP Checker Windows desktop application.

## Interface

### `build.ps1`
PowerShell orchestration script implementing reproducible builds, frontend bundling, backend compilation, and Tauri installer creation.
- **Parameters**:
  - `-SkipTests`: Skip running `cargo test` during the build loop.
  - `-SkipNpmCi`: Reuse existing `node_modules` instead of executing a clean install.
  - `-FrontEndOnly`: Terminate pipeline after compiling the frontend (`tsc --noEmit && vite build`).
  - `-NoBundle`: Build release binaries without generating NSIS installer bundles.
  - `-Ci`: Non-interactive mode that halts on the first encountered failure.
  - `-BuildNumber <string>`: Optional integer appended to the product version.

### `smoke.ps1`
Post-build smoke verification runner evaluating build artifacts against three independent gates.
- **Parameters**:
  - `-ExePath <string>`: Path to target executable (defaults to artifact recorded in `build-artifacts.json`).
  - `-SkipLaunch`: Restrict verification to headless `cargo test`.
  - `-GraceSeconds <int>`: Minimum process uptime required during launch validation (default: 12s).
  - `-DevUrl <string>`: HTTP endpoint for frontend shell validation (default: `http://127.0.0.1:1420`).
- **Exit Codes**:
  - `0`: All gates passed.
  - `1`: Gate failure.
  - `3`: Missing build artifacts.
  - `4`: Toolchain or harness blocked.

### `make_icons.py`
Standalone Python utility generating multi-resolution icon assets for Tauri v2 using Pillow.
- **CLI Flags**:
  - `--out <path>`: Target output directory (defaults to `src-tauri/icons`).

## Invariants

- Toolchain preflight validates Node.js, npm, Rust/Cargo (`x86_64-pc-windows-msvc`), Tauri CLI, and available disk capacity before any build step executes.
- Cargo bin path (`$env:USERPROFILE\.cargo\bin`) is prepended to `$env:PATH` dynamically if not present in the execution environment.
- Non-zero process exit codes from child tasks abort pipeline execution when `-Ci` or `$ErrorActionPreference = 'Stop'` is active.
- `smoke.ps1` verifies that a launched executable creates a valid desktop window handle (`MainWindowHandle != 0`) and survives the full grace window before process tree teardown.
- Output artifacts are consistently tracked in `build-artifacts.json` with target paths and file sizes.

## Side Effects

- Modifies local environment variable `$env:PATH` during script execution.
- Generates build logs in `build.log` and metadata in `build-artifacts.json`.
- Compiles frontend assets into `../dist/` and backend binaries into `../src-tauri/target/release/`.
- Spawns, monitors, and terminates child processes (`node`, `cargo`, `ip-checker.exe`).

## Subdirectories & System Boundaries

- **Subdirectories**: None (leaf package).
- **System Boundaries**:
  - Node.js runtime and npm package manager.
  - Rust compiler toolchain (`cargo`, `rustc`, `cargo-tauri`).
  - Python runtime with `Pillow` library.
  - Windows Process API (`System.Diagnostics.Process`).

## Verification

```powershell
powershell -Command "Test-Path scripts/build.ps1, scripts/smoke.ps1, scripts/make_icons.py"
```
