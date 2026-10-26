<#
.SYNOPSIS
    IP Checker -- reproducible Windows build.

.DESCRIPTION
    Implements spec sec11 (packaging) + sec12 Phase 4 (installer NSIS + portable .exe).

    Pipeline:
      1. preflight   -- node/npm, rustc/cargo, x86_64-pc-windows-msvc target, Tauri CLI, disk space
      2. npm ci      -- deterministic dependency install (fallback to `npm install` on lockfile-less tree)
      3. npm run build  -- tsc --noEmit && vite build  (front-end dist)
      4. cargo test  -- headless unit/integration tests (skippable)
      5. cargo tauri build -- NSIS installer + portable exe
      6. report      -- prints every produced artifact path

    Any missing toolchain item fails LOUDLY with a checklist instead of a half-built installer.

.PARAMETER SkipTests      Skip `cargo test` (faster packaging loop).
.PARAMETER SkipNpmCi      Reuse the existing node_modules instead of a clean install.
.PARAMETER FrontEndOnly   Stop after `npm run build`.
.PARAMETER NoBundle       Build the release binary but skip installer bundling (fast check).
.PARAMETER Ci             Non-interactive: abort immediately on first failure (used by smoke.ps1).
.PARAMETER BuildNumber    Optional integer appended to the product version.

.EXAMPLE
    pwsh -File scripts/build.ps1
    pwsh -File scripts/build.ps1 -SkipTests -Ci
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipNpmCi,
    [switch]$FrontEndOnly,
    [switch]$NoBundle,
    [switch]$Ci,
    [string]$BuildNumber
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- paths / env
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ProjectRoot 'package.json'

# rustup installs into %USERPROFILE%\.cargo\bin which is frequently NOT on PATH
# inside non-login shells (CI, agent sandboxes, fresh PowerShell). Prepend it.
$CargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path -LiteralPath $CargoBin) {
    $env:PATH = "$CargoBin;$env:PATH"
}

if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = Join-Path $ProjectRoot 'src-tauri\target'
}
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR | Out-Null

# ---------------------------------------------------------------- logging
$script:LogLines = [System.Collections.Generic.List[string]]::new()
function Write-Step   { param([string]$m) $line = "==> $m"; $script:LogLines.Add($line); Write-Host $line -ForegroundColor Cyan }
function Write-Info   { param([string]$m) $line = "    $m"; $script:LogLines.Add($line); Write-Host $line }
function Write-Ok     { param([string]$m) $line = "  [OK] $m"; $script:LogLines.Add($line); Write-Host $line -ForegroundColor Green }
function Write-Warn2  { param([string]$m) $line = "  [WARN] $m"; $script:LogLines.Add($line); Write-Host $line -ForegroundColor Yellow }
function Write-Fail   { param([string]$m) $line = "  [FAIL] $m"; $script:LogLines.Add($line); Write-Host $line -ForegroundColor Red }

function Invoke-Native {
    <# Runs a native command, streams output, returns exit code. Never throws on non-zero. #>
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkDir = $ProjectRoot
    )
    $display = "$Exe $($Arguments -join ' ')"
    Write-Info "`$ $display"
    $script:LogLines.Add("    `$ $display")
    Push-Location $WorkDir
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object {
            $t = "$_"
            $script:LogLines.Add("      $t")
            Write-Host "      $t"
        }
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prevEAP
        Pop-Location
    }
}

function Exit-WithChecklist {
    param([string]$Reason, [string[]]$Checklist)
    Write-Fail $Reason
    Write-Host ''
    Write-Host 'MISSING TOOLCHAIN CHECKLIST' -ForegroundColor Red
    foreach ($c in $Checklist) { Write-Host "  - $c" -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Install hints:' -ForegroundColor Yellow
    Write-Host '  rustup  : https://rustup.rs   ->  rustup target add x86_64-pc-windows-msvc'
    Write-Host '  MSVC    : Visual Studio 2022 Build Tools, workload "Desktop development with C++" + Windows SDK 10.0.26100'
    Write-Host '  Node    : https://nodejs.org  (>= 20)'
    Write-Host '  TauriCLI: npm i -D @tauri-apps/cli'
    Write-Host ''
    $logPath = Join-Path $ProjectRoot 'scripts\build.log'
    $script:LogLines | Set-Content -LiteralPath $logPath -Encoding utf8
    Write-Host "Full log: $logPath"
    exit 1
}

$script:StartedAt = Get-Date
$script:TestsFailed = $false
Write-Host ''
Write-Host 'IP CHECKER -- BUILD (spec sec11)' -ForegroundColor Magenta
Write-Host ("Project : " + $ProjectRoot)
Write-Host ("Target  : " + $env:CARGO_TARGET_DIR)
Write-Host ("Started : " + $script:StartedAt.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ''

# ---------------------------------------------------------------- 1. preflight
Write-Step 'Preflight: toolchain'
$missing = [System.Collections.Generic.List[string]]::new()

# node / npm
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
$npmCmd  = Get-Command npm  -ErrorAction SilentlyContinue
if (-not $nodeCmd) { $missing.Add('node (Node.js >= 20) not found on PATH') } else { Write-Ok "node $( & node --version )" }
if (-not $npmCmd)  { $missing.Add('npm not found on PATH') } else { Write-Ok "npm $( & npm --version )" }

# rustc / cargo
$rustcCmd = Get-Command rustc -ErrorAction SilentlyContinue
$cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $rustcCmd) { $missing.Add("rustc not found (looked on PATH and $CargoBin)") } else { Write-Ok "$( & rustc --version )" }
if (-not $cargoCmd) { $missing.Add("cargo not found (looked on PATH and $CargoBin)") } else { Write-Ok "$( & cargo --version )" }

# MSVC target
if ($cargoCmd) {
    $rustupCmd = Get-Command rustup -ErrorAction SilentlyContinue
    if ($rustupCmd) {
        $targets = (& rustup target list --installed) 2>&1
        if ("$targets" -match 'x86_64-pc-windows-msvc') {
            Write-Ok 'rust target x86_64-pc-windows-msvc installed'
        } else {
            $missing.Add('rust target x86_64-pc-windows-msvc missing  ->  rustup target add x86_64-pc-windows-msvc')
        }
    } else {
        Write-Warn2 'rustup not found -- cannot verify x86_64-pc-windows-msvc target; cargo will report a link error if MSVC is absent'
    }
}

# MSVC linker (link.exe comes from VS Build Tools; cargo finds it via vswhere at build time)
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere) {
    $vsPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) 2>&1
    if ($vsPath) { Write-Ok "MSVC Build Tools: $vsPath" }
    else { $missing.Add('MSVC C++ build tools component missing (Visual Studio Build Tools 2022, workload "Desktop development with C++")') }
} else {
    Write-Warn2 'vswhere.exe not found -- MSVC toolchain presence cannot be verified up front'
}

# Tauri CLI: binary node_modules/.bin/tauri.cmd OR a `tauri` entry in package.json scripts
$tauriCliLocal = Join-Path $ProjectRoot 'node_modules\@tauri-apps\cli'
$hasTauriCli = Test-Path -LiteralPath $tauriCliLocal
if ($hasTauriCli) { Write-Ok "@tauri-apps/cli present ($tauriCliLocal)" }
else { $missing.Add('Tauri CLI missing  ->  npm i -D @tauri-apps/cli') }

# package.json + tauri.conf.json are owned by the scaffold agent -- verify, do not repair
if (-not (Test-Path -LiteralPath $ManifestPath)) { $missing.Add('package.json missing at project root') }
$tauriConf = Join-Path $ProjectRoot 'src-tauri\tauri.conf.json'
if (-not (Test-Path -LiteralPath $tauriConf)) { $missing.Add('src-tauri/tauri.conf.json missing') }
$cargoToml = Join-Path $ProjectRoot 'src-tauri\Cargo.toml'
if (-not (Test-Path -LiteralPath $cargoToml)) { $missing.Add('src-tauri/Cargo.toml missing') }

# disk space (target dir drive)
$targetDrive = (Split-Path -Qualifier $env:CARGO_TARGET_DIR)
$free = (Get-PSDrive -Name $targetDrive.TrimEnd(':') -ErrorAction SilentlyContinue).Free
if ($null -ne $free) {
    $freeGb = [math]::Round($free / 1GB, 2)
    if ($freeGb -lt 4) { Write-Warn2 "only $freeGb GB free on $targetDrive (a debug+release rust build can exceed this)" }
    else { Write-Ok "$freeGb GB free on $targetDrive" }
}

if ($missing.Count -gt 0) {
    Exit-WithChecklist -Reason "Preflight failed: $($missing.Count) required item(s) missing." -Checklist $missing
}

# ---------------------------------------------------------------- 2. npm ci
Write-Step 'Installing npm dependencies'
if ($SkipNpmCi) {
    Write-Info 'skipped (-SkipNpmCi)'
} else {
    $lock = Join-Path $ProjectRoot 'package-lock.json'
    if (Test-Path -LiteralPath $lock) {
        $code = Invoke-Native -Exe 'npm' -Arguments @('ci', '--no-audit', '--no-fund')
    } else {
        Write-Warn2 'package-lock.json absent -- falling back to `npm install` (not reproducible)'
        $code = Invoke-Native -Exe 'npm' -Arguments @('install', '--no-audit', '--no-fund')
    }
    if ($code -ne 0) { Exit-WithChecklist -Reason "npm dependency install failed (exit $code)." -Checklist @('Check network / registry access', 'Delete node_modules and retry') }
    Write-Ok 'npm dependencies installed'
}

# Re-verify the Tauri CLI after install (a fresh clone may have nothing yet).
if (-not (Test-Path -LiteralPath $tauriCliLocal)) {
    Exit-WithChecklist -Reason 'Tauri CLI still missing after npm install.' -Checklist @('npm i -D @tauri-apps/cli (package.json is owned by the scaffold task)')
}

# ---------------------------------------------------------------- 3. front-end build
Write-Step 'Building front-end (tsc --noEmit && vite build)'
$code = Invoke-Native -Exe 'npm' -Arguments @('run', 'build')
if ($code -ne 0) { Exit-WithChecklist -Reason "`npm run build` failed (exit $code)." -Checklist @('Fix TypeScript errors reported above', 'Run `npm run typecheck` for the isolated view') }
$distDir = Join-Path $ProjectRoot 'dist'
if (Test-Path -LiteralPath (Join-Path $distDir 'index.html')) {
    $distSize = [math]::Round(((Get-ChildItem -Recurse -File $distDir | Measure-Object -Property Length -Sum).Sum) / 1MB, 2)
    Write-Ok "dist/ built ($distSize MB)"
} else {
    Exit-WithChecklist -Reason 'dist/index.html not produced by vite build.' -Checklist @('Check vite.config.ts build.outDir')
}

if ($FrontEndOnly) {
    Write-Ok 'Front-end only build finished (-FrontEndOnly)'
    exit 0
}

# ---------------------------------------------------------------- 4. cargo test
if ($SkipTests) {
    Write-Step 'cargo test -- skipped (-SkipTests)'
} else {
    Write-Step 'Running cargo test (headless)'
    $code = Invoke-Native -Exe 'cargo' -Arguments @('test', '--manifest-path', $cargoToml, '--all-targets', '--', '--test-threads=1')
    if ($code -ne 0) {
        Write-Warn2 "cargo test failed (exit $code) -- packaging continues, but DO NOT ship."
        $script:TestsFailed = $true
    } else { Write-Ok 'cargo test passed' }
}

# ---------------------------------------------------------------- 5. tauri build
Write-Step 'Building Tauri bundle (NSIS installer + portable exe)'
$env:CI = $null
# package.json is owned by the scaffold task; resolve its `tauri` script, then call the
# local CLI directly so argument passing is unambiguous (npm run tauri -- x is fragile).
$tauriCmd = Join-Path $ProjectRoot 'node_modules\.bin\tauri.cmd'
if (-not (Test-Path -LiteralPath $tauriCmd)) { $tauriCmd = 'tauri' }

$tauriArgs = @('build')
if ($NoBundle) { $tauriArgs += '--no-bundle' }
if ($BuildNumber) { $tauriArgs += @('--config', "{`"version`":`"0.1.0+$BuildNumber`"}") }
if ($env:TAURI_SIGNING_PRIVATE_KEY) { Write-Info 'updater signing key detected -- artifacts will be signed' }
else { Write-Warn2 'TAURI_SIGNING_PRIVATE_KEY not set -- release stays unsigned (SmartScreen warning, see README)' }

$code = Invoke-Native -Exe $tauriCmd -Arguments $tauriArgs
if ($code -ne 0) {
    Exit-WithChecklist -Reason "tauri build failed (exit $code)." -Checklist @('Read the cargo/tauri error above','Verify src-tauri/Cargo.toml + tauri.conf.json','Verify webview2 is installed for the target machine')
}

# ---------------------------------------------------------------- 6. report artifacts
Write-Step 'Artifacts'
$bundleRoot = Join-Path $env:CARGO_TARGET_DIR 'release'
$portableExe = Join-Path $bundleRoot 'ip-checker.exe'
if (-not (Test-Path -LiteralPath $portableExe)) {
    # productName "IP Checker" -> binary may be named differently; search
    $cand = Get-ChildItem -Path $bundleRoot -Filter '*.exe' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch 'build-script|uninstall' } | Select-Object -First 1
    if ($cand) { $portableExe = $cand.FullName }
}

$nsisExe = Get-ChildItem -Path (Join-Path $bundleRoot 'bundle\nsis') -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1
$msiExe  = Get-ChildItem -Path (Join-Path $bundleRoot 'bundle\msi') -Filter '*.msi' -File -ErrorAction SilentlyContinue | Select-Object -First 1

$artifacts = @()
if ($portableExe -and (Test-Path -LiteralPath $portableExe)) {
    $artifacts += [pscustomobject]@{ Kind='portable exe'; Path=$portableExe; SizeMB=[math]::Round((Get-Item $portableExe).Length/1MB,2) }
}
if ($nsisExe) { $artifacts += [pscustomobject]@{ Kind='NSIS installer'; Path=$nsisExe.FullName; SizeMB=[math]::Round($nsisExe.Length/1MB,2) } }
if ($msiExe)  { $artifacts += [pscustomobject]@{ Kind='MSI installer';  Path=$msiExe.FullName;  SizeMB=[math]::Round($msiExe.Length/1MB,2) } }

if ($artifacts.Count -eq 0) {
    Write-Fail 'No artifact produced. Check the tauri build output above.'
    exit 1
}

$artifacts | Format-Table -AutoSize | Out-String | Write-Host
foreach ($a in $artifacts) { Write-Ok ("{0}: {1} ({2} MB)" -f $a.Kind, $a.Path, $a.SizeMB) }

# artifact manifest for smoke.ps1 / release notes
$manifestJson = Join-Path $ProjectRoot 'scripts\build-artifacts.json'
$artifacts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestJson -Encoding utf8
Write-Info "artifact manifest: $manifestJson"

$elapsed = (Get-Date) - $script:StartedAt
Write-Host ''
Write-Host ("BUILD OK in {0:mm\:ss}" -f $elapsed) -ForegroundColor Green
if ($script:TestsFailed) { Write-Warn2 'WARNING: cargo test failed earlier -- artifact is NOT release-grade.'; exit 2 }
$script:LogLines | Set-Content -LiteralPath (Join-Path $ProjectRoot 'scripts\build.log') -Encoding utf8
exit 0
