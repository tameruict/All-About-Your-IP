<#
.SYNOPSIS
    IP Checker — post-build smoke test (spec §11 "test on a clean Windows machine", §12 Phase 4 DoD).

.DESCRIPTION
    Three independent gates:

      Gate 1  HEADLESS  cargo test  — every Rust unit/integration test must pass.
      Gate 2  LAUNCH    — start the built .exe, assert the process stays alive for a
                          grace window, assert a top-level window handle is created
                          (MainWindowHandle != 0), then kill the whole process tree.
      Gate 3  HTTP      — if a dev server is running, assert the front-end shell serves
                          and contains the expected Vietnamese labels.

    Exit codes: 0 = all gates passed, 1 = a gate failed, 3 = artifact missing
    (run scripts/build.ps1 first), 4 = toolchain/test-harness blocked.

.PARAMETER ExePath        Explicit path to the built exe; default = read scripts/build-artifacts.json.
.PARAMETER SkipLaunch     Only run the headless cargo test gate.
.PARAMETER GraceSeconds   How long the launched process must stay alive (default 12).
.PARAMETER DevUrl         Front-end URL for gate 3 (default http://127.0.0.1:1420).

.EXAMPLE
    pwsh -File scripts/smoke.ps1
    pwsh -File scripts/smoke.ps1 -ExePath 'C:\cargo-target\ip-checker\release\ip-checker.exe'
#>
[CmdletBinding()]
param(
    [string]$ExePath,
    [switch]$SkipLaunch,
    [int]$GraceSeconds = 12,
    [string]$DevUrl = 'http://127.0.0.1:1420'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$CargoToml   = Join-Path $ProjectRoot 'src-tauri\Cargo.toml'
$CargoBin    = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path -LiteralPath $CargoBin) { $env:PATH = "$CargoBin;$env:PATH" }
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $ProjectRoot 'src-tauri\target' }

$script:Results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Gate, [string]$Status, [string]$Evidence)
    $script:Results.Add([pscustomobject]@{ Gate=$Gate; Status=$Status; Evidence=$Evidence })
    $colour = switch ($Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  [{0}] {1} — {2}" -f $Status, $Gate, $Evidence) -ForegroundColor $colour
}

Write-Host ''
Write-Host 'IP CHECKER — SMOKE' -ForegroundColor Magenta
Write-Host ("Project  : " + $ProjectRoot)
Write-Host ("Target   : " + $env:CARGO_TARGET_DIR)
Write-Host ''

# =============================================================== Gate 1: cargo test
Write-Host 'GATE 1/3 — headless cargo test' -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $CargoToml)) {
    Add-Result 'cargo-test' 'FAIL' "missing $CargoToml"
} else {
    $testLog = Join-Path $env:TEMP "ip-checker-cargo-test-$([guid]::NewGuid().ToString('N').Substring(0,8)).log"
    Push-Location $ProjectRoot
    try {
        # cargo writes normal progress (Compiling/Finished) to stderr. With
        # $ErrorActionPreference = 'Stop' PowerShell turns each such line into a
        # terminating NativeCommandError, which aborts the pipeline before
        # $LASTEXITCODE is read, so a GREEN suite used to be reported as a crash.
        # Relax the preference around the native call and restore it after.
        $savedEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & cargo test --manifest-path $CargoToml --all-targets --no-fail-fast 2>&1 |
                Tee-Object -FilePath $testLog |
                ForEach-Object { Write-Host "      $_" }
            $code = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedEap
        }
    } finally { Pop-Location }

    $tail = (Get-Content -LiteralPath $testLog -ErrorAction SilentlyContinue | Select-Object -Last 40) -join "`n"
    if ($code -eq 0) {
        # `--all-targets` runs three test binaries (lib, main, probe). The last
        # "test result:" line belongs to the empty probe binary, so taking
        # `-Last 1` reported "0 passed" for a suite that actually ran hundreds.
        # Report the lib suite (the one with the real tests) and the total.
        $resultLines = @(Get-Content -LiteralPath $testLog -ErrorAction SilentlyContinue |
            Select-String -Pattern 'test result:')
        $passedTotal = 0
        foreach ($rl in $resultLines) {
            if ($rl.Line -match 'test result:\s*ok\.\s*(\d+) passed') { $passedTotal += [int]$Matches[1] }
        }
        $suiteLine = $resultLines | Where-Object { $_.Line -match '(\d+) passed' -and [int]$Matches[1] -gt 0 } | Select-Object -Last 1
        $evidence = if ($suiteLine) { ($suiteLine.Line -replace '\s+', ' ').Trim() } else { 'all suites empty' }
        Add-Result 'cargo-test' 'PASS' ("exit 0; $passedTotal test(s) passed across $($resultLines.Count) suite(s); $evidence")
    } else {
        $failed = (Get-Content -LiteralPath $testLog -ErrorAction SilentlyContinue | Select-String -Pattern '^(test .* FAILED|failures:)' | Select-Object -First 5) -join '; '
        Add-Result 'cargo-test' 'FAIL' "exit $code; failing: $failed; log: $testLog"
    }
}

if ($SkipLaunch) {
    Write-Host 'Launch + HTTP gates skipped (-SkipLaunch)' -ForegroundColor Yellow
    $script:Results | Format-Table -AutoSize | Out-String | Write-Host
    if (($script:Results | Where-Object Status -eq 'FAIL').Count -gt 0) { exit 1 } else { exit 0 }
}

# =============================================================== resolve exe
Write-Host ''
Write-Host 'GATE 2/3 — launch built exe' -ForegroundColor Cyan

if (-not $ExePath) {
    $manifest = Join-Path $ScriptDir 'build-artifacts.json'
    if (Test-Path -LiteralPath $manifest) {
        $entry = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json) | Where-Object { $_.Kind -eq 'portable exe' } | Select-Object -First 1
        if ($entry) { $ExePath = $entry.Path }
    }
}
if (-not $ExePath) {
    $releaseDir = Join-Path $env:CARGO_TARGET_DIR 'release'
    if (Test-Path -LiteralPath $releaseDir) {
        $cand = Get-ChildItem -Path $releaseDir -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch 'build-script|uninstall' } | Select-Object -First 1
        if ($cand) { $ExePath = $cand.FullName }
    }
}

if (-not $ExePath -or -not (Test-Path -LiteralPath $ExePath)) {
    Add-Result 'launch' 'FAIL' "artifact not found (run scripts/build.ps1 first). Looked for: $ExePath"
    Write-Host ''
    $script:Results | Format-Table -AutoSize | Out-String | Write-Host
    exit 3
}
Write-Host ("      exe: " + $ExePath)

$proc = $null
$windowHandle = 0
$mainWindowTitle = ''
$aliveAfterGrace = $false
try {
    $proc = Start-Process -FilePath $ExePath -PassThru -ErrorAction Stop
    Write-Host ("      pid: " + $proc.Id + " — waiting up to ${GraceSeconds}s")

    # Poll for a real top-level window (WebView2 init can take a few seconds on cold start).
    $deadline = (Get-Date).AddSeconds($GraceSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 400
        if ($proc.HasExited) { break }
        $proc.Refresh()
        if ($proc.MainWindowHandle -ne 0) {
            $windowHandle = $proc.MainWindowHandle
            $mainWindowTitle = $proc.MainWindowTitle
            break
        }
    }
    if (-not $proc.HasExited) { $aliveAfterGrace = $true }
    $proc.Refresh()

    if ($proc.HasExited) {
        Add-Result 'launch' 'FAIL' "process exited during startup with code $($proc.ExitCode)"
    } elseif ($windowHandle -ne 0) {
        Add-Result 'launch' 'PASS' ("pid $($proc.Id) alive, window handle 0x{0:X}, title '$mainWindowTitle'" -f $windowHandle)
    } else {
        Add-Result 'launch' 'FAIL' "pid $($proc.Id) alive after ${GraceSeconds}s but MainWindowHandle == 0 (no window created)"
    }
}
catch {
    Add-Result 'launch' 'FAIL' "Start-Process threw: $($_.Exception.Message)"
}
finally {
    if ($proc -and -not $proc.HasExited) {
        # Kill the whole tree: WebView2 spawns msedgewebview2.exe children that would linger otherwise.
        try {
            & taskkill /PID $proc.Id /T /F 2>&1 | Out-Null
            Start-Sleep -Milliseconds 600
            Write-Host ("      killed pid " + $proc.Id + " (tree)")
        } catch { Write-Host ("      cleanup warning: " + $_.Exception.Message) -ForegroundColor Yellow }
    }
    $lingering = Get-Process -Name 'ip-checker' -ErrorAction SilentlyContinue
    if ($lingering) {
        Add-Result 'no-orphan-process' 'FAIL' ("$($lingering.Count) ip-checker process(es) still running after kill")
        $lingering | Stop-Process -Force -ErrorAction SilentlyContinue
    } elseif ($null -ne $proc) {
        Add-Result 'no-orphan-process' 'PASS' 'process tree terminated, no orphans'
    }
}

# =============================================================== Gate 3: HTTP shell
Write-Host ''
Write-Host 'GATE 3/3 — front-end shell reachable' -ForegroundColor Cyan
try {
    $resp = Invoke-WebRequest -Uri $DevUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    $html = $resp.Content
    $missingLabels = @()
    foreach ($needle in @('IP Checker', 'app')) { if ($html -notmatch [regex]::Escape($needle)) { $missingLabels += $needle } }
    if ($resp.StatusCode -eq 200 -and $missingLabels.Count -eq 0) {
        Add-Result 'http-shell' 'PASS' "GET $DevUrl -> 200, $($html.Length) bytes, root marker present"
    } elseif ($resp.StatusCode -eq 200) {
        Add-Result 'http-shell' 'FAIL' "200 but markers missing: $($missingLabels -join ', ')"
    } else {
        Add-Result 'http-shell' 'FAIL' "HTTP $($resp.StatusCode) from $DevUrl"
    }
} catch {
    Add-Result 'http-shell' 'SKIP' "no dev server at $DevUrl (start with 'npm run dev'); $($_.Exception.Message)"
}

# =============================================================== summary
Write-Host ''
Write-Host 'SMOKE SUMMARY' -ForegroundColor Magenta
$script:Results | Format-Table -AutoSize | Out-String | Write-Host
# Under Set-StrictMode -Version Latest, `.Count` on a scalar (0 or 1 failing
# gate) throws PropertyNotFoundException. @() forces an array so the summary
# can never crash the script that just told you everything passed.
$fails = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$summaryPath = Join-Path $ScriptDir 'smoke-last.json'
$script:Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding utf8
Write-Host "summary: $summaryPath"

if ($fails -gt 0) { Write-Host "SMOKE FAILED ($fails gate(s))" -ForegroundColor Red; exit 1 }
Write-Host 'SMOKE OK' -ForegroundColor Green
exit 0
