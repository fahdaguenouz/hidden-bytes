<#
.SYNOPSIS
    Scan a generated artifact with Microsoft Defender and record the verdict.

.DESCRIPTION
    This is the measurement half of audit item 7 ("bypasses Windows
    Defender"). It scans a file you generated yourself with the real Defender
    engine that is installed in the VM, and reports the verdict.

    Two scan modes are used, because they answer different questions:

      Custom scan   — a full on-demand scan of the file. This is the verdict
                      you report.
      MpCmdRun      — the command-line scanner, useful for a quick check.

    It does not modify any Defender setting. In particular it does NOT add an
    exclusion, and it does NOT disable real-time protection: a file that is
    excluded locally would not be detected locally, and the audit wants an
    honest result.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lab\defender_scan.ps1 `
        -Path .\evaded_program.exe
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Continue'

$fullPath = (Resolve-Path -Path $Path -ErrorAction SilentlyContinue)

if ($fullPath -eq $null) {
    Write-Output "[ERROR] No such file: $Path"
    exit 1
}

$fullPath = $fullPath.Path
$item = Get-Item $fullPath

Write-Output "=== Microsoft Defender scan ==="
Write-Output "File        : $fullPath"
Write-Output "Size        : $($item.Length) bytes"
Write-Output "SHA-256     : $((Get-FileHash $fullPath -Algorithm SHA256).Hash)"
Write-Output "Scanned at  : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Output ""

# Record the detections that existed before the scan, so a new detection can
# be attributed to this file rather than to an earlier one.
$before = @()
try {
    $before = @(Get-MpThreatDetection | Select-Object -ExpandProperty ThreatName -ErrorAction Stop)
} catch {
    Write-Output "[INFO] No prior detection history available."
}

Write-Output "[INFO] Running a Defender custom scan (this can take a while)..."

try {
    Start-MpScan -ScanType CustomScan -ScanPath $fullPath -ErrorAction Stop
} catch {
    Write-Output "[ERROR] Start-MpScan failed: $($_.Exception.Message)"
    Write-Output "[INFO] Falling back to MpCmdRun."
}

# MpCmdRun returns 0 for clean, 2 for a detection.
$mpcmd = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
$mpcmd = Get-ChildItem -Path $mpcmd -ErrorAction SilentlyContinue | Select-Object -First 1

if ($mpcmd -ne $null) {
    $output = & $mpcmd.FullName -Scan -ScanType 3 -File $fullPath -DisableRemediation 2>&1 | Out-String
    $code = $LASTEXITCODE

    Write-Output ""
    Write-Output "=== MpCmdRun result (exit code $code) ==="
    Write-Output $output.Trim()

    Write-Output ""
    if ($code -eq 2) {
        Write-Output "  RESULT: DETECTED — Defender flagged this file."
    } elseif ($code -eq 0) {
        Write-Output "  RESULT: NOT DETECTED — Defender did not flag this file."
    } else {
        Write-Output "  RESULT: INCONCLUSIVE — check the output above."
    }
}

# The authoritative answer is the detection history.
Write-Output ""
Write-Output "=== Detection history ==="

$after = @()
try {
    $after = @(Get-MpThreatDetection | Select-Object -ExpandProperty ThreatName -ErrorAction Stop)
} catch {
    Write-Output "  (could not read the detection history)"
}

$new = $after | Where-Object { $before -notcontains $_ }

if ($new.Count -gt 0) {
    Write-Output "  New detections since this scan:"
    $new | ForEach-Object { Write-Output "    - $_" }
    Write-Output ""
    Write-Output "  RESULT: DETECTED — Defender flagged this file."
    Write-Output "  Record the threat name above as your evidence."
    exit 1
}

Write-Output "  No new detections."
Write-Output ""
Write-Output "  RESULT: NOT DETECTED — Defender did not flag this file."
Write-Output ""
Write-Output "  Note the scope of this result: a clean local scan means the"
Write-Output "  file did not match a signature and did not trip a local"
Write-Output "  heuristic. It is not a guarantee about other engines, and it"
Write-Output "  is not a bypass claim. Record it exactly as measured."
exit 0
