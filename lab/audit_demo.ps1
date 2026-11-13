<#
.SYNOPSIS
    One-shot evasion demonstration for the audit.

.DESCRIPTION
    Shows, with Windows Defender, that a file carrying a known malware
    signature (EICAR) is detected in the clear but invisible once it has been
    encrypted with this project's `evasion` tool. No Defender setting is
    changed and no real malware is used.

    Everything is generated from source at run time -- no binary / .pyz needs
    to be committed to the repository. Run it from the repo root:

        powershell -ExecutionPolicy Bypass -File lab\audit_demo.ps1

    Optionally point it at a specific interpreter:

        powershell -ExecutionPolicy Bypass -File lab\audit_demo.ps1 -PythonExe py
#>

param(
    [string]$PythonExe = "py"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)   # repo root

# --- resolve interpreter -------------------------------------------------
$py = (Get-Command $PythonExe -ErrorAction SilentlyContinue).Source
if (-not $py) {
    $py = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
}
if (-not (Test-Path $py)) {
    Write-Output "[ERROR] No Python interpreter found. Edit -PythonExe."
    exit 1
}
$mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"

function Scan($path) {
    & $mp -Scan -ScanType 3 -File ((Resolve-Path $path).Path)
}

Write-Output "Interpreter : $py"
Write-Output "Defender    : $mp"
Write-Output ""

# --- STEP 1: plaintext signature IS detected -----------------------------
Write-Output "########## STEP 1  plaintext EICAR -> EXPECT: detected ##########"
& $py lab\detect_positive_control.py --out lab\eicar_test.com | Out-Null
Scan lab\eicar_test.com
Write-Output ""

# --- STEP 2: encrypt the SAME payload with the tool ----------------------
Write-Output "########## STEP 2  encrypt with the evasion tool ##########"
& $py lab\build_eicar_evaded.py
Write-Output ""

# --- STEP 3: encrypted artifact is NOT detected --------------------------
Write-Output "########## STEP 3  encrypted artifact -> EXPECT: no threats ##########"
Scan lab\eicar_evaded.pyz
Write-Output ""

# --- STEP 4: decrypt -> payload is real malware again --------------------
Write-Output "########## STEP 4  decrypt -> EXPECT: detected & deleted ##########"
& $py -m src.evasion --decrypt lab\eicar_evaded.pyz --output lab\out.com --no-delay
Start-Sleep -Seconds 3
if (Test-Path lab\out.com) {
    Write-Output "[info] out.com still present; forcing an on-demand scan:"
    Scan lab\out.com
} else {
    Write-Output "[info] out.com was removed by real-time protection (detection)."
}
Write-Output ""

# --- the evidence: Defender's own threat log -----------------------------
Write-Output "########## Defender threat log (most recent 3) ##########"
# ThreatName lives in Get-MpThreat, keyed by ThreatID; build a lookup.
$names = @{}
foreach ($t in (Get-MpThreat -ErrorAction SilentlyContinue)) { $names[$t.ThreatID] = $t.ThreatName }
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
    Select-Object -First 3 `
        @{n='Time';e={$_.InitialDetectionTime}}, `
        @{n='Threat';e={$names[$_.ThreatID]}}, `
        @{n='File';e={($_.Resources -join '; ')}} | Format-List

Write-Output "Done. Summary: encrypted = clean, plaintext/decrypted = detected -> encryption is the only variable."
