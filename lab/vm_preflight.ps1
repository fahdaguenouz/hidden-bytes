<#
.SYNOPSIS
    Hidden-Bytes — Windows VM preflight check.

.DESCRIPTION
    Run this inside the isolated Windows VM before the audit demonstration.
    It inspects the environment and reports; it changes no settings and
    contacts no network service.

    Save the output as audit evidence:

        powershell -ExecutionPolicy Bypass -File lab\vm_preflight.ps1 |
            Tee-Object -FilePath audit\vm-preflight.txt

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File lab\vm_preflight.ps1
#>

$ErrorActionPreference = 'Continue'

$script:Pass = 0
$script:Warn = 0
$script:Fail = 0

function Write-Section {
    param([string]$Title)
    Write-Output ""
    Write-Output "== $Title =="
}

function Add-Pass {
    param([string]$Message)
    Write-Output "  [PASS] $Message"
    $script:Pass++
}

function Add-Warn {
    param([string]$Message)
    Write-Output "  [WARN] $Message"
    $script:Warn++
}

function Add-Fail {
    param([string]$Message)
    Write-Output "  [FAIL] $Message"
    $script:Fail++
}

Write-Output "Hidden-Bytes — Windows VM preflight report"
Write-Output "Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Output "Computer: $env:COMPUTERNAME"

# ---------------------------------------------------------------------------
Write-Section "1. Operating system"
# ---------------------------------------------------------------------------

$os = Get-CimInstance Win32_OperatingSystem
Write-Output "  Product: $($os.Caption)"
Write-Output "  Version: $($os.Version) (build $($os.BuildNumber))"
Write-Output "  Architecture: $($os.OSArchitecture)"

if ($os.Caption -match 'Windows 10|Windows 11') {
    Add-Pass "Windows 10 or 11 detected"
} else {
    Add-Fail "Windows 10/11 is required by the subject"
}

if ($os.Version -ne $null) {
    $build = [int]$os.BuildNumber
    if ($build -ge 19041) {
        Add-Pass "Build $build is a supported Windows 10/11 baseline"
    } else {
        Add-Warn "Build $build is older than the usual Windows 10 baseline"
    }
}

# ---------------------------------------------------------------------------
Write-Section "2. Network isolation"
# ---------------------------------------------------------------------------

Write-Output "  Active adapters:"
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    Write-Output "    $($_.Name) ($($_.InterfaceDescription))"
}

$adapters = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' }

foreach ($config in $adapters) {
    $ipv4 = $config.IPv4Address | Select-Object -First 1
    if ($ipv4 -eq $null) { continue }

    Write-Output "  Adapter '$($config.InterfaceAlias)' has address $($ipv4.IPAddress)"

    $gateway = $config.IPv4DefaultGateway | Select-Object -First 1
    if ($gateway -eq $null) {
        Add-Pass "Adapter '$($config.InterfaceAlias)' has no default gateway (Host-Only / Internal style)"
    } else {
        Write-Output "    default gateway: $($gateway.NextHop)"
        if ($gateway.NextHop -eq '10.0.2.2' -or $gateway.NextHop -eq '192.168.56.1') {
            Add-Warn "Gateway $($gateway.NextHop) looks like a VirtualBox NAT/host-only gateway — confirm the adapter mode"
        } else {
            Add-Warn "Adapter '$($config.InterfaceAlias)' has a default gateway — confirm it is not NAT or Bridged"
        }
    }
}

# An isolated VM must not resolve or reach public names.
try {
    $resolved = Resolve-DnsName -Name example.com -ErrorAction Stop
    Add-Fail "Public DNS resolution works — the VM is not isolated"
} catch {
    Add-Pass "Public DNS resolution fails"
}

try {
    $response = Invoke-WebRequest -Uri 'https://example.com' -TimeoutSec 8 -ErrorAction Stop
    Add-Fail "Outbound HTTPS works — the VM is not isolated"
} catch {
    Add-Pass "Outbound HTTPS is blocked"
}

# ---------------------------------------------------------------------------
Write-Section "3. Defender status"
# ---------------------------------------------------------------------------

try {
    $mp = Get-MpComputerStatus

    Write-Output "  Real-time protection enabled : $($mp.RealTimeProtectionEnabled)"
    Write-Output "  Antivirus enabled            : $($mp.AntivirusEnabled)"
    Write-Output "  Signature age (days)         : $($mp.AntivirusSignatureAge)"
    Write-Output "  Signature updated            : $($mp.AntivirusSignatureLastUpdated)"

    if ($mp.RealTimeProtectionEnabled) {
        Add-Pass "Defender real-time protection is enabled"
    } else {
        Add-Fail "Defender real-time protection is DISABLED — the audit expects it enabled"
    }

    if ($mp.AntivirusEnabled) {
        Add-Pass "Defender antivirus is enabled"
    } else {
        Add-Fail "Defender antivirus is disabled"
    }

    if ($mp.AntivirusSignatureAge -le 2) {
        Add-Pass "Signatures are current"
    } else {
        Add-Warn "Signatures are $($mp.AntivirusSignatureAge) days old — update before the demo"
    }
} catch {
    Add-Warn "Could not read the Defender status: $($_.Exception.Message)"
}

try {
    $preference = Get-MpPreference
    $exclusions = @()
    $exclusions += $preference.ExclusionPath
    $exclusions += $preference.ExclusionProcess
    $exclusions += $preference.ExclusionExtension
    $exclusions = $exclusions | Where-Object { $_ -ne $null -and $_ -ne '' } | Select-Object -Unique

    if ($exclusions.Count -gt 0) {
        Write-Output "  Defender exclusions:"
        $exclusions | ForEach-Object { Write-Output "    $_" }
        Add-Warn "Defender exclusions are configured — confirm they do not cover the demo folder"
    } else {
        Add-Pass "No Defender exclusions are configured"
    }
} catch {
    Add-Warn "Could not read the Defender exclusion list"
}

Write-Output ""
Write-Output "  Recent Defender detections (last 5):"
try {
    $detections = Get-MpThreatDetection | Select-Object -First 5
    if ($detections -eq $null -or $detections.Count -eq 0) {
        Write-Output "    (none)"
        Add-Pass "No prior detections on this VM"
    } else {
        $detections | ForEach-Object {
            Write-Output "    $($_.InitialDetectionTime)  $($_.ThreatName)"
        }
        Add-Warn "Prior detections exist — the auditor may ask about them"
    }
} catch {
    Write-Output "    (could not read)"
}

# ---------------------------------------------------------------------------
Write-Section "4. Python toolchain"
# ---------------------------------------------------------------------------

$python = Get-Command python, python3, py -ErrorAction SilentlyContinue | Select-Object -First 1

if ($python -eq $null) {
    Add-Fail "No Python interpreter found — install Python 3.10+ in the VM"
} else {
    Write-Output "  Interpreter: $($python.Source)"
    $version = & $python.Source --version 2>&1
    Write-Output "  Version: $version"

    & $python.Source -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
    if ($LASTEXITCODE -eq 0) {
        Add-Pass "Python 3.10 or newer"
    } else {
        Add-Fail "Python 3.10 or newer is required"
    }

    & $python.Source -c "import cryptography" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Add-Pass "cryptography is installed"
    } else {
        Add-Fail "cryptography is missing — run: pip install -r requirements-dev.txt"
    }

    & $python.Source -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Add-Pass "PyInstaller is installed (needed for --build-exe)"
    } else {
        Add-Warn "PyInstaller is missing — run: pip install pyinstaller"
    }
}

# ---------------------------------------------------------------------------
Write-Section "5. Tool smoke test"
# ---------------------------------------------------------------------------

if ($python -ne $null -and (Test-Path 'hidden_bytes/evasion/cli.py')) {
    & $python.Source -m hidden_bytes.evasion --help *> $null
    if ($LASTEXITCODE -eq 0) { Add-Pass "evasion CLI starts" } else { Add-Fail "evasion CLI does not start" }

    & $python.Source -m hidden_bytes.polymorphic --help *> $null
    if ($LASTEXITCODE -eq 0) { Add-Pass "polymorphic CLI starts" } else { Add-Fail "polymorphic CLI does not start" }
}

# ---------------------------------------------------------------------------
Write-Section "6. Summary"
# ---------------------------------------------------------------------------

Write-Output "  PASS: $script:Pass   WARN: $script:Warn   FAIL: $script:Fail"

if ($script:Fail -gt 0) {
    Write-Output ""
    Write-Output "  Result: NOT READY — fix the FAIL items before the demonstration."
    exit 1
}

if ($script:Warn -gt 0) {
    Write-Output ""
    Write-Output "  Result: READY WITH WARNINGS — review each warning with the auditor."
    exit 0
}

Write-Output ""
Write-Output "  Result: READY"
exit 0
