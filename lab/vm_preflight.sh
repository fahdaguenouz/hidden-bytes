#!/usr/bin/env bash
#
# Hidden-Bytes — Windows VM preflight check.
#
# Run this INSIDE the isolated Windows VM before the audit demonstration. It
# checks the things the audit asks the auditor to verify, and prints a
# report you can save as evidence.
#
# It is read-only: it inspects the environment and reports. It does not
# change any setting, and it never touches a network service.
#
# Usage (in the Windows VM, from the repository root):
#
#     bash lab/vm_preflight.sh
#     bash lab/vm_preflight.sh > audit/vm-preflight.txt
#
# On Windows, run it from Git Bash or WSL. A PowerShell equivalent for the
# few Windows-specific checks is included in lab/vm_preflight.ps1.

set -u

PASS=0
WARN=0
FAIL=0

pass() { printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
warn() { printf '  [WARN] %s\n' "$1"; WARN=$((WARN + 1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

section() { printf '\n== %s ==\n' "$1"; }

printf 'Hidden-Bytes — VM preflight report\n'
printf 'Generated: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf 'Host: %s\n' "$(uname -a 2>/dev/null || echo 'unknown')"

# ---------------------------------------------------------------------------
section "1. Operating system"
# ---------------------------------------------------------------------------

if grep -qi "microsoft" /proc/version 2>/dev/null || [ -n "${WSL_DISTRO_NAME:-}" ]; then
    printf '  Environment: WSL / Linux compatibility layer on Windows\n'
    printf '  NOTE: the audit expects the tools to run in the Windows VM itself.\n'
    printf '        WSL is acceptable for building, but the demonstration\n'
    printf '        should be run from a native Windows shell.\n'
    warn "Running under WSL rather than a native Windows shell"
elif [ -n "${OS:-}" ]; then
    pass "Running on a native Windows environment"
else
    printf '  Environment: Linux (not the audit VM)\n'
    warn "This does not look like the Windows VM — run the preflight there"
fi

if command -v cmd.exe >/dev/null 2>&1; then
    VERSION=$(cmd.exe /c ver 2>/dev/null | tr -d '\r')
    printf '  Windows version: %s\n' "$VERSION"
    if printf '%s' "$VERSION" | grep -qiE "10\.0|11\.0"; then
        pass "Windows 10 or 11 detected"
    else
        fail "Windows 10/11 required by the subject"
    fi
fi

# ---------------------------------------------------------------------------
section "2. Network isolation"
# ---------------------------------------------------------------------------

# The subject requires Host-Only or Internal networking. Those modes have no
# route to the internet, so the absence of a default gateway and the
# absence of outbound connectivity are the observable signs.
DEFAULT_ROUTE=$(ip route show default 2>/dev/null | head -1)

if [ -z "$DEFAULT_ROUTE" ]; then
    pass "No default route — the VM has no direct path to the internet"
else
    printf '  Default route: %s\n' "$DEFAULT_ROUTE"
    if printf '%s' "$DEFAULT_ROUTE" | grep -qE '192\.168\.56\.|10\.0\.2\.'; then
        pass "Default route is a VirtualBox host-only / NAT gateway address"
    else
        warn "A default route exists — confirm the adapter is Host-Only, not NAT"
    fi
fi

# Name resolution and outbound HTTPS to a public host must both fail.
if command -v getent >/dev/null 2>&1; then
    if getent hosts example.com >/dev/null 2>&1; then
        fail "Public DNS resolution works — the VM is not isolated"
    else
        pass "Public DNS resolution fails"
    fi
fi

if command -v curl >/dev/null 2>&1; then
    if curl -sS --max-time 8 -o /dev/null https://example.com 2>/dev/null; then
        fail "Outbound HTTPS works — the VM is not isolated"
    else
        pass "Outbound HTTPS is blocked"
    fi
fi

# ---------------------------------------------------------------------------
section "3. Python toolchain"
# ---------------------------------------------------------------------------

PYTHON=""
for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -n "$PYTHON" ]; then
    PYVER=$("$PYTHON" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)
    printf '  Interpreter: %s (%s)\n' "$PYTHON" "$PYVER"
    if "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
        pass "Python 3.10 or newer"
    else
        fail "Python 3.10 or newer is required"
    fi

    if "$PYTHON" -c 'import cryptography' 2>/dev/null; then
        pass "cryptography is installed"
    else
        fail "cryptography is missing — run: pip install -r requirements-dev.txt"
    fi

    if "$PYTHON" -c 'import PyInstaller' 2>/dev/null; then
        pass "PyInstaller is installed (needed for --build-exe)"
    else
        warn "PyInstaller is missing — --build-exe will not work here"
    fi
else
    fail "No Python interpreter found"
fi

if [ -f "hidden_bytes/evasion/cli.py" ] && [ -f "hidden_bytes/polymorphic.py" ]; then
    pass "Repository layout looks correct"
else
    fail "Run this from the repository root"
fi

# ---------------------------------------------------------------------------
section "4. Tool smoke test"
# ---------------------------------------------------------------------------

if [ -n "$PYTHON" ]; then
    if "$PYTHON" -m hidden_bytes.evasion --help >/dev/null 2>&1; then
        pass "evasion CLI starts"
    else
        fail "evasion CLI does not start"
    fi

    if "$PYTHON" -m hidden_bytes.polymorphic --help >/dev/null 2>&1; then
        pass "polymorphic CLI starts"
    else
        fail "polymorphic CLI does not start"
    fi

    if "$PYTHON" -m pytest --collect-only -q >/dev/null 2>&1; then
        pass "test suite is collectable"
    else
        warn "pytest could not collect the test suite"
    fi
fi

# ---------------------------------------------------------------------------
section "5. Defender status (Windows-specific)"
# ---------------------------------------------------------------------------

if command -v powershell.exe >/dev/null 2>&1; then
    POWERSHELL_STATUS=$(powershell.exe -NoProfile -Command \
        "try { \$s = Get-MpComputerStatus; Write-Output \$s.RealTimeProtectionEnabled } catch { Write-Output 'unknown' }" 2>/dev/null | tr -d '\r' | tail -1)

    printf '  Real-time protection: %s\n' "${POWERSHELL_STATUS:-unknown}"

    if [ "${POWERSHELL_STATUS:-}" = "True" ]; then
        pass "Defender real-time protection is enabled"
    elif [ "${POWERSHELL_STATUS:-}" = "False" ]; then
        fail "Defender real-time protection is DISABLED — the audit expects it enabled"
    else
        warn "Could not read the Defender status"
    fi

    # The exclusion list matters: a detection that is excluded locally will
    # not appear in the local scan, and the audit wants an honest result.
    POWERSHELL_EXCL=$(powershell.exe -NoProfile -Command \
        "try { (Get-MpPreference).ExclusionPath } catch { Write-Output '' }" 2>/dev/null | tr -d '\r' | grep -v '^$' | head -5)

    if [ -n "$POWERSHELL_EXCL" ]; then
        printf '  Defender exclusions:\n'
        printf '%s\n' "$POWERSHELL_EXCL" | sed 's/^/    /'
        warn "Defender exclusions are configured — confirm they do not cover the demo folder"
    else
        pass "No Defender path exclusions"
    fi
else
    warn "PowerShell not reachable — run lab/vm_preflight.ps1 in the Windows VM"
fi

# ---------------------------------------------------------------------------
section "6. Summary"
# ---------------------------------------------------------------------------

printf '  PASS: %d   WARN: %d   FAIL: %d\n' "$PASS" "$WARN" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    printf '\n  Result: NOT READY — fix the FAIL items before the demonstration.\n'
    exit 1
fi

if [ "$WARN" -gt 0 ]; then
    printf '\n  Result: READY WITH WARNINGS — review each warning with the auditor.\n'
    exit 0
fi

printf '\n  Result: READY\n'
exit 0
