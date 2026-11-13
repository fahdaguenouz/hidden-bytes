"""Positive-control program: a file Windows Defender is DESIGNED to detect.

This is the opposite of the evasion test. It uses the EICAR anti-malware test
string -- a harmless, 68-byte, industry-standard file that every AV engine
flags on purpose -- so you can confirm detection works and compare it against
an evaded build. It contains NO real malware.

Detection outcome:
  * If the written file disappears / the write is blocked -> Defender's
    real-time protection detected and quarantined it (SUCCESS: detection works).
  * If the file survives -> real-time protection did NOT act (check that it is
    enabled, or scan on demand with MpCmdRun).

Usage:
    python lab/detect_positive_control.py --out eicar_test.com
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_eicar() -> bytes:
    # Standard EICAR string, assembled from fragments so THIS source file is
    # not itself a literal signature match before it runs.
    parts = [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
        r"$EICAR-STANDARD-ANTIVIRUS-",
        r"TEST-FILE!$H+H*",
    ]
    return ("".join(parts)).encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description="Write an EICAR positive-control file.")
    parser.add_argument("--out", type=Path, default=Path("eicar_test.com"),
                        help="path to write the detectable test file to")
    args = parser.parse_args()

    data = build_eicar()
    print(f"[*] Writing EICAR positive-control file -> {args.out}", flush=True)
    try:
        args.out.write_bytes(data)
    except OSError as exc:
        print(f"[+] DETECTED: write blocked by security software: {exc}", flush=True)
        return 1

    if args.out.exists():
        print("[-] NOT detected on write: the file is still present.", flush=True)
        return 0
    print("[+] DETECTED: file quarantined immediately after write.", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
