"""Audit helper: encrypt the EICAR test payload with the evasion tool.

WHY THIS EXISTS
---------------
EICAR is a harmless file that every antivirus detects on purpose. Windows
Defender's real-time filter quarantines it the instant it is written to disk,
so you cannot feed a plaintext EICAR file through the normal

    python -m src.evasion --encrypt <file> ...

command: Defender removes the input before the tool can read it. That failure
is itself proof that Defender detects the raw payload.

To encrypt it anyway WITHOUT disabling Defender, this script keeps the EICAR
bytes in memory and hands the tool an in-memory stand-in for the input file.
No plaintext is ever written to disk, and no Defender setting is changed.

USAGE
-----
    python lab/build_eicar_evaded.py                 # -> lab/eicar_evaded.pyz
    python lab/build_eicar_evaded.py --exe           # -> lab/eicar_evaded.exe
    python lab/build_eicar_evaded.py --out X --delay 30 --add-size 0.2

The produced artifact recovers to the real EICAR payload, so Defender detects
it again once it is decrypted or run -- demonstrating that the encryption, not
any change to the payload, is what hides it from the static scanner.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from src.evasion.runner import (  # noqa: E402
    build_executable_from_source,
    build_runner_file,
)

# Standard EICAR string, assembled from fragments so THIS source file is not
# itself a literal signature match.
EICAR = ("".join([
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
    r"$EICAR-STANDARD-ANTIVIRUS-",
    r"TEST-FILE!$H+H*",
])).encode("ascii")


class _Stat:
    def __init__(self, size: int) -> None:
        self.st_size = size


class MemSource:
    """Minimal in-memory stand-in for the pathlib.Path the tool expects."""

    def __init__(self, data: bytes, name: str) -> None:
        self._data = data
        self.name = name

    def read_bytes(self) -> bytes:
        return self._data

    def stat(self) -> _Stat:
        return _Stat(len(self._data))


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt EICAR with the evasion tool (in-memory).")
    parser.add_argument("--exe", action="store_true",
                        help="build a native .exe (needs PyInstaller) instead of a .pyz")
    parser.add_argument("--out", type=Path, default=None,
                        help="output path (default: lab/eicar_evaded.pyz or .exe)")
    parser.add_argument("--delay", type=float, default=30.0,
                        help="runner delay in seconds (default: 30)")
    parser.add_argument("--add-size", type=float, default=None,
                        help="padding MB (default: 0.2 for .pyz, 15 for .exe)")
    args = parser.parse_args()

    if args.out is None:
        args.out = REPO / "lab" / ("eicar_evaded.exe" if args.exe else "eicar_evaded.pyz")
    if args.add_size is None:
        args.add_size = 15.0 if args.exe else 0.2

    src = MemSource(EICAR, "eicar_test.com")

    if args.exe:
        build_executable_from_source(source=src, output=args.out,
                                     add_size_mb=args.add_size, delay=args.delay)
    else:
        build_runner_file(source=src, output=args.out,
                          add_size_mb=args.add_size, delay=args.delay)

    print(f"[OK] encrypted EICAR -> {args.out} ({args.out.stat().st_size} bytes)")
    print("[*] no plaintext EICAR was ever written to disk; Defender was not changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
