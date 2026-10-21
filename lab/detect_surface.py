#!/usr/bin/env python3
"""Static analysis of what a scanner can see in a generated artifact.

This tool answers the question "what would an antivirus or a multi-scanner
service actually find in this file?" without uploading anything anywhere. It
reports the properties that drive scanner verdicts, so you can fix the
artifact locally instead of discovering the problem after uploading it.

It reports:

- the real file type (a file named `.exe` is not necessarily a PE),
- the PE structure, when there is one,
- section entropy, which is the main heuristic signal for "packed/encrypted",
- the size of the largest high-entropy region, which is what overlay
  heuristics look for,
- strings that a scanner's signature database could match on,
- whether the payload appears in cleartext.

Nothing is executed and nothing is uploaded. The file is only read.

Usage:

    python3 lab/detect_surface.py evaded_program.exe
    python3 lab/detect_surface.py --json evaded_program.exe
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

# Strings that appear in this project's own artifacts and are worth checking
# for, because their presence or absence changes a scanner's view.
INTERESTING_MARKERS = (
    b"HBX1",
    b"HBXP",
    b"HBX-RUNNER-V1",
    b"reverse_shell",
    b"cmd.exe",
    b"powershell",
    b"/bin/sh",
    b"/bin/bash",
    b"subprocess",
    b"os.system",
    b"socket",
    b"dup2",
    b"connect",
    b"shebang",
    b"import ",
    b"payload",
    b"passphrase",
    b"decrypt",
    b"encrypt",
)

# Extensions that identify a Python source file rather than a program.
SCRIPT_MARKERS = (b"#!/usr/bin/env python", b"#!/usr/bin/python", b"import ")

# A PE file starts with the DOS "MZ" signature.
DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"
ZIP_MAGIC = b"PK\x03\x04"


def entropy(data: bytes) -> float:
    """Return the Shannon entropy of a byte string, in bits per byte."""

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def file_type(path: Path) -> dict:
    """Identify what the file actually is, not what it is called."""

    with path.open("rb") as handle:
        head = handle.read(4096)

    result = {
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "extension": path.suffix.lower(),
        "is_pe": False,
        "is_zip": head[:4] == ZIP_MAGIC,
        "is_script": any(head.startswith(marker) for marker in SCRIPT_MARKERS),
        "pe_machine": None,
        "pe_sections": 0,
    }

    if head[:2] == DOS_MAGIC:
        result["is_pe"] = True
        try:
            import pefile

            pe = pefile.PE(str(path))
            result["pe_machine"] = pe.FILE_HEADER.Machine
            result["pe_sections"] = pe.FILE_HEADER.NumberOfSections
            result["pe_is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            pe.close()
        except Exception:  # noqa: BLE001 - report what we can
            result["pe_machine"] = None

    return result


def section_entropy(path: Path) -> list[dict]:
    """Return the entropy of each PE section, when the file is a PE."""

    if not file_type(path)["is_pe"]:
        return []

    import pefile

    sections = []
    pe = pefile.PE(str(path))
    try:
        for section in pe.sections:
            data = section.get_data()
            sections.append(
                {
                    "name": section.Name.rstrip(b"\x00").decode(
                        "ascii", errors="replace"
                    ),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(entropy(data), 4),
                }
            )
    finally:
        pe.close()

    return sections


def largest_high_entropy_region(path: Path, threshold: float = 7.5) -> dict:
    """Measure the largest run of high-entropy bytes in the file.

    This is the number that overlay heuristics care about: a small code
    section followed by a very large high-entropy blob is the classic
    "encrypted or packed payload" shape.
    """

    block = 64 * 1024
    largest = 0
    current = 0
    total = 0
    blocks = []

    with path.open("rb") as handle:
        while True:
            data = handle.read(block)
            if not data:
                break

            total += len(data)
            blocks.append(entropy(data))

            if entropy(data) >= threshold:
                current += len(data)
                largest = max(largest, current)
            else:
                current = 0

    return {
        "file_size": total,
        "largest_high_entropy_bytes": largest,
        "largest_high_entropy_ratio": round(largest / total, 4) if total else 0.0,
        "block_entropy_min": round(min(blocks), 4) if blocks else 0.0,
        "block_entropy_max": round(max(blocks), 4) if blocks else 0.0,
        "block_entropy_mean": (
            round(sum(blocks) / len(blocks), 4) if blocks else 0.0
        ),
    }


def string_hits(path: Path) -> dict:
    """Report which notable byte sequences are present in the file."""

    data = path.read_bytes()

    hits = {marker.decode("ascii"): (marker in data) for marker in INTERESTING_MARKERS}

    # Printable ASCII runs of 8 or more characters, the way a scanner's
    # string extractor would find them.
    printable = re.findall(rb"[\x20-\x7e]{8,}", data)
    longest = max((len(item) for item in printable), default=0)

    return {
        "markers": hits,
        "printable_string_count": len(printable),
        "longest_printable_string": longest,
    }


def analyse(path: Path) -> dict:
    """Return the full detection-surface report for a file."""

    info = file_type(path)
    info["entropy"] = round(entropy(path.read_bytes()), 4)
    info["regions"] = largest_high_entropy_region(path)
    info["sections"] = section_entropy(path)
    info["strings"] = string_hits(path)

    findings = []

    if info["extension"] in (".exe", ".dll") and not info["is_pe"]:
        findings.append(
            "The file is named .exe but is not a PE executable. "
            "A Windows scanner will not analyse it as a program."
        )

    if info["is_script"]:
        findings.append(
            "The file is a Python script, not a compiled program. "
            "A multi-scanner service may classify it by its text content."
        )

    if info["regions"]["largest_high_entropy_ratio"] > 0.5:
        findings.append(
            "Most of the file is one high-entropy region "
            f"({info['regions']['largest_high_entropy_ratio'] * 100:.1f}%). "
            "Overlay heuristics flag this shape as packed or encrypted."
        )

    if info["strings"]["markers"].get("HBX1"):
        findings.append(
            "The container magic 'HBX1' is visible in the file. "
            "It identifies the format to anyone who looks."
        )

    info["findings"] = findings

    return info


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect_surface",
        description=(
            "Report what a scanner can see in a generated artifact, without "
            "uploading it anywhere."
        ),
    )
    parser.add_argument("file", type=Path, help="the artifact to analyse")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.file.is_file():
        print(f"[ERROR] No such file: {args.file}", file=sys.stderr)
        return 1

    report = analyse(args.file)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"=== {report['name']} ===")
    print(f"  size            : {report['size_bytes']:,} bytes")
    print("  file type       : ", end="")
    kinds = []
    if report["is_pe"]:
        kinds.append(f"PE (machine 0x{report['pe_machine']:04x})")
    if report["is_zip"]:
        kinds.append("zip archive")
    if report["is_script"]:
        kinds.append("script")
    print(", ".join(kinds) if kinds else "unknown")
    print(f"  overall entropy : {report['entropy']} bits/byte")

    regions = report["regions"]
    print(
        f"  largest entropy region: {regions['largest_high_entropy_bytes']:,} bytes "
        f"({regions['largest_high_entropy_ratio'] * 100:.1f}% of the file)"
    )

    for section in report["sections"]:
        print(
            f"    section {section['name']:<10} "
            f"entropy {section['entropy']:.4f}  "
            f"raw {section['raw_size']:,}"
        )

    print("  markers:")
    for name, present in report["strings"]["markers"].items():
        if present:
            print(f"    + {name}")

    if report["findings"]:
        print("  findings:")
        for finding in report["findings"]:
            print(f"    ! {finding}")
    else:
        print("  findings: none")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
