#!/usr/bin/env python3
"""Measure a generated artifact against VirusTotal and report the result.

This is the measurement half of audit items 7 and 8. It uploads the artifact
to the VirusTotal public API, waits for the scan to finish, and prints the
detection ratio the audit asks for:

    "bypasses detection by at least 60% of security vendors"

which means **at most 40% of the engines may flag the file**.

Before you upload anything, read this:

- **Only upload artifacts you created yourself.** Never upload a third-party
  binary, a confidential file, or anything from your employer. The sample is
  published to a public multi-scanner service and may be shared onward.
- The subject's example uses a file you wrote yourself ("Hello, World!"), and
  that is what you should upload.
- VirusTotal's terms of service expect you to use the API for research and
  security work, which is what this is.

Setup:

    export VT_API_KEY='your-virustotal-api-key'
    python3 lab/vt_check.py evaded_program.exe

The API key comes from your VirusTotal account page. The key is read from
the environment so it never lands in a shell history or a screenshot.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"

# The audit's threshold: the file must be missed by at least 60% of engines.
REQUIRED_BYPASS = 60.0

# How long to wait for the multi-scanner analysis to complete.
MAX_WAIT_SECONDS = 600
POLL_INTERVAL = 15


def api_key() -> str:
    """Read the VirusTotal API key from the environment."""

    key = os.environ.get("VT_API_KEY", "").strip()

    if not key:
        raise ValueError(
            "VT_API_KEY is not set. Create an API key in your VirusTotal "
            "account and export it: export VT_API_KEY='...'"
        )

    return key


def upload(path: Path, key: str) -> str:
    """Upload a file and return the analysis id."""

    import urllib.request

    url = f"{VIRUSTOTAL_API}/files"

    with path.open("rb") as handle:
        data = handle.read()

    request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"x-apikey": key},
    )

    with urllib.request.urlopen(request, timeout=300) as response:
        payload = json.loads(response.read().decode("utf-8"))

    return payload["data"]["id"]


def get_analysis(analysis_id: str, key: str) -> dict:
    """Fetch the analysis result for an uploaded file."""

    import urllib.request

    url = f"{VIRUSTOTAL_API}/analyses/{analysis_id}"

    request = urllib.request.Request(url, headers={"x-apikey": key})

    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def summarise(analysis: dict) -> dict:
    """Turn the raw analysis into the numbers the audit cares about."""

    stats = analysis.get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected

    if total == 0:
        return {"total": 0}

    # "Bypasses" counts everything that did not flag it as malicious.
    bypassed = total - malicious

    return {
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "detection_ratio_percent": round(malicious / total * 100, 2),
        "bypass_percent": round(bypassed / total * 100, 2),
        "meets_requirement": (bypassed / total * 100) >= REQUIRED_BYPASS,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vt_check",
        description=(
            "Upload a self-authored artifact to VirusTotal and report the "
            "detection ratio the audit asks for."
        ),
    )
    parser.add_argument("file", type=Path, help="the artifact to submit")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the raw summary as JSON",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=MAX_WAIT_SECONDS,
        help="seconds to wait for the analysis (default: 600)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.file.is_file():
        print(f"[ERROR] No such file: {args.file}", file=sys.stderr)
        return 1

    try:
        key = api_key()
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(f"[INFO] Uploading {args.file} ({args.file.stat().st_size:,} bytes)")

    try:
        analysis_id = upload(args.file, key)
    except Exception as exc:  # noqa: BLE001 - report and stop
        print(f"[ERROR] Upload failed: {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] Analysis id: {analysis_id}")
    print("[INFO] Waiting for the multi-scanner analysis to complete...")

    deadline = time.monotonic() + args.timeout
    analysis = None

    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)

        try:
            analysis = get_analysis(analysis_id, key)
        except Exception as exc:  # noqa: BLE001 - keep polling
            print(f"[WARN] Could not fetch the result yet: {exc}")
            continue

        status = analysis.get("status", "unknown")
        print(f"[INFO] Status: {status}")

        if status == "completed":
            break
    else:
        print("[ERROR] Timed out waiting for the analysis.", file=sys.stderr)
        return 1

    summary = summarise(analysis)

    if not summary.get("total"):
        print("[ERROR] The analysis returned no engine results.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    print("")
    print("=== VirusTotal result ===")
    print(f"  engines reporting : {summary['total']}")
    print(f"  malicious         : {summary['malicious']}")
    print(f"  suspicious        : {summary['suspicious']}")
    print(f"  undetected        : {summary['undetected']}")
    print(f"  harmless          : {summary['harmless']}")
    print(f"  detection ratio   : {summary['detection_ratio_percent']}%")
    print(f"  bypass rate       : {summary['bypass_percent']}%")
    print(f"  required bypass   : {REQUIRED_BYPASS}%")

    if summary["meets_requirement"]:
        print("")
        print("  RESULT: PASS — the file is missed by at least 60% of engines.")
        return 0

    print("")
    print(
        f"  RESULT: FAIL — only {summary['bypass_percent']}% of engines missed "
        f"the file; {REQUIRED_BYPASS}% is required."
    )
    print("  Record this result honestly. Do not report a number you did not")
    print("  observe. See README section 10 for what the detection depends on.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
