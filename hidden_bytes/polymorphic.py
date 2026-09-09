"""Generator for a harmless, visibly self-modifying demonstration program."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import sys


MAX_PAYLOAD = 4096
BLOCKED = re.compile(
    r"(?i)(reverse[_ -]?shell|cmd\.exe|powershell|/bin/(?:ba)?sh|socket\s*\(|"
    r"subprocess|os\.system|connect\s*\(|netcat|\bnc\s+-|curl\s|wget\s)"
)


TEMPLATE = '''#!/usr/bin/env python3
"""Generated safe polymorphism demonstration; contains no network or shell code."""
from pathlib import Path
import hashlib
import secrets

POLYMORPHIC_NONCE = "{nonce}"
PAYLOAD = {payload!r}
PAYLOAD_SHA256 = "{digest}"

def rotate_signature():
    path = Path(__file__)
    source = path.read_text(encoding="utf-8")
    old = 'POLYMORPHIC_NONCE = "' + POLYMORPHIC_NONCE + '"'
    new = 'POLYMORPHIC_NONCE = "' + secrets.token_hex(24) + '"'
    path.write_text(source.replace(old, new, 1), encoding="utf-8")

if __name__ == "__main__":
    if hashlib.sha256(PAYLOAD.encode("utf-8")).hexdigest() != PAYLOAD_SHA256:
        raise SystemExit("payload integrity check failed")
    print("[INFO] Safe polymorphic signature updated successfully.")
    print(PAYLOAD)
    rotate_signature()
'''


def _load_payload(value: str) -> str:
    candidate = Path(value)
    if candidate.is_file():
        payload = candidate.read_text(encoding="utf-8")
    else:
        payload = value
    if not payload.strip():
        raise ValueError("payload must not be empty")
    if len(payload.encode("utf-8")) > MAX_PAYLOAD:
        raise ValueError(f"payload exceeds the {MAX_PAYLOAD}-byte safe demo limit")
    if BLOCKED.search(payload):
        raise ValueError("network, shell, and process-launch payloads are not permitted")
    return payload


def generate(output: Path, payload_arg: str) -> None:
    payload = _load_payload(payload_arg)
    nonce = secrets.token_hex(24)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    source = TEMPLATE.format(nonce=nonce, payload=payload, digest=digest)
    # A random inert comment makes independently generated files structurally distinct.
    source += "# variant:" + base64.b64encode(os.urandom(48)).decode("ascii") + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(source, encoding="utf-8")
    try:
        output.chmod(0o755)
    except OSError:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymorphic",
        description="Generate a harmless self-modifying local demonstration program.",
    )
    parser.add_argument("--generate", required=True, metavar="OUTPUT")
    parser.add_argument("--payload", required=True, metavar="TEXT_OR_FILE")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        generate(Path(args.generate), args.payload)
        print(f'Polymorphic demo generated successfully as "{args.generate}".')
        print("[INFO] The generated program has no network or command-execution capability.")
        return 0
    except (OSError, UnicodeError, ValueError) as error:
        print(f"polymorphic: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

