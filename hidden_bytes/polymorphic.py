#!/usr/bin/env python3
"""
Hidden-Bytes — Safe Polymorphic Demonstration

Demonstrates:
    - Generation of structurally distinct program files
    - Randomized signatures and inert comments
    - SHA-256 payload integrity verification
    - Visible, local self-modification
    - Repeatable behavior with changing file hashes

This is a local educational demonstration. It does not implement
antivirus evasion, network communication, shell execution,
persistence, or arbitrary executable payload loading.
"""

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
NONCE_BYTES = 24
VARIANT_BYTES = 48

# Reject common shell/process/network payload indicators.
# This is a basic guardrail, NOT a security sandbox.
BLOCKED = re.compile(
    r"(?i)(reverse[_ -]?shell|cmd\.exe|powershell|"
    r"/bin/(?:ba)?sh|subprocess|os\.system|"
    r"netcat|\bnc\s+-|curl\s|wget\s)"
)


TEMPLATE = r'''#!/usr/bin/env python3
"""Generated harmless polymorphism demonstration."""
from pathlib import Path
import hashlib
import secrets

POLYMORPHIC_NONCE = "__NONCE__"
PAYLOAD = __PAYLOAD__
PAYLOAD_SHA256 = "__DIGEST__"


def rotate_signature():
    """Change this demonstration's local signature."""
    path = Path(__file__)
    source = path.read_text(encoding="utf-8")

    old = 'POLYMORPHIC_NONCE = "' + POLYMORPHIC_NONCE + '"'
    new = 'POLYMORPHIC_NONCE = "' + secrets.token_hex(24) + '"'

    if old not in source:
        raise SystemExit("could not locate signature to update")

    updated = source.replace(old, new, 1)

    # Write the modified program locally.
    path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    actual_digest = hashlib.sha256(
        PAYLOAD.encode("utf-8")
    ).hexdigest()

    if actual_digest != PAYLOAD_SHA256:
        raise SystemExit("payload integrity check failed")

    print("[INFO] Payload integrity verified.")
    print("[INFO] Harmless polymorphism demonstration.")
    print(PAYLOAD)

    rotate_signature()
    print("[INFO] Local signature updated.")

# VARIANT_MARKER
'''


def _load_payload(value: str) -> str:
    """
    Load a payload from a UTF-8 text file, or treat value as literal text.

    The payload is printed as text; it is never evaluated or executed.
    """

    candidate = Path(value)

    if candidate.is_file():
        payload = candidate.read_text(encoding="utf-8")
    else:
        payload = value

    if not payload.strip():
        raise ValueError("payload must not be empty")

    encoded = payload.encode("utf-8")

    if len(encoded) > MAX_PAYLOAD:
        raise ValueError(
            f"payload exceeds the {MAX_PAYLOAD}-byte safe demo limit"
        )

    if BLOCKED.search(payload):
        raise ValueError(
            "payload contains a blocked shell/process indicator"
        )

    return payload


def _build_source(payload: str, nonce: str, digest: str) -> str:
    """
    Build the generated Python program without using str.format().

    This avoids accidentally interpreting braces inside the generated
    Python source as template placeholders.
    """

    source = TEMPLATE
    source = source.replace("__NONCE__", nonce, 1)
    source = source.replace("__PAYLOAD__", repr(payload), 1)
    source = source.replace("__DIGEST__", digest, 1)

    variant = base64.b64encode(
        os.urandom(VARIANT_BYTES)
    ).decode("ascii")

    source = source.replace(
        "# VARIANT_MARKER",
        "# VARIANT: " + variant,
        1,
    )

    return source


def generate(output: Path, payload_arg: str) -> None:
    """Generate a harmless polymorphic demonstration program."""

    output = output.resolve()
    payload = _load_payload(payload_arg)

    nonce = secrets.token_hex(NONCE_BYTES)
    digest = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()

    source = _build_source(
        payload=payload,
        nonce=nonce,
        digest=digest,
    )

    # Validate syntax before writing the generated program.
    compile(source, str(output), "exec")

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        source,
        encoding="utf-8",
    )

    # Make executable on platforms that support Unix file permissions.
    try:
        output.chmod(0o755)
    except OSError:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymorphic",
        description=(
            "Generate a harmless local self-modifying "
            "polymorphism demonstration."
        ),
    )

    parser.add_argument(
        "--generate",
        required=True,
        metavar="OUTPUT",
        help="path of the generated Python program",
    )

    parser.add_argument(
        "--payload",
        required=True,
        metavar="TEXT_OR_FILE",
        help="literal text or path to a UTF-8 text file",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        output = Path(args.generate)

        generate(
            output=output,
            payload_arg=args.payload,
        )

        print(
            f'[OK] Generated demonstration: "{output}"'
        )
        print(
            "[INFO] Payload is displayed as text, not executed."
        )
        print(
            "[INFO] The generated program modifies its local signature."
        )
        print(
            "[INFO] No network, shell, or process-launch capability "
            "is implemented."
        )

        return 0

    except (OSError, UnicodeError, ValueError) as error:
        print(
            f"polymorphic: error: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())