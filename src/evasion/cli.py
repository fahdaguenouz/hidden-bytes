"""Command-line interface for the evasion / HBX1 packaging tool."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..common import delay_number, positive_number
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
        type=delay_number,
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


def _run_encrypt(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.output is None:
        parser.error("--output is required with --encrypt")

    original_size = args.source.stat().st_size

    key_path = encrypt_file(
        source=args.source,
        output=args.output,
        add_size_mb=args.add_size,
        delay=args.delay,
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


def _run_decrypt(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.output is None:
        parser.error("--output is required with --decrypt")

    
    decrypt_file(
        source=args.source,
        output=args.output,
        key_path=args.key,
        no_delay=args.no_delay,
    )

    print("[OK] Recovery completed.")
    print(f"[INFO] Recovered file: {args.output}")
    print("[INFO] The recovered file was written to disk but was NOT executed.")
    return 0


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
