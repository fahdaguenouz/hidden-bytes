#!/usr/bin/env python3
"""Lab-only listener for the Hidden-Bytes reverse shell demonstration.

This is the receiving end of the demonstration. It listens on a local
address, accepts one connection and relays it to the terminal in both
directions, so the operator can type commands and see the output of the
remote shell.

The shell itself runs on the *client* side: that is what makes it a reverse
shell. This listener only carries the bytes.

Safety rules for this file:

- It binds 127.0.0.1 by default. Use --host only to reach a listener on
  another machine of your own isolated lab.
- It is a lab demonstrator, not a server for a real engagement.

Usage:

    python3 lab/listener.py --port 4444
    python3 lab/listener.py --host 0.0.0.0 --port 4444
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="listener",
        description="Accept one reverse shell connection in an isolated lab.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="address to bind (default: 127.0.0.1, local only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="port to listen on (default: 4444)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="seconds to wait for a connection (default: 60)",
    )
    return parser


def _pump_to_terminal(connection: socket.socket) -> None:
    """Copy the socket output to the terminal until the socket closes."""

    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except OSError:
        pass


def _pump_to_socket(connection: socket.socket) -> None:
    """Copy the operator's terminal input to the socket."""

    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            connection.sendall(line.encode("utf-8"))
    except (OSError, KeyboardInterrupt):
        pass
    finally:
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main() -> int:
    args = build_parser().parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(args.timeout)

    try:
        server.bind((args.host, args.port))
        server.listen(1)
    except OSError as exc:
        print(f"[ERROR] Could not listen on {args.host}:{args.port}: {exc}")
        return 1

    print(f"[INFO] Listening on {args.host}:{args.port}. Waiting for a connection...")

    try:
        connection, address = server.accept()
    except socket.timeout:
        print("[ERROR] No connection received before the timeout.")
        return 1
    finally:
        server.close()

    print(f"[INFO] Connection received from {address[0]}:{address[1]}")
    print("[INFO] Type a command and press enter. Type 'exit' to finish.")

    # The remote shell runs on the client side; this process only relays.
    reader = threading.Thread(
        target=_pump_to_terminal, args=(connection,), daemon=True
    )
    reader.start()

    try:
        _pump_to_socket(connection)
    finally:
        connection.close()
        reader.join(timeout=5)

    print("[INFO] Session closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
