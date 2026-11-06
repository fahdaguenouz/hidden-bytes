"""AES-256-GCM encryption and recovery for HBX1 containers.

A container is the encrypted form of a payload. It can be written on its own
(``.hbx`` file) or embedded in a self-extracting runner that waits for the
configured delay before recovering the payload.

Each container is protected by a freshly generated 256-bit random key. The key
is written to a sidecar ``.key`` file and is required to recover the payload;
it is never derived from a passphrase.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    HEADER_SIZE,
    KEY_SIZE,
    MAGIC,
    MAX_HEADER_SIZE,
    MIB,
    NONCE_SIZE,
)
from .container import read_container
from .encoding import b64_decode, b64_encode


def build_payload(source: Path, delay: float) -> tuple[bytes, dict, bytes]:
    """Encrypt a file in memory.

    Returns ``(body, header, key)`` where ``body`` is the container without
    the size padding, ``header`` is its metadata and ``key`` is the raw
    256-bit random encryption key. The key must be written to a sidecar
    ``.key`` file so the container can be recovered later.
    """

    if delay < 0:
        raise ValueError("delay cannot be negative")

    plaintext = source.read_bytes()
    original_size = len(plaintext)

    # Fresh 256-bit key for every encryption.
    key = AESGCM.generate_key(bit_length=256)

    # Fresh 96-bit nonce for every encryption.
    nonce = os.urandom(NONCE_SIZE)

    # Authenticate the format identifier as AAD: altering MAGIC breaks auth.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)

    header = {
        "algorithm": "AES-256-GCM",
        "ciphertext_length": len(ciphertext),
        "delay_seconds": delay,
        "original_name": source.name,
        "original_size": original_size,
        "nonce": b64_encode(nonce),
    }

    raw_header = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    if len(raw_header) > MAX_HEADER_SIZE:
        raise ValueError("generated header is unexpectedly large")

    body = MAGIC + HEADER_SIZE.pack(len(raw_header)) + raw_header + ciphertext

    return body, header, key


def padding_for(requested_size: int, current_size: int) -> int:
    """Return the number of random bytes needed to reach the requested size."""

    if requested_size < current_size:
        raise ValueError(
            "requested final size is too small for the encrypted container "
            f"metadata and ciphertext. Minimum required: {current_size} bytes; "
            f"requested: {requested_size} bytes."
        )
    return requested_size - current_size


def encrypt_file(
    source: Path,
    output: Path,
    add_size_mb: float,
    delay: float,
) -> Path:
    """Encrypt a file into a standalone HBX1 container.

    The final container size is ``original_size + round(add_size_mb * MIB)``,
    reached by appending cryptographically random padding.

    A fresh random key is generated for every encryption and written to a
    sidecar ``.key`` file next to the output. The sidecar path is returned.
    """

    source = source.resolve()
    output = output.resolve()

    if not source.is_file():
        raise ValueError(f"source file does not exist: {source}")
    if source == output:
        raise ValueError("source and output cannot be the same file")
    if add_size_mb < 0:
        raise ValueError("add_size_mb cannot be negative")

    body, header, key = build_payload(source, delay)

    # header["original_size"] is len(plaintext) computed by build_payload;
    # reuse it instead of calling source.stat() again.
    requested_size = header["original_size"] + round(add_size_mb * MIB)
    padding = padding_for(requested_size, len(body))

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("wb") as handle:
        handle.write(body)
        if padding:
            handle.write(os.urandom(padding))

    actual_size = output.stat().st_size
    if actual_size != requested_size:
        raise RuntimeError(
            "internal size verification failed: "
            f"expected {requested_size}, got {actual_size}"
        )

    key_path = output.with_name(output.name + ".key")
    key_path.write_text(b64_encode(key) + "\n", encoding="ascii")

    # Best-effort restriction on Unix; Windows may ignore this.
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    return key_path


def load_key(key_path: Path) -> bytes:
    """Read and validate a Base64-encoded AES-256 key."""
    if not key_path.is_file():
        raise ValueError(f"key file does not exist: {key_path}")

    key = b64_decode(key_path.read_text(encoding="ascii").strip(), "key")
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"invalid AES-256 key length: expected {KEY_SIZE} bytes, "
            f"got {len(key)}"
        )
    return key


def _resolve_key(header: dict, key_path: Path | None) -> bytes:
    """Return the key of a container from its sidecar key file."""

    if key_path is None:
        raise ValueError(
            "a key file is required to recover this container; use --key"
        )

    return load_key(key_path)


def decrypt_payload(
    header: dict,
    ciphertext: bytes,
    key: bytes,
) -> bytes:
    """Decrypt and authenticate a container payload."""

    nonce = b64_decode(header["nonce"], "nonce")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise ValueError(
            "authentication failed: wrong key or container data was modified"
        ) from exc

    expected_size = int(header["original_size"])
    if len(plaintext) != expected_size:
        raise ValueError(
            "recovered plaintext size does not match metadata: "
            f"expected {expected_size}, got {len(plaintext)}"
        )

    return plaintext


def decrypt_file(
    source: Path,
    output: Path,
    key_path: Path | None = None,
    no_delay: bool = False,
) -> None:
    """Recover the original plaintext from an HBX1 container or a runner.

    The recovered file is written to disk only; it is never executed by this
    function. A runner carries its key embedded in its launcher, so no key
    file is needed; a plain ``.hbx`` container needs its key via ``key_path``.
    """

    from .runner import is_runner, read_runner_key

    source = source.resolve()
    output = output.resolve()

    if source == output:
        raise ValueError("source and output cannot be the same file")

    header, ciphertext = _read_any_container(source)

    delay = float(header["delay_seconds"])
    if delay and not no_delay:
        print(f"[INFO] Recovery delayed for {delay:g} second(s)...", flush=True)
        time.sleep(delay)

    if is_runner(source):
        key = read_runner_key(source)
        if key is None:
            raise ValueError(
                "could not read the key embedded in this runner; a native "
                "executable recovers its payload only by being run"
            )
    else:
        key = _resolve_key(header, key_path)
    plaintext = decrypt_payload(header, ciphertext, key)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)

    if output.stat().st_size != int(header["original_size"]):
        raise RuntimeError("recovered file size verification failed")


def _read_any_container(source: Path) -> tuple[dict, bytes]:
    """Read a container from a plain ``.hbx`` file or from a runner."""

    from .runner import is_runner, read_runner_container

    if is_runner(source):
        return read_runner_container(source)

    return read_container(source)
