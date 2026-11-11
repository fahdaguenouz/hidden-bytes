"""AES-256-GCM encryption and recovery for HBX1 containers.

A container is the encrypted form of a payload. The CLI always embeds the
container inside a self-extracting runner that waits for the configured delay
before recovering the payload.

Each container is protected by a freshly generated 256-bit random key, never
derived from a passphrase. The key is **embedded inside the runner artifact
itself** (see ``runner.py``): no separate key file is ever produced, and the
runner recovers its own payload. The runner artifact is therefore the secret
and must be protected with access controls.
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
    MAGIC,
    MAX_HEADER_SIZE,
    NONCE_SIZE,
)
from .encoding import b64_decode, b64_encode


def build_payload(source: Path, delay: float) -> tuple[bytes, dict, bytes]:
    """Encrypt a file in memory.

    Returns ``(body, header, key)`` where ``body`` is the container without
    the size padding, ``header`` is its metadata and ``key`` is the raw
    256-bit random encryption key. The caller (``runner.py``) embeds that key
    inside the runner artifact so it can recover its own payload later.
    """

    if delay < 0:
        raise ValueError("delay cannot be negative")

    plaintext = source.read_bytes()
    original_size = len(plaintext)

    # new 256-bit key for every encryption.
    key = AESGCM.generate_key(bit_length=256)

    # new 96-bit nonce for every encryption.
    nonce = os.urandom(NONCE_SIZE)

    #  the format identifier: altering MAGIC breaks auth.
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
    no_delay: bool = False,
) -> None:
    """Recover the original plaintext from a Hidden-Bytes runner.

    The recovered file is written to disk only; it is never executed by this
    function. The runner carries its key embedded in its launcher, so no key
    file or passphrase is needed.
    """

    from .runner import is_runner, read_runner_container, read_runner_key

    source = source.resolve()
    output = output.resolve()

    if source == output:
        raise ValueError("source and output cannot be the same file")

    if not is_runner(source):
        raise ValueError(
            "input is not a Hidden-Bytes runner; only runners produced by "
            "--encrypt carry the embedded key needed to recover them"
        )

    header, ciphertext = read_runner_container(source)

    delay = float(header["delay_seconds"])
    if delay and not no_delay:
        print(f"[INFO] Recovery delayed for {delay:g} second(s)...", flush=True)
        time.sleep(delay)

    key = read_runner_key(source)
    if key is None:
        raise ValueError(
            "could not read the key embedded in this runner; a native "
            "executable recovers its payload only by being run"
        )

    plaintext = decrypt_payload(header, ciphertext, key)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(plaintext)

    if output.stat().st_size != int(header["original_size"]):
        raise RuntimeError("recovered file size verification failed")
