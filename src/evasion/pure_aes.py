"""Dependency-free AES-256-GCM decryption.

The generated self-extracting runner must be able to recover its payload on a
machine that has nothing installed except a Python 3 interpreter, so the
container cannot depend on the third-party ``cryptography`` package at
recovery time. This module implements the subset of AES-GCM that HBX1 needs:
the forward cipher (used for counter-mode keystream and for the tag mask) and
GHASH (used for authentication).

The source of this module is spliced verbatim into the generated runner, so it
must stay importable with the standard library only and must not use
``from __future__`` statements.
"""

import hmac
import struct


class InvalidTagError(Exception):
    """Raised when the GCM authentication tag does not match."""


def _build_sbox():
    """Generate the AES S-box from the algebraic definition.

    Only the forward S-box is needed: AES-GCM uses the forward cipher for both
    the counter-mode keystream and the tag mask, and never the inverse cipher.
    """

    sbox = [0] * 256
    p = 1
    q = 1

    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)

        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09

        value = q
        for shift in (1, 2, 3, 4):
            value ^= ((q << shift) | (q >> (8 - shift))) & 0xFF

        sbox[p] = value ^ 0x63
        if p == 1:
            break

    sbox[0] = 0x63

    return sbox


SBOX = _build_sbox()


def _xtime(value):
    """Multiply a byte by 2 in GF(2^8)."""

    value <<= 1
    if value & 0x100:
        value ^= 0x11B
    return value & 0xFF


def _expand_key(key):
    """Expand an AES key into the round keys of its cipher."""

    key_length = len(key)
    if key_length not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes long")

    nk = key_length // 4
    rounds = nk + 6

    words = [list(key[index * 4:index * 4 + 4]) for index in range(nk)]
    rcon = 1

    for index in range(nk, 4 * (rounds + 1)):
        temp = list(words[index - 1])

        if index % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[byte] for byte in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and index % nk == 4:
            temp = [SBOX[byte] for byte in temp]

        words.append(
            [words[index - nk][position] ^ temp[position] for position in range(4)]
        )

    return [
        [byte for word in words[round_index * 4:round_index * 4 + 4] for byte in word]
        for round_index in range(rounds + 1)
    ]


def _add_round_key(state, round_key):
    for index in range(16):
        state[index] ^= round_key[index]


def _sub_bytes(state):
    for index in range(16):
        state[index] = SBOX[state[index]]


def _shift_rows(state):
    for row in range(1, 4):
        values = [state[row + 4 * column] for column in range(4)]
        values = values[row:] + values[:row]
        for column in range(4):
            state[row + 4 * column] = values[column]


def _mix_columns(state):
    for column in range(4):
        a0, a1, a2, a3 = state[4 * column:4 * column + 4]
        state[4 * column + 0] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
        state[4 * column + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
        state[4 * column + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
        state[4 * column + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)


def encrypt_block(key, block):
    """Encrypt a single 16-byte block with AES."""

    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes long")

    round_keys = _expand_key(key)
    state = list(block)

    _add_round_key(state, round_keys[0])
    for round_index in range(1, len(round_keys) - 1):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_index])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[-1])

    return bytes(state)


def _gf128_multiply(x, y):
    """Multiply two 128-bit values in the GCM Galois field."""

    reduction = 0xE1 << 120
    result = 0
    value = y

    for bit in range(128):
        if (x >> (127 - bit)) & 1:
            result ^= value
        if value & 1:
            value = (value >> 1) ^ reduction
        else:
            value >>= 1

    return result


def _ghash(h, aad, ciphertext):
    """Compute GHASH over the additional data and the ciphertext."""

    y = 0
    h_int = int.from_bytes(h, "big")

    def absorb(data):
        nonlocal y
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16].ljust(16, b"\x00")
            y = _gf128_multiply(y ^ int.from_bytes(block, "big"), h_int)

    absorb(aad)
    absorb(ciphertext)

    length_block = struct.pack(
        ">QQ", len(aad) * 8, len(ciphertext) * 8
    )
    y = _gf128_multiply(y ^ int.from_bytes(length_block, "big"), h_int)

    return y.to_bytes(16, "big")


def _keystream(key, j0, length):
    """Generate the AES-GCM counter-mode keystream."""

    prefix = j0[:12]
    counter = int.from_bytes(j0[12:], "big")
    stream = bytearray()

    while len(stream) < length:
        counter = (counter + 1) & 0xFFFFFFFF
        block = encrypt_block(key, prefix + counter.to_bytes(4, "big"))
        stream.extend(block)

    return bytes(stream[:length])


def decrypt_gcm(key, nonce, ciphertext, aad=b""):
    """Decrypt and authenticate an AES-GCM message.

    ``ciphertext`` is the encrypted data with the 16-byte GCM tag appended,
    exactly as produced by the ``cryptography`` package.
    """

    if len(nonce) != 12:
        raise ValueError("only 96-bit GCM nonces are supported")
    if len(ciphertext) < 16:
        raise ValueError("ciphertext is too short to hold a GCM tag")

    body = ciphertext[:-16]
    tag = ciphertext[-16:]

    h = encrypt_block(key, b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"

    stream = _keystream(key, j0, len(body))
    plaintext = bytes(
        byte ^ stream[index] for index, byte in enumerate(body)
    )

    mask = encrypt_block(key, j0)
    digest = _ghash(h, aad, body)
    expected = bytes(left ^ right for left, right in zip(digest, mask))

    if not hmac.compare_digest(expected, tag):
        raise InvalidTagError("authentication failed")

    return plaintext


def encrypt_gcm(key, nonce, plaintext, aad=b""):
    """Encrypt and authenticate a message with AES-GCM.

    The result is the ciphertext with the 16-byte GCM tag appended, exactly
    the format produced by the ``cryptography`` package.
    """

    if len(nonce) != 12:
        raise ValueError("only 96-bit GCM nonces are supported")

    h = encrypt_block(key, b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"

    stream = _keystream(key, j0, len(plaintext))
    body = bytes(
        byte ^ stream[index] for index, byte in enumerate(plaintext)
    )

    mask = encrypt_block(key, j0)
    digest = _ghash(h, aad, body)
    tag = bytes(left ^ right for left, right in zip(digest, mask))

    return body + tag
