from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from hidden_bytes.evasion import (
    MIB,
    build_runner_file,
    decrypt_file,
    encrypt_file,
    inspect_file,
    is_runner,
    read_runner_container,
)
from hidden_bytes.evasion.crypto import build_payload
from hidden_bytes.evasion.pure_aes import decrypt_gcm
from hidden_bytes.polymorphic import generate


def test_encryption_padding_metadata_and_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"hello\x00binary" * 100)
    container = tmp_path / "sample.hbx"
    recovered = tmp_path / "recovered.bin"

    key = encrypt_file(source, container, add_size_mb=1, delay=0)

    assert container.stat().st_size == source.stat().st_size + MIB
    assert container.read_bytes()[:4] == b"HBX1"
    assert inspect_file(container)["algorithm"] == "AES-256-GCM"
    assert source.read_bytes() not in container.read_bytes()
    decrypt_file(container, recovered, key)
    assert recovered.read_bytes() == source.read_bytes()


def test_wrong_key_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"important")
    container = tmp_path / "sample.hbx"
    encrypt_file(source, container, add_size_mb=0.01, delay=0)
    wrong = tmp_path / "wrong.key"
    import base64, os
    wrong.write_text(base64.b64encode(os.urandom(32)).decode("ascii"))
    with pytest.raises(Exception):
        decrypt_file(container, tmp_path / "out", wrong)


def test_recovery_enforces_recorded_delay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"delay me")
    container = tmp_path / "sample.hbx"
    key = encrypt_file(source, container, add_size_mb=0.01, delay=101)
    sleeps: list[float] = []
    monkeypatch.setattr("hidden_bytes.evasion.time.sleep", sleeps.append)
    decrypt_file(container, tmp_path / "out", key)
    assert sleeps == [101]


def test_polymorphic_demo_changes_itself_but_keeps_behavior(tmp_path: Path) -> None:
    demo = tmp_path / "demo.py"
    generate(demo, "Hello from the safe payload")
    before = hashlib.sha256(demo.read_bytes()).hexdigest()
    first = subprocess.run([sys.executable, str(demo)], check=True, capture_output=True, text=True)
    after_first = hashlib.sha256(demo.read_bytes()).hexdigest()
    second = subprocess.run([sys.executable, str(demo)], check=True, capture_output=True, text=True)
    after_second = hashlib.sha256(demo.read_bytes()).hexdigest()
    assert before != after_first != after_second
    assert first.stdout == second.stdout
    assert "Hello from the safe payload" in first.stdout


def test_polymorphic_demo_rejects_reverse_shells(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not permitted"):
        generate(tmp_path / "bad.py", "powershell reverse shell")


# ---------------------------------------------------------------------------
# Pure-Python AES-256-GCM
# ---------------------------------------------------------------------------


def test_pure_aes_gcm_matches_the_cryptography_library() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = os.urandom(32)
    nonce = os.urandom(12)

    for size in (0, 1, 15, 16, 17, 1000):
        plaintext = os.urandom(size)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"HBX1")
        assert decrypt_gcm(key, nonce, ciphertext, b"HBX1") == plaintext


def test_pure_aes_gcm_rejects_tampering() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = bytearray(AESGCM(key).encrypt(nonce, b"payload", b"HBX1"))
    ciphertext[0] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_gcm(key, nonce, bytes(ciphertext), b"HBX1")


# ---------------------------------------------------------------------------
# The self-extracting runner
# ---------------------------------------------------------------------------


def _write_payload(path: Path) -> None:
    path.write_text(
        "import os\n"
        "print('PAYLOAD-EXECUTED')\n"
        "open(os.environ['HBX_MARKER'], 'w').write('done')\n"
    )


def test_runner_increases_the_file_size_by_the_requested_amount(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=1,
        delay=0,
        passphrase="hunter2",
        passphrase_source={"env": "HBX_PASSPHRASE"},
    )

    assert runner.stat().st_size == source.stat().st_size + MIB
    assert is_runner(runner)


def test_runner_embeds_the_delay_in_the_container(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=0.01,
        delay=101,
        passphrase="hunter2",
    )

    header, ciphertext = read_runner_container(runner)
    assert header["delay_seconds"] == 101
    assert header["original_name"] == "simple_program.py"
    assert header["original_size"] == source.stat().st_size
    assert ciphertext


def test_runner_enforces_the_delay_before_launching_the_payload(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=0.01,
        delay=3,
        passphrase="hunter2",
        passphrase_source={"env": "HBX_PASSPHRASE"},
    )

    marker = tmp_path / "marker.txt"
    environment = dict(os.environ, HBX_PASSPHRASE="hunter2", HBX_MARKER=str(marker))

    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, str(runner)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    elapsed = time.monotonic() - started

    assert completed.returncode == 0, completed.stderr
    assert elapsed >= 3, f"the runner returned after {elapsed:.2f}s, expected >= 3s"
    assert "Execution delayed by 3 seconds" in completed.stdout
    assert "Binary decrypted successfully" in completed.stdout
    assert "Target program executed" in completed.stdout
    assert "PAYLOAD-EXECUTED" in completed.stdout
    assert marker.read_text() == "done"


def test_runner_rejects_a_wrong_passphrase(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=0.01,
        delay=0,
        passphrase="correct-passphrase",
        passphrase_source={"env": "HBX_PASSPHRASE"},
    )

    environment = dict(os.environ, HBX_PASSPHRASE="wrong-passphrase")
    completed = subprocess.run(
        [sys.executable, str(runner)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode != 0
    assert "decryption failed" in completed.stderr
    assert "PAYLOAD-EXECUTED" not in completed.stdout


def test_runner_does_not_expose_the_plaintext_payload(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=0.01,
        delay=0,
        passphrase="hunter2",
    )

    assert b"PAYLOAD-EXECUTED" not in runner.read_bytes()


def test_decrypt_recovers_the_payload_from_a_runner(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=0.01,
        delay=0,
        passphrase="hunter2",
        passphrase_source={"env": "HBX_PASSPHRASE"},
    )

    recovered = tmp_path / "recovered.py"
    decrypt_file(
        runner,
        recovered,
        passphrase="hunter2",
    )

    assert recovered.read_bytes() == source.read_bytes()


def test_decrypt_uses_the_passphrase_source_recorded_in_the_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    build_runner_file(
        source,
        runner,
        add_size_mb=0.01,
        delay=0,
        passphrase="hunter2",
        passphrase_source={"env": "HBX_PASSPHRASE"},
    )

    monkeypatch.setenv("HBX_PASSPHRASE", "hunter2")

    recovered = tmp_path / "recovered.py"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "hidden_bytes.evasion.cli",
            "--decrypt",
            str(runner),
            "--output",
            str(recovered),
            "--no-delay",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    assert recovered.read_bytes() == source.read_bytes()


def test_container_mode_still_writes_a_key_file(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"key file mode")

    container = tmp_path / "sample.hbx"
    key_path = encrypt_file(source, container, add_size_mb=0.01, delay=0)

    assert key_path is not None
    assert key_path.is_file()
    assert inspect_file(container)["artifact_type"] == "container"
    assert "kdf" not in inspect_file(container)


def test_passphrase_container_records_the_kdf_metadata(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"passphrase mode")

    container = tmp_path / "sample.hbx"
    key_path = encrypt_file(
        source,
        container,
        add_size_mb=0.01,
        delay=0,
        passphrase="hunter2",
        passphrase_source={"env": "HBX_PASSPHRASE"},
    )

    assert key_path is None

    metadata = inspect_file(container)
    assert metadata["kdf"]["name"] == "PBKDF2-HMAC-SHA256"
    assert metadata["kdf"]["env"] == "HBX_PASSPHRASE"

    recovered = tmp_path / "recovered.bin"
    decrypt_file(container, recovered, passphrase="hunter2")
    assert recovered.read_bytes() == source.read_bytes()


def test_passphrase_container_rejects_a_wrong_passphrase(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"passphrase mode")

    container = tmp_path / "sample.hbx"
    encrypt_file(
        source,
        container,
        add_size_mb=0.01,
        delay=0,
        passphrase="correct",
    )

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_file(container, tmp_path / "out", passphrase="wrong")


def test_build_payload_rejects_a_negative_delay(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"x")

    with pytest.raises(ValueError, match="delay"):
        build_payload(source, delay=-1)


def test_cli_encrypt_then_run_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "simple_program.py"
    _write_payload(source)

    runner = tmp_path / "obfuscated.pyz"
    marker = tmp_path / "marker.txt"

    environment = dict(os.environ, HBX_PASSPHRASE="hunter2")
    encrypted = subprocess.run(
        [
            sys.executable,
            "-m",
            "hidden_bytes.evasion.cli",
            "--encrypt",
            str(source),
            "--output",
            str(runner),
            "--add-size",
            "0.01",
            "--delay",
            "0",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert encrypted.returncode == 0, encrypted.stderr

    executed = subprocess.run(
        [sys.executable, str(runner)],
        env=dict(environment, HBX_MARKER=str(marker)),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert executed.returncode == 0, executed.stderr
    assert "PAYLOAD-EXECUTED" in executed.stdout
