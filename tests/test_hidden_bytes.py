from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

import pytest

from hidden_bytes.evasion import MIB, decrypt_file, encrypt_file, inspect_file
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
