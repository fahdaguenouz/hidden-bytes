"""Shared helpers for building the generated artifacts.

The generated artifacts (the evasion runner and the polymorphic program)
decrypt with the ``cryptography`` library at run time, and can be packaged into
a single native executable with PyInstaller, which bundles that library.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def has_pyinstaller() -> bool:
    """Return True when the PyInstaller module can be imported."""

    from importlib.util import find_spec

    try:
        return find_spec("PyInstaller") is not None
    except (ImportError, ValueError):  # pragma: no cover - defensive
        return False


def build_executable(
    script_path: Path,
    output: Path,
    name: str,
    extra_data: Path | None = None,
    workdir: Path | None = None,
    trailer: bytes | None = None,
) -> Path:
    """Package a Python script into a single native executable.

    Requires PyInstaller. On Windows the result is a ``.exe`` file, which is
    what the audit demonstration needs.

    ``trailer`` is optional data appended after the packaged archive. The
    PyInstaller loader finds its archive with a back-to-front scan for its
    cookie, so trailing bytes do not affect execution.
    """

    if shutil.which("pyinstaller") is None and not has_pyinstaller():
        raise ValueError(
            "PyInstaller is not available. Install it with: "
            "python -m pip install pyinstaller"
        )

    owned_workdir = workdir is None
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="hbx_build_"))

    try:
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--noconfirm",
            "--clean",
            "--name",
            name,
            "--distpath",
            str(workdir / "dist"),
            "--workpath",
            str(workdir / "build"),
            "--specpath",
            str(workdir),
        ]

        if extra_data is not None:
            command += ["--add-data", f"{extra_data.resolve()}{os.pathsep}."]

        command.append(str(script_path.resolve()))

        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        if completed.returncode != 0:
            raise ValueError(
                "PyInstaller failed with exit code "
                f"{completed.returncode}:\n{completed.stdout}"
            )

        built = workdir / "dist" / name
        if sys.platform == "win32":
            built = built.with_suffix(".exe")

        if not built.is_file():
            raise ValueError("PyInstaller did not produce the expected executable")

        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, output)

        if trailer:
            with output.open("ab") as handle:
                handle.write(trailer)

        return output
    finally:
        if owned_workdir:
            shutil.rmtree(workdir, ignore_errors=True)
