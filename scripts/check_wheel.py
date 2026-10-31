"""Install the built dependency-free wheel in a clean interpreter environment."""

import subprocess
import tempfile
import zipfile
from pathlib import Path

(wheel,) = Path("dist").glob("*.whl")
with zipfile.ZipFile(wheel) as archive:
    files = set(archive.namelist())
    assert "account_connections/py.typed" in files
    assert not any(name.startswith(("tests/", "publish/", ".github/")) for name in files)
with tempfile.TemporaryDirectory() as directory:
    env = Path(directory) / "venv"
    subprocess.run(["uv", "venv", str(env)], check=True)
    python = env / "bin/python"
    subprocess.run(
        ["uv", "pip", "install", "--python", str(python), "--no-deps", str(wheel.resolve())],
        check=True,
    )
    subprocess.run(
        [
            str(python),
            "-c",
            "from account_connections import Choice, Selection, resolve; "
            "assert resolve('actor', Selection(Choice('actor'), 'revision'), None)"
            ".owner == 'actor'",
        ],
        cwd=directory,
        check=True,
    )
