"""Install the built wheel without optional dependencies in a clean environment."""

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
            """
from pathlib import Path
from account_connections import Choice, Selection, resolve
from account_connections.people import People, Policy
from account_connections.controls import Controls
from account_connections.admission import AdmissionService
assert resolve('actor', Selection(Choice('actor'), 'revision'), None).owner == 'actor'
people = People(Path('controls'))
people.enroll('actor', namespaces=['default'])
controls = Controls(people)
attempt = controls.begin('actor', 'default')
controls.stage('actor', 'default', attempt, lambda: None)
controls.publish('actor', 'default', attempt, lambda: None)
policy = Policy('1', frozenset({'cart'}))
people.select('actor', 'default', 'actor', policy=policy,
              expected=people.namespace('actor', 'default')['selection']['revision'])
admission = AdmissionService(people, controls, b'synthetic-test-key' * 2)
assert admission.capture('actor', 'default', policy=policy).owner == 'actor'
""",
        ],
        cwd=directory,
        check=True,
    )
