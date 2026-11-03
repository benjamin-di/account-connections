"""Synthetic checks of reporting boundaries; no browser or application auth."""

import importlib.util
import json
import os
import signal
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "account_ci_check", Path(__file__).parents[1] / "scripts" / "ci-check.py"
)
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def test_gate_inventory():
    assert ci.commands("dependencies") == [("sync", ["uv", "sync", "--locked"])]
    assert ci.commands("tests") == [("pytest", ["uv", "run", "--locked", "pytest", "-q"])]
    assert ci.commands("browser-tests")[0][1] == [
        "uv",
        "run",
        "--locked",
        "--group",
        "browser",
        "pytest",
        "-q",
        "tests/test_web_browser.py",
    ]
    assert ci.commands("wheel")[0][1][-2:] == ["python", "scripts/check_wheel.py"]
    assert ci.commands("package") == [("build", ["uv", "build"])]
    assert ci.commands("lint")[0][1][-3:] == ["ruff", "check", "."]
    assert ci.commands("format")[0][1][-4:] == ["ruff", "format", "--check", "."]
    assert ci.commands("typecheck")[0][1][-2:] == ["mypy", "src/account_connections"]
    assert ci.commands("whitespace") == [("whitespace", ["git", "diff", "--check"])]


def test_command_failure_and_bounded_tail(tmp_path):
    result = ci.command(
        [sys.executable, "-c", "import sys; print('x' * 100000); sys.exit(7)"],
        tmp_path / "command.log",
        dict(os.environ),
    )
    assert result["exit_code"] == 7
    assert result["truncated"]
    assert (tmp_path / "command.log").stat().st_size == ci.LOG_BYTES


def test_unwritable_log_preserves_status(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("file, not a directory")
    result = ci.command(
        [sys.executable, "-c", "raise SystemExit(9)"], blocked / "x.log", dict(os.environ)
    )
    assert result["exit_code"] == 9
    assert not result["log_retained"]


def test_missing_command_retains_failure(tmp_path):
    result = ci.command([str(tmp_path / "absent")], tmp_path / "x.log", dict(os.environ))
    assert result["exit_code"] == 127


@pytest.mark.parametrize("failure", [False, True])
def test_real_pytest_reports_are_isolated(tmp_path, monkeypatch, failure):
    monkeypatch.chdir(tmp_path)
    test = tmp_path / "synthetic_test.py"
    test.write_text(f"def test_synthetic():\n    assert {not failure!r}\n")
    monkeypatch.setattr(
        ci, "commands", lambda gate: [("pytest", [sys.executable, "-m", "pytest", "-q", str(test)])]
    )
    status = ci.run("tests")
    assert status == int(failure)
    status = ci.run("tests")
    assert status == int(failure)
    reports = sorted((tmp_path / ".artifacts/ci/junit").glob("*.xml"))
    assert len(reports) == 2
    for report in reports:
        root = ET.parse(report).getroot()
        assert len(root.findall(".//testcase")) == 1
        assert len(root.findall(".//failure")) == int(failure)
    records = list((tmp_path / ".artifacts/ci/diagnostics").glob("*.json"))
    assert len(records) == 2
    assert all(json.loads(path.read_text())["exit_code"] == int(failure) for path in records)


@pytest.mark.parametrize("failure", [False, True])
def test_unwritable_artifacts_preserve_pytest_status(tmp_path, monkeypatch, failure):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".artifacts").write_text("file, not a directory")
    test = tmp_path / "synthetic_test.py"
    test.write_text(f"def test_synthetic():\n    assert {not failure!r}\n")
    monkeypatch.setattr(
        ci, "commands", lambda gate: [("pytest", [sys.executable, "-m", "pytest", "-q", str(test)])]
    )
    assert ci.run("tests") == int(failure)


def test_first_failure_stops_remaining_commands(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    marker = tmp_path / "should-not-exist"
    monkeypatch.setattr(
        ci,
        "commands",
        lambda gate: [
            ("failure", [sys.executable, "-c", "raise SystemExit(11)"]),
            ("later", [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"]),
        ],
    )
    assert ci.run("lint") == 11
    assert not marker.exists()


def test_cancellation_kills_descendant_and_preserves_signal(tmp_path):
    marker = tmp_path / "escaped"
    grandchild = f"import time; time.sleep(1); open({str(marker)!r}, 'w').close()"
    child = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        "print('ready', flush=True); time.sleep(30)"
    )
    timer = threading.Timer(0.25, lambda: os.kill(os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        result = ci.command([sys.executable, "-c", child], tmp_path / "x.log", dict(os.environ))
    finally:
        timer.cancel()
        timer.join()
    assert result["exit_code"] == 128 + signal.SIGTERM
    time.sleep(1.1)
    assert not marker.exists()
