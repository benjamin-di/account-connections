"""Run the existing source gates with bounded logs and genuine pytest reports.

Native stages share the same checkout and locked development environment. Browser
profiles and report generation stay in disposable invocation state; only bounded
command logs, status and actual JUnit reports are retained.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

LOG_BYTES = 64 * 1024


class Cancelled(BaseException):
    def __init__(self, number):
        self.number = number


def stop(process):
    """Fence descendants too, including after their group leader has exited."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def save(path, data):
    """Artifact storage is advisory; it must never replace a gate's status."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return True
    except OSError:
        print("Check diagnostics could not be retained", file=sys.stderr, flush=True)
        return False


def command(argv, log, environment):
    process = None
    tail = bytearray()
    total = 0
    previous = {}
    pending = []
    status = 127

    def cancel(number, _frame):
        pending.append(number)
        if process is not None:
            raise Cancelled(number)

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, cancel)
        if pending:
            raise Cancelled(pending[0])
        process = subprocess.Popen(
            argv,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if pending:
            raise Cancelled(pending[0])
        while chunk := os.read(process.stdout.fileno(), 8192):
            total += len(chunk)
            tail.extend(chunk)
            del tail[:-LOG_BYTES]
            # A closed console must not mask the command's actual result.
            with contextlib.suppress(OSError):
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        status = process.wait()
        if status < 0:
            status = 128 - status
    except Cancelled as interrupted:
        status = 128 + interrupted.number
    except FileNotFoundError:
        status = 127
        print("Required check command is unavailable", file=sys.stderr, flush=True)
    except PermissionError:
        status = 126
        print("Required check command is not executable", file=sys.stderr, flush=True)
    except OSError:
        status = 125
        print("Check command could not run", file=sys.stderr, flush=True)
    finally:
        # A second cancellation must not interrupt bounded group teardown.
        for number in previous:
            signal.signal(number, signal.SIG_IGN)
        if process is not None:
            stop(process)
            process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)
        retained = save(log, tail)
    return {
        "exit_code": status,
        "output_bytes": total,
        "truncated": total > LOG_BYTES,
        "log_retained": retained,
    }


def commands(gate):
    uv = ["uv", "run", "--locked"]
    gates = {
        "dependencies": [("sync", ["uv", "sync", "--locked"])],
        "lint": [("lint", [*uv, "ruff", "check", "."])],
        "format": [("format", [*uv, "ruff", "format", "--check", "."])],
        "typecheck": [("mypy", [*uv, "mypy", "src/account_connections"])],
        "tests": [("pytest", [*uv, "pytest", "-q"])],
        "whitespace": [("whitespace", ["git", "diff", "--check"])],
        "browser": [
            ("install", [*uv, "--group", "browser", "playwright", "install", "chromium"]),
            (
                "preflight",
                [*uv, "--group", "browser", "python", "scripts/ci-check.py", "browser-preflight"],
            ),
        ],
        "browser-tests": [
            ("pytest", [*uv, "--group", "browser", "pytest", "-q", "tests/test_web_browser.py"])
        ],
        "package": [("build", ["uv", "build"])],
        "wheel": [("wheel", [*uv, "python", "scripts/check_wheel.py"])],
    }
    return gates[gate]


def browser_preflight():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as browser:
        executable = Path(browser.chromium.executable_path)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        print("The locked Chromium executable is unavailable", file=sys.stderr)
        return 1
    # ldd examines this downloaded binary; it does not reinstall host packages.
    result = subprocess.run(["ldd", str(executable)], capture_output=True, text=True, check=False)
    if result.returncode or "not found" in result.stdout or "not found" in result.stderr:
        print(
            "Chromium system libraries are unavailable; provision the worker before retrying",
            file=sys.stderr,
        )
        return result.returncode or 1
    print("Locked Chromium executable and system libraries are available", flush=True)
    return 0


def report_state(report):
    try:
        root = ET.parse(report).getroot()
    except FileNotFoundError:
        return "missing"
    except (ET.ParseError, OSError):
        return "unreadable"
    return "present" if root.tag in ("testsuite", "testsuites") else "unreadable"


def publish_report(report, destination):
    state = report_state(report)
    if state == "present":
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(report, destination)
        except OSError:
            print("JUnit could not be retained", file=sys.stderr, flush=True)
            return "unretained"
    return state


def run(gate):
    root = Path.cwd()
    invocation = f"{gate}-{uuid.uuid4().hex}"
    reports = root / ".artifacts" / "ci"
    destination = reports / "junit" / f"junit-{invocation}.xml"
    environment = dict(os.environ)
    environment["UV_LINK_MODE"] = "copy"
    environment["PLAYWRIGHT_SKIP_BROWSER_GC"] = "1"
    environment["PLAYWRIGHT_BROWSERS_PATH"] = environment.get("CI_BROWSER_CACHE") or "/tmp/browsers"
    steps = []
    status = 0
    # Report generation happens in private writable invocation state, even if the
    # archive destination is unwritable. Only the XML is copied out, best effort.
    with tempfile.TemporaryDirectory(prefix="account-ci-") as temporary:
        state = Path(temporary)
        environment["TMPDIR"] = temporary
        environment["XDG_CONFIG_HOME"] = str(state / "config")
        report = state / "junit.xml"
        if gate in {"tests", "browser-tests"}:
            environment["PYTEST_ADDOPTS"] = (
                environment.get("PYTEST_ADDOPTS", "")
                + f" --junitxml={shlex.quote(str(report))}"
                + " --tb=short --show-capture=no -o junit_logging=no"
            )
        for name, argv in commands(gate):
            print(f"Running {gate}: {name}", flush=True)
            started = time.monotonic()
            result = command(argv, reports / "logs" / f"{invocation}-{name}.log", environment)
            status = result["exit_code"]
            seconds = round(time.monotonic() - started, 3)
            steps.append({"step": name, "seconds": seconds, **result})
            print(f"{gate}/{name}: exit={status}, seconds={seconds}", flush=True)
            if status:
                break
        junit = publish_report(report, destination)
    print(f"{gate}: exit={status}, JUnit={junit}", flush=True)
    diagnostics = {
        "gate": gate,
        "invocation": invocation,
        "exit_code": status,
        "junit": junit,
        "steps": steps,
    }
    save(reports / "diagnostics" / f"{invocation}.json", (json.dumps(diagnostics) + "\n").encode())
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "gate",
        choices=(
            "dependencies",
            "lint",
            "format",
            "typecheck",
            "tests",
            "whitespace",
            "browser",
            "browser-tests",
            "package",
            "wheel",
            "browser-preflight",
        ),
    )
    gate = parser.parse_args().gate
    raise SystemExit(browser_preflight() if gate == "browser-preflight" else run(gate))
