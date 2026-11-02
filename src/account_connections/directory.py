"""Optional, bounded exact-subject directory transport; no discovery or cache."""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import json
import math
import re
import ssl
import threading
import time
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from .people import DirectoryPerson, Identity

_SUBJECT = re.compile(r"[A-Za-z0-9_-]{1,200}\Z")
_PREFIX = re.compile(r"(?:/[A-Za-z0-9_-]+)*\Z")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class DirectoryUnavailable(Exception):
    """A fixed, non-sensitive failure; hosts keep directory admission closed."""

    def __init__(self) -> None:
        super().__init__("directory_unavailable")


def _location(value: str) -> tuple[str, int, str]:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or not value.startswith("https://")
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
        or any(char in value for char in ("?", "#", "@", "\\", "%"))
    ):
        raise ValueError("invalid directory configuration")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = 443 if parts.port is None else parts.port
        prefix = parts.path.rstrip("/")
        if (
            not host
            or not 1 <= port <= 65535
            or parts.netloc.endswith(":")
            or not _PREFIX.fullmatch(prefix)
            or parts.path not in (prefix, prefix + "/")
        ):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(_HOST_LABEL.fullmatch(p) for p in host.split(".")):
                raise ValueError from None
        return host, port, prefix
    except ValueError:
        raise ValueError("invalid directory configuration") from None


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class ExactSubjectDirectory:
    """Bind one scoped directory key to one verified issuer.

    ``base_url`` is a fixed HTTPS origin with an optional canonical route prefix.
    The only request is ``GET <prefix>/users/<subject>``. Subjects use the directory
    protocol's raw ASCII identifier alphabet; they are never URL-encoded.

    ``timeout`` bounds caller latency, including resolution and slow responses.
    Stalled operations retain one of a finite number of daemon-worker slots;
    capacity exhaustion fails immediately. Late results are discarded.
    """

    def __init__(
        self,
        *,
        issuer: str,
        base_url: str,
        api_key: str,
        timeout: float = 3.0,
        max_bytes: int = 8192,
        max_in_flight: int = 4,
    ) -> None:
        _location(issuer)
        self._host, self._port, self._prefix = _location(base_url)
        if (
            not isinstance(api_key, str)
            or not 32 <= len(api_key) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in api_key)
            or type(timeout) not in (int, float)
            or not 0 < timeout <= 30
            or not math.isfinite(timeout)
            or type(max_bytes) is not int
            or not 256 <= max_bytes <= 65536
            or type(max_in_flight) is not int
            or not 1 <= max_in_flight <= 32
        ):
            raise ValueError("invalid directory configuration")
        self._issuer = issuer
        self._api_key = api_key
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._slots = threading.BoundedSemaphore(max_in_flight)
        self._tls = ssl.create_default_context()

    def __repr__(self) -> str:
        return "<ExactSubjectDirectory>"

    def __call__(self, identity: Identity) -> DirectoryPerson | None:
        if (
            not isinstance(identity, Identity)
            or identity.issuer != self._issuer
            or not isinstance(identity.subject, str)
            or not _SUBJECT.fullmatch(identity.subject)
        ):
            return DirectoryPerson(False)
        subject = identity.subject
        deadline = time.monotonic() + self._timeout
        if not self._slots.acquire(blocking=False):
            raise DirectoryUnavailable()
        completed = threading.Event()
        result: list[DirectoryPerson | None] = []

        def worker() -> None:
            try:
                # The worker never logs remote failure details.
                with contextlib.suppress(Exception):
                    verdict = self._lookup(subject, deadline)
                    if time.monotonic() < deadline:
                        result.append(verdict)
            finally:
                self._slots.release()
                completed.set()

        try:
            threading.Thread(target=worker, name="directory-lookup", daemon=True).start()
        except Exception:
            self._slots.release()
            raise DirectoryUnavailable() from None
        if (
            not completed.wait(max(0, deadline - time.monotonic()))
            or time.monotonic() >= deadline
            or not result
        ):
            raise DirectoryUnavailable()
        return result[0]

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DirectoryUnavailable()
        return remaining

    def _lookup(self, subject: str, deadline: float) -> DirectoryPerson | None:
        connection = None
        try:
            connection = http.client.HTTPSConnection(
                self._host, self._port, timeout=self._remaining(deadline), context=self._tls
            )
            # Resolve/connect before sending credentials. A resolver returning
            # after the deadline must never initiate an authenticated request.
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise DirectoryUnavailable()
            sock.settimeout(self._remaining(deadline))
            # HTTPSConnection connects directly: environment proxies, redirects,
            # cookies and ambient authentication are deliberately never used.
            connection.request(
                "GET",
                self._prefix + "/users/" + subject,
                headers={"X-API-Key": self._api_key, "Accept": "application/json"},
            )
            sock.settimeout(self._remaining(deadline))
            response = connection.getresponse()
            self._remaining(deadline)
            if response.status == 404:
                return None
            if response.status != 200:
                raise DirectoryUnavailable()
            content_type = response.getheader("Content-Type", "").split(";")
            if content_type[0].strip().lower() != "application/json" or any(
                parameter.strip().lower() not in ("charset=utf-8", 'charset="utf-8"')
                for parameter in content_type[1:]
            ):
                raise DirectoryUnavailable()
            if response.getheader("Content-Encoding", "identity").strip().lower() != "identity":
                raise DirectoryUnavailable()
            length = response.getheader("Content-Length")
            transfer = response.getheader("Transfer-Encoding")
            # HTTPResponse prioritizes chunked framing over Content-Length.
            # Never let a conflicting length truncate the JSON we validate.
            if transfer is not None and (transfer.lower() != "chunked" or length is not None):
                raise DirectoryUnavailable()
            if length is not None and (
                not re.fullmatch(r"[0-9]{1,6}", length) or int(length) > self._max_bytes
            ):
                raise DirectoryUnavailable()
            chunks = []
            size = 0
            while not response.isclosed():
                sock.settimeout(self._remaining(deadline))
                chunk = response.read1(min(4096, self._max_bytes + 1 - size))
                self._remaining(deadline)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > self._max_bytes or length is not None and size == int(length):
                    break
            body = b"".join(chunks)
            if len(body) > self._max_bytes or length is not None and len(body) != int(length):
                raise DirectoryUnavailable()
            result = json.loads(body.decode("utf-8"), object_pairs_hook=_unique)
            if (
                not isinstance(result, dict)
                or set(result) != {"displayName", "disabled", "admitted"}
                or type(result["disabled"]) is not bool
                or type(result["admitted"]) is not bool
                or not isinstance(result["displayName"], str)
                or len(result["displayName"]) > 2048
                or any(unicodedata.category(c).startswith("C") for c in result["displayName"])
            ):
                raise DirectoryUnavailable()
            return DirectoryPerson(
                admitted=result["admitted"] is True and result["disabled"] is False,
                label=result["displayName"],
            )
        except Exception:
            # HTTP/parser failures can contain URLs, identities, headers or a
            # response. Never let their messages cross the directory seam.
            raise DirectoryUnavailable() from None
        finally:
            if connection is not None:
                # Cleanup must not disclose remote exception text.
                with contextlib.suppress(Exception):
                    connection.close()
