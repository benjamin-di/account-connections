import http.client
import io
import json
import ssl
import threading
import time
import traceback

import pytest

from account_connections import directory
from account_connections.people import DirectoryPerson, Identity, People
from account_connections.storage import StateError

ISSUER = "https://identity.example.com"
BASE = "https://directory.example.com/connections-directory"
KEY = "synthetic-directory-key-" * 3
IDENTITY = Identity(ISSUER, "subject_alice-1")


class Response:
    def __init__(self, body=None, *, status=200, headers=None):
        self.status = status
        self.headers = {"Content-Type": "application/json"} | (headers or {})
        self.body = (
            json.dumps({"displayName": "Alice", "disabled": False, "admitted": True}).encode()
            if body is None
            else body
        )
        self.reads = []
        self.offset = 0

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def read1(self, amount):
        self.reads.append(amount)
        chunk = self.body[self.offset : self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def isclosed(self):
        return self.offset >= len(self.body)


@pytest.fixture
def transport(monkeypatch):
    instances = []

    class Connection:
        response = Response()
        failure = None

        def __init__(self, host, port, **kwargs):
            self.host = host
            self.port = port
            self.kwargs = kwargs
            self.requests = []
            self.closed = False
            self.sock = self
            self.socket_timeouts = []
            instances.append(self)

        def connect(self):
            pass

        def settimeout(self, timeout):
            self.socket_timeouts.append(timeout)

        def request(self, *args, **kwargs):
            self.requests.append((args, kwargs))
            if self.failure:
                raise self.failure

        def getresponse(self):
            return self.response

        def close(self):
            self.closed = True

    monkeypatch.setattr(directory.http.client, "HTTPSConnection", Connection)
    return Connection, instances


def lookup(**kwargs):
    return directory.ExactSubjectDirectory(
        **({"issuer": ISSUER, "base_url": BASE, "api_key": KEY} | kwargs)
    )


@pytest.mark.parametrize(
    "framing,trailing,accepted",
    [
        ("Transfer-Encoding: chunked\r\n", b"", True),
        ("Transfer-Encoding: chunked\r\n", b"TRAIL", False),
        ("Transfer-Encoding: chunked\r\nContent-Length: {size}\r\n", b"TRAIL", False),
        ("Transfer-Encoding: gzip\r\n", b"", False),
        ("Transfer-Encoding: gzip, chunked\r\n", b"", False),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", b"", False),
    ],
)
def test_real_http_response_framing(transport, framing, trailing, accepted):
    body = json.dumps({"displayName": "Alice", "disabled": False, "admitted": True}).encode()
    chunks = f"{len(body):x}\r\n".encode() + body + b"\r\n"
    if trailing:
        chunks += f"{len(trailing):x}\r\n".encode() + trailing + b"\r\n"
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + framing.format(size=len(body)).encode()
        + b"\r\n"
        + chunks
        + b"0\r\n\r\n"
    )

    class Socket:
        def makefile(self, *args):
            return io.BytesIO(wire)

    response = http.client.HTTPResponse(Socket())
    response.begin()
    connection, _ = transport
    connection.response = response
    if accepted:
        assert lookup()(IDENTITY) == DirectoryPerson(True, "Alice")
    else:
        with pytest.raises(directory.DirectoryUnavailable, match="^directory_unavailable$"):
            lookup()(IDENTITY)


def test_exact_subject_uses_direct_verified_https_and_scoped_key(transport, monkeypatch):
    _, instances = transport
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid:8443")
    monkeypatch.setenv("ALL_PROXY", "https://proxy.invalid:8443")
    client = lookup()
    assert client(IDENTITY) == DirectoryPerson(True, "Alice")
    connection = instances[0]
    assert (connection.host, connection.port) == ("directory.example.com", 443)
    assert 0 < connection.kwargs["timeout"] <= 3.0
    assert all(0 < timeout <= 3.0 for timeout in connection.socket_timeouts)
    context = connection.kwargs["context"]
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert connection.requests == [
        (
            ("GET", "/connections-directory/users/subject_alice-1"),
            {"headers": {"X-API-Key": KEY, "Accept": "application/json"}},
        )
    ]
    assert connection.closed
    assert repr(client) == "<ExactSubjectDirectory>"
    assert KEY not in repr(client) and ISSUER not in repr(client)


def test_fixed_origin_prefix_port_and_trailing_slash(transport):
    _, instances = transport
    assert lookup(base_url="https://directory.example.com:8443/")(IDENTITY).admitted
    assert instances[0].port == 8443
    assert instances[0].requests[0][0] == ("GET", "/users/subject_alice-1")


@pytest.mark.parametrize(
    "subject",
    ["", "a" * 201, "../bob", "alice/bob", "alice%2fbob", "alice?x=1", "alice#x", "é", "a\n"],
)
def test_invalid_subject_never_creates_connection(transport, subject):
    _, instances = transport
    identity = Identity(ISSUER, "temporary")
    object.__setattr__(identity, "subject", subject)
    assert lookup()(identity) == DirectoryPerson(False)
    assert instances == []


def test_different_issuer_and_nonidentity_never_create_connection(transport):
    _, instances = transport
    assert lookup()(Identity(ISSUER + "/", IDENTITY.subject)) == DirectoryPerson(False)
    assert lookup()(None) == DirectoryPerson(False)
    assert instances == []


@pytest.mark.parametrize(
    "url",
    [
        "http://directory.example.com",
        "https://user:password@directory.example.com",
        "https://directory.example.com?client=other",
        "https://directory.example.com#fragment",
        "https://directory.example.com/../other",
        "https://directory.example.com/%2fother",
        "https://directory.example.com//other",
        "https://directory.example.com//",
        "https://directory.example.com:0",
        "https://directory.example.com:65536",
        "https://directory.example.com:bad",
        "https://directory.example.com:",
        "https://directory.example.com\n",
        "https://directory.example.com\\other",
        "https://.example.com",
        "https://example..com",
        "https://-example.com",
    ],
)
def test_malformed_configuration_is_rejected_without_echoing_values(url):
    for option in ("issuer", "base_url"):
        with pytest.raises(ValueError, match="^invalid directory configuration$"):
            lookup(**{option: url})


@pytest.mark.parametrize(
    "options",
    [
        {"api_key": "short"},
        {"api_key": KEY + "\r\nInjected: header"},
        {"api_key": KEY + " "},
        {"api_key": KEY + "é"},
        {"api_key": "x" * 4097},
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": 31},
        {"timeout": True},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"timeout": 10**400},
        {"max_bytes": 255},
        {"max_bytes": 65537},
        {"max_bytes": True},
        {"max_in_flight": 0},
        {"max_in_flight": 33},
        {"max_in_flight": True},
    ],
)
def test_invalid_key_timeout_and_body_limits_fail_configuration(options):
    with pytest.raises(ValueError, match="^invalid directory configuration$"):
        lookup(**options)


@pytest.mark.parametrize("admitted,disabled", [(True, True), (False, False), (False, True)])
def test_only_exact_admitted_and_not_disabled_is_positive(transport, admitted, disabled):
    connection, _ = transport
    connection.response = Response(
        json.dumps({"displayName": "Alice", "disabled": disabled, "admitted": admitted}).encode()
    )
    assert lookup()(IDENTITY) == DirectoryPerson(False, "Alice")


def test_unknown_subject_is_denial_without_reading_error_body(transport):
    connection, instances = transport
    response = connection.response = Response(b"private error content", status=404)
    assert lookup()(IDENTITY) is None
    assert not response.reads
    assert instances[0].closed


@pytest.mark.parametrize("status", [201, 204, 301, 302, 307, 308, 400, 401, 403, 429, 500, 503])
def test_redirect_auth_failure_and_outage_never_follow_or_return_remote_body(transport, status):
    connection, instances = transport
    response = connection.response = Response(
        b"sensitive error", status=status, headers={"Location": "https://other.invalid/users/other"}
    )
    with pytest.raises(directory.DirectoryUnavailable, match="^directory_unavailable$"):
        lookup()(IDENTITY)
    assert len(instances) == 1 and len(instances[0].requests) == 1
    assert not response.reads and instances[0].closed


@pytest.mark.parametrize(
    "body",
    [
        b"not JSON",
        b"\xff",
        b"[]",
        b"null",
        b'{"displayName":"Alice","disabled":false,"admitted":false,"admitted":true}',
        b'{"displayName":"Alice","admitted":true}',
        b'{"displayName":"Alice","disabled":false,"admitted":true,"email":"private"}',
        b'{"displayName":"Alice","disabled":0,"admitted":true}',
        b'{"displayName":"Alice","disabled":false,"admitted":1}',
        b'{"displayName":"Alice","disabled":false,"admitted":"true"}',
        b'{"displayName":null,"disabled":false,"admitted":true}',
        b'{"displayName":7,"disabled":false,"admitted":true}',
        json.dumps({"displayName": "a" * 2049, "disabled": False, "admitted": True}).encode(),
        json.dumps({"displayName": "Alice\nprivate", "disabled": False, "admitted": True}).encode(),
        json.dumps({"displayName": "Alice\u200b", "disabled": False, "admitted": True}).encode(),
    ],
)
def test_malformed_schema_duplicate_fields_and_labels_are_unavailable(transport, body):
    connection, instances = transport
    connection.response = Response(body)
    with pytest.raises(directory.DirectoryUnavailable, match="^directory_unavailable$"):
        lookup()(IDENTITY)
    assert instances[0].closed


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/html"},
        {"Content-Type": "application/json; charset=latin-1"},
        {"Content-Type": "application/json, application/json"},
        {"Content-Encoding": "gzip"},
        {"Content-Encoding": "deflate"},
        {"Content-Length": "8193"},
        {"Content-Length": "-1"},
        {"Content-Length": "NaN"},
        {"Content-Length": "999999999999999999999999"},
    ],
)
def test_invalid_headers_and_oversized_declared_body_refuse_before_read(transport, headers):
    connection, _ = transport
    response = connection.response = Response(headers=headers)
    with pytest.raises(directory.DirectoryUnavailable):
        lookup()(IDENTITY)
    assert not response.reads


def test_undeclared_oversized_body_is_bounded(transport):
    connection, _ = transport
    response = connection.response = Response(b" " * 9000)
    with pytest.raises(directory.DirectoryUnavailable):
        lookup()(IDENTITY)
    assert response.reads == [4096, 4096, 1]


def test_truncated_declared_body_refuses_even_if_partial_body_is_valid_json(transport):
    connection, _ = transport
    connection.response = Response(headers={"Content-Length": "999"})
    with pytest.raises(directory.DirectoryUnavailable):
        lookup()(IDENTITY)


def test_utf8_content_type_and_empty_display_name_are_allowed(transport):
    connection, _ = transport
    connection.response = Response(
        b'{"displayName":"","disabled":false,"admitted":true}',
        headers={"Content-Type": 'application/json; charset="UTF-8"'},
    )
    assert lookup()(IDENTITY) == DirectoryPerson(True, "")


def test_transport_exceptions_are_sanitized_and_connections_closed(transport):
    connection, instances = transport
    connection.failure = TimeoutError(KEY + IDENTITY.subject + "remote body")
    with pytest.raises(directory.DirectoryUnavailable) as error:
        lookup()(IDENTITY)
    diagnostic = "".join(traceback.format_exception(error.value))
    assert KEY not in diagnostic and IDENTITY.subject not in diagnostic
    assert "remote body" not in diagnostic
    assert instances[0].closed


def test_each_lookup_is_uncached_and_uses_a_new_connection(transport):
    connection, instances = transport
    client = lookup()
    assert client(IDENTITY).admitted
    connection.response = Response(b'{"displayName":"Alice","disabled":true,"admitted":true}')
    assert not client(IDENTITY).admitted
    assert len(instances) == 2 and all(item.closed for item in instances)


def test_stalled_resolver_has_finite_caller_deadline_and_bounded_capacity(transport, monkeypatch):
    connection, instances = transport
    resolving = threading.Event()
    resolved = threading.Event()
    closed = threading.Event()

    def connect(self):
        resolving.set()
        resolved.wait(5)  # Synthetic resolver ignores the socket timeout.

    def close(self):
        self.closed = True
        closed.set()

    monkeypatch.setattr(connection, "connect", connect)
    monkeypatch.setattr(connection, "close", close)
    client = lookup(timeout=0.1, max_in_flight=1)
    failures = []
    slot_released = threading.Event()
    real_release = client._slots.release

    def release_slot():
        real_release()
        slot_released.set()

    monkeypatch.setattr(client._slots, "release", release_slot)

    def caller():
        try:
            client(IDENTITY)
        except directory.DirectoryUnavailable as error:
            failures.append(str(error))

    caller_thread = threading.Thread(target=caller)
    try:
        caller_thread.start()
        assert resolving.wait(1)
        caller_thread.join(1)
        assert not caller_thread.is_alive()
        assert failures == ["directory_unavailable"]
        assert len(instances) == 1
        assert instances[0].requests == []
        # Repeated calls while DNS remains stuck create no further workers.
        for _ in range(20):
            with pytest.raises(directory.DirectoryUnavailable):
                client(IDENTITY)
        assert len(instances) == 1
    finally:
        resolved.set()
        caller_thread.join(1)
    assert closed.wait(1) and slot_released.wait(1)
    assert instances[0].requests == []  # Late resolution sends no scoped key.


def test_slow_body_obeys_deadline_and_late_positive_result_is_discarded(transport, monkeypatch):
    connection, instances = transport
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class SlowResponse(Response):
        def read1(self, amount):
            entered.set()
            release.wait(5)
            return super().read1(amount)

    response = connection.response = SlowResponse()
    real_close = connection.close

    def close(self):
        real_close(self)
        finished.set()

    monkeypatch.setattr(connection, "close", close)
    client = lookup(timeout=0.1, max_in_flight=1)
    failures = []
    slot_released = threading.Event()
    real_release = client._slots.release

    def release_slot():
        real_release()
        slot_released.set()

    monkeypatch.setattr(client._slots, "release", release_slot)

    def caller():
        try:
            client(IDENTITY)
        except directory.DirectoryUnavailable as error:
            failures.append(str(error))

    caller_thread = threading.Thread(target=caller)
    try:
        caller_thread.start()
        assert entered.wait(1)
        caller_thread.join(1)
        assert not caller_thread.is_alive() and failures == ["directory_unavailable"]
        with pytest.raises(directory.DirectoryUnavailable):
            client(IDENTITY)
        assert len(instances) == 1
    finally:
        release.set()
        caller_thread.join(1)
    assert finished.wait(1) and slot_released.wait(1) and response.reads
    # A later negative response must be observed; the expired positive is not cached.
    connection.response = Response(b'{"displayName":"Alice","disabled":true,"admitted":true}')
    assert not client(IDENTITY).admitted
    assert len(instances) == 2


def test_trickle_reads_shrink_socket_budget_and_do_not_extend_caller_deadline(transport):
    connection, instances = transport

    class TrickleResponse(Response):
        def read1(self, amount):
            time.sleep(0.01)
            return super().read1(1)

    connection.response = TrickleResponse()
    started = time.monotonic()
    with pytest.raises(directory.DirectoryUnavailable):
        lookup(timeout=0.05)(IDENTITY)
    assert time.monotonic() - started < 1
    timeouts = instances[0].socket_timeouts
    assert len(timeouts) > 2
    assert all(later <= earlier for earlier, later in zip(timeouts, timeouts[1:], strict=False))


def test_thread_start_failure_releases_capacity_and_redacts_error(transport, monkeypatch):
    client = lookup(max_in_flight=1)

    def fail(_self):
        raise RuntimeError(KEY)

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", fail)
        with pytest.raises(directory.DirectoryUnavailable) as error:
            client(IDENTITY)
        assert KEY not in "".join(traceback.format_exception(error.value))
    assert client(IDENTITY).admitted


def test_unavailability_preserves_active_authority_and_denial_does_not_readmit(tmp_path, transport):
    connection, _ = transport
    people = People(tmp_path / "authority")
    people.contact("alice", namespaces=["shop"], identity=IDENTITY, explicit=True)
    people.directory = lookup()
    connection.response = Response(status=503)
    with pytest.raises(StateError, match="directory_unavailable"):
        people.refresh("alice")
    people.require_admitted("alice")
    connection.response = Response(b'{"displayName":"Alice","disabled":false,"admitted":false}')
    with pytest.raises(StateError, match="person_inactive"):
        people.refresh("alice")
    with pytest.raises(StateError, match="person_inactive"):
        people.require_admitted("alice")
    connection.response = Response()
    people.refresh("alice")
    with pytest.raises(StateError, match="person_inactive"):
        people.require_admitted("alice")
