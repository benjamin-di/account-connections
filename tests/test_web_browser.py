"""Real HTML submissions through the generic router, with synthetic browser auth."""

import contextlib
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.testclient import TestClient

from account_connections.people import People, Policy
from account_connections.web import Hooks, routes

playwright = pytest.importorskip("playwright.sync_api")


@contextlib.contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def test_browser_forms_keep_exact_origin_and_cross_origin_navigation_has_no_referrer(tmp_path):
    calls, submissions, foreign_visits = [], [], []
    client = None

    class Auth:
        def identity(self, request):
            if request.cookies.get("session") == "synthetic-alice":
                return {"issuer": "https://identity.example.com", "sub": "alice-sub"}
            return None

        def require_fresh(self, request, **kwargs):
            return None if request.cookies.get("fresh") == "1" else Response(status_code=403)

        def refused(self, request):
            return Response(status_code=403)

        def step_up_url(self, next=None):
            return "/connections/login?reauth=1"

    class QuietHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

    class Router(QuietHandler):
        def handle_request(self):
            assert client is not None
            if self.command == "POST":
                submissions.append(self.headers.get("Origin"))
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            response = client.request(
                self.command, self.path, headers=dict(self.headers), content=body
            )
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.content)

        do_GET = do_POST = handle_request

    class Foreign(QuietHandler):
        def do_GET(self):
            foreign_visits.append(self.headers.get("Referer"))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                f'<form method="post" action="{origin}/connections/start">'
                '<input name="namespace" value="example"><button>Forged connect</button>'
                "</form>".encode()
            )

    people = People(tmp_path / "authority")
    people.enroll("alice", namespaces=["example"])

    async def start(request, owner, namespace, form):
        calls.append((owner, namespace))
        return Response("Provider action reached")

    with serve(Router) as origin, serve(Foreign) as foreign:
        hooks = Hooks(
            actor=lambda identity: "alice",
            namespaces=lambda person: ["example"],
            policy=lambda namespace: Policy("1", frozenset({"cart"})),
            actions={"start": start},
            render_namespace=lambda owner, namespace: (
                '<form method="post" action="/connections/start">'
                '<input name="namespace" value="example"><button>Connect</button></form>'
                f'<a href="{foreign}/outside">External destination</a>'
            ),
        )
        with (
            TestClient(
                Starlette(routes=routes(people, Auth(), hooks, origin=origin)),
                base_url=origin,
                follow_redirects=False,
            ) as client,
            playwright.sync_playwright() as driver,
        ):
            browser = driver.chromium.launch(
                executable_path=os.environ.get("CONNECTIONS_TEST_BROWSER"),
                args=["--no-sandbox", "--disable-background-networking"],
            )
            try:
                context = browser.new_context()
                context.add_cookies(
                    [
                        {"name": "session", "value": "synthetic-alice", "url": origin},
                        {"name": "fresh", "value": "1", "url": origin},
                    ]
                )
                page = context.new_page()
                page.goto(origin + "/connections/")
                page.get_by_role("button", name="Connect", exact=True).click()
                assert submissions == [origin]
                assert calls == [("alice", "example")]
                assert page.locator("body").inner_text() == "Provider action reached"

                page.goto(origin + "/connections/")
                page.get_by_role("link", name="External destination").click()
                assert foreign_visits == [None]
                page.get_by_role("button", name="Forged connect").click()
                assert submissions == [origin, foreign]
                assert calls == [("alice", "example")]
                assert page.locator("body").inner_text() != "Provider action reached"
            finally:
                browser.close()
