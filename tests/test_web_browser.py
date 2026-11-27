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


@pytest.mark.parametrize("javascript", [True, False])
@pytest.mark.parametrize("action_label", ["Connect", "Continue sign-in", "Confirm account"])
def test_provider_actions_are_visible_and_keep_origin_and_referrer(
    tmp_path, javascript, action_label
):
    calls, submissions, foreign_visits = [], [], []
    client = None

    class Auth:
        def identity(self, request):
            if request.cookies.get("session") == "synthetic-alice":
                return {"issuer": "https://identity.example.com", "sub": "alice-sub"}
            return None

        def refused(self, request):
            return Response(status_code=403)

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

    from account_connections.controls import Controls

    controls = Controls(people)
    attempt = controls.begin("alice", "example")
    if action_label == "Connect":
        # An adopter can retain an active control without a saved provider session.
        controls.publish("alice", "example", attempt, lambda: None, require_staged=False)

    async def start(request, owner, namespace, form):
        calls.append((owner, namespace))
        return Response("Provider action reached")

    with serve(Router) as origin, serve(Foreign) as foreign:
        hooks = Hooks(
            actor=lambda identity: "alice",
            namespaces=lambda person: ["example"],
            policy=lambda namespace: Policy("1", frozenset({"cart"})),
            actions={"start": start},
            connection_ready=lambda owner, namespace: False,
            render_namespace=lambda owner, namespace: (
                '<form method="post" action="/connections/start">'
                f'<input name="namespace" value="example"><button>{action_label}</button></form>'
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
                context = browser.new_context(java_script_enabled=javascript)
                context.add_cookies(
                    [
                        {"name": "session", "value": "synthetic-alice", "url": origin},
                    ]
                )
                page = context.new_page()
                page.goto(origin + "/connections/")
                assert page.get_by_role("button", name=action_label, exact=True).is_visible()
                assert "Disconnecting example removes" not in page.locator("article").inner_text()
                assert page.locator("main").count() == 1
                assert page.locator("article").count() == 1
                assert "system-ui" in page.locator("body").evaluate(
                    "el => getComputedStyle(el).fontFamily"
                )
                assert (
                    float(
                        page.get_by_role("button", name=action_label, exact=True)
                        .evaluate("el => getComputedStyle(el).minHeight")
                        .removesuffix("px")
                    )
                    >= 44
                )
                page.get_by_role("button", name=action_label, exact=True).click()
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


@pytest.fixture
def management_browser(tmp_path):
    from signin_window.connections import disconnect_confirmation

    from account_connections.controls import Controls
    from account_connections.people import Identity

    people = People(tmp_path / "authority")
    for person in ("alice", "bob"):
        people.enroll(person, namespaces=["example"])
        people.bind(person, Identity("https://identity.example.com", person + "-sub"), name=person)
    people.bind(
        "bob", Identity("https://identity.example.com", "bob-sub"), name='<Bob> & "Example"'
    )
    controls = Controls(people)
    for person in ("alice", "bob"):
        attempt = controls.begin(person, "example")
        controls.publish(person, "example", attempt, lambda: None, require_staged=False)
    policy = Policy("1", frozenset({"cart", "orders", "financial"}))
    prefix = "/workspace/accounts"
    calls, submissions, violations = [], [], []
    client = None

    class Auth:
        def identity(self, request):
            person = request.cookies.get("actor")
            if person in {"alice", "bob"}:
                return {
                    "issuer": "https://identity.example.com",
                    "sub": person + "-sub",
                    "label": person,
                }
            return None

        def refused(self, request):
            return Response("Sign in again", status_code=403 if self.identity(request) else 401)

    class Router(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_request(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.command == "POST":
                submissions.append((self.path, self.headers.get("Origin"), body))
            response = client.request(
                self.command, self.path, headers=dict(self.headers), content=body
            )
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.content)

        do_GET = do_POST = handle_request

    def render(owner, namespace):
        revision = controls.status(owner, namespace)["revision"]
        fields = (
            '<input name="namespace" value="example">'
            f'<input name="control_revision" value="{revision}">'
        )
        return (
            f'<form method="post" action="{prefix}/reconnect">{fields}'
            "<button>Reconnect example</button></form>"
            + disconnect_confirmation(
                f'<form method="post" action="{prefix}/disconnect">{fields}'
                "<button>Confirm disconnect</button></form>",
                "example",
                "Remove saved provider credentials and stop shared access.",
            )
        )

    async def provider(request, owner, namespace, form):
        if form["control_revision"] != controls.status(owner, namespace)["revision"]:
            return Response("Changed", status_code=409)
        calls.append((owner, namespace, request.url.path))
        if request.url.path.endswith("/disconnect"):
            controls.disconnect(owner, namespace, lambda: None)
        return Response("Existing provider flow")

    hooks = Hooks(
        actor=lambda identity: identity["sub"].removesuffix("-sub"),
        namespaces=lambda person: ["example"],
        policy=lambda namespace: policy,
        default_capabilities=lambda namespace: frozenset({"cart"}),
        capability_labels=lambda namespace: {
            "cart": "Basket",
            "orders": "Order history",
            "financial": "Financial records",
        },
        actions={"reconnect": provider, "disconnect": provider},
        render_namespace=render,
    )
    with serve(Router) as origin:
        client = TestClient(
            Starlette(routes=routes(people, Auth(), hooks, origin=origin, prefix=prefix)),
            base_url=origin,
            follow_redirects=False,
        )
        with playwright.sync_playwright() as driver:
            browser = driver.chromium.launch(
                executable_path=os.environ.get("CONNECTIONS_TEST_BROWSER"),
                args=["--no-sandbox", "--disable-background-networking"],
            )
            try:
                yield (
                    people,
                    controls,
                    policy,
                    browser,
                    origin,
                    prefix,
                    calls,
                    submissions,
                    violations,
                )
            finally:
                browser.close()
                client.close()


@pytest.mark.parametrize("width,theme", [(320, "light"), (390, "dark"), (1024, "light")])
def test_complete_share_edit_revoke_dialog_with_keyboard_and_scopes(
    management_browser, width, theme
):
    people, _, _, browser, origin, prefix, _, submissions, _ = management_browser
    context = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=theme)
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.add_init_script(
        "document.addEventListener('securitypolicyviolation', "
        "e => console.error('CSP:' + e.violatedDirective))"
    )
    page.on(
        "console", lambda message: errors.append(message.text) if message.type == "error" else None
    )
    page.goto(origin + prefix + "/")
    assert page.locator("section.panel.hero").count() == 1
    assert page.locator("article[data-namespace='example']").count() == 1
    opener = page.locator("#share-0-new > summary")
    opener.focus()
    page.keyboard.press("Enter")
    dialog = page.get_by_role("dialog")
    assert dialog.is_visible()
    picker = dialog.get_by_label("Person", exact=True)
    assert picker.evaluate("el => el === document.activeElement")
    assert picker.input_value() == ""
    assert dialog.get_by_role("button", name="Share access", exact=True).is_disabled()
    assert picker.locator("option").all_text_contents() == ["Choose a person", '<Bob> & "Example"']
    picker.select_option("bob")
    assert dialog.get_by_label("Basket", exact=True).is_checked()
    assert not dialog.get_by_label("Order history", exact=True).is_checked()
    assert "Financial records" not in dialog.locator(".share-summary").inner_text()
    dialog.locator(".people-help > summary").click()
    dialog.get_by_role("button", name="Refresh list", exact=True).click()
    assert dialog.get_by_label("Basket", exact=True).is_checked()
    assert picker.input_value() == "bob"
    page.once("dialog", lambda prompt: prompt.dismiss())
    page.keyboard.press("Escape")
    assert dialog.is_visible()  # Unsaved choices survive cancelling dismissal.
    dialog.get_by_role("button", name='Share with <Bob> & "Example"', exact=True).click()
    playwright.expect(dialog).not_to_be_visible()
    playwright.expect(page.get_by_role("status")).to_contain_text("can now choose example")
    assert people.namespace("alice", "example")["shares"]["bob"]["capabilities"] == ["cart"]
    assert page.locator("article").evaluate("el => el === document.activeElement")
    page.get_by_text('Edit access for <Bob> & "Example"', exact=True).click()
    assert dialog.locator("select").count() == 0
    assert dialog.locator("[data-save]").is_disabled()
    dialog.get_by_label("Basket", exact=True).uncheck()
    dialog.get_by_label("Order history", exact=True).check()
    assert "choose the account again" in dialog.locator("[data-reselection]").inner_text()
    dialog.locator("[data-save]").click()
    playwright.expect(dialog).not_to_be_visible()
    assert people.namespace("alice", "example")["shares"]["bob"]["capabilities"] == ["orders"]
    page.get_by_text('Edit access for <Bob> & "Example"', exact=True).click()
    dialog.get_by_role("button", name='Stop sharing with <Bob> & "Example"', exact=True).click()
    playwright.expect(dialog).not_to_be_visible()
    assert people.namespace("alice", "example")["shares"] == {}
    assert len(submissions) == 3 and all(item[1] == origin for item in submissions)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    opener = page.locator("#share-0-new > summary")
    opener.click()
    dialog.get_by_role("button", name="Close", exact=True).click()
    assert opener.evaluate("el => el === document.activeElement")
    assert not errors
    context.close()


def test_stale_dialog_keeps_choices_and_never_retries_an_uncertain_write(management_browser):
    people, controls, _, browser, origin, prefix, _, submissions, _ = management_browser
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("Person", exact=True).select_option("bob")
    dialog.get_by_label("Order history", exact=True).check()
    controls.begin("alice", "example")
    dialog.locator("[data-save]").click()
    playwright.expect(dialog.get_by_role("alert")).to_contain_text("changed")
    assert dialog.is_visible()
    assert dialog.get_by_label("Person", exact=True).input_value() == "bob"
    assert dialog.get_by_label("Order history", exact=True).is_checked()
    assert dialog.locator("[data-save]").is_disabled()
    assert len(submissions) == 1 and people.namespace("alice", "example")["shares"] == {}
    context.close()


def test_no_script_form_and_refresh_keep_explicit_choices(management_browser):
    people, _, _, browser, origin, prefix, _, _, _ = management_browser
    context = browser.new_context(java_script_enabled=False)
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    form = page.locator("#share-0-new-form")
    form.get_by_label("Person", exact=True).select_option("bob")
    form.get_by_label("Basket", exact=True).uncheck()
    form.get_by_label("Order history", exact=True).check()
    form.locator(".people-help > summary").click()
    form.get_by_role("button", name="Refresh list", exact=True).click()
    assert form.get_by_label("Order history", exact=True).is_checked()
    assert not form.get_by_label("Basket", exact=True).is_checked()
    assert form.get_by_label("Person", exact=True).input_value() == "bob"
    summary = form.locator(".share-summary").inner_text()
    assert '<Bob> & "Example"' in summary
    assert "Order history" in summary and "Basket" not in summary
    form.get_by_label("Order history", exact=True).uncheck()
    assert "no permissions" in form.locator(".share-summary").inner_text()
    form.get_by_label("Financial records", exact=True).check()
    summary = form.locator(".share-summary").inner_text()
    assert "Financial records" in summary and "Order history" not in summary
    form.locator("[data-save]").click()
    assert page.url == origin + prefix + "/"
    assert people.namespace("alice", "example")["shares"]["bob"]["capabilities"] == ["financial"]
    context.close()


def test_incoming_revision_change_leave_and_owned_provider_flows(management_browser):
    people, controls, policy, browser, origin, prefix, calls, _, _ = management_browser
    grant = people.offer(
        "alice", "example", "bob", policy=policy, capabilities=frozenset({"cart"}), expected=None
    )
    people.select(
        "bob",
        "example",
        "alice",
        policy=policy,
        expected=people.namespace("bob", "example")["selection"]["revision"],
        grant_revision=grant.revision,
    )
    people.offer(
        "alice",
        "example",
        "bob",
        policy=policy,
        capabilities=frozenset({"orders"}),
        expected=grant.revision,
    )
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "bob", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    assert page.get_by_text("Access changed. Choose this account again.", exact=True).count() == 1
    page.get_by_role("button", name="Use this account again", exact=True).click()
    playwright.expect(page.get_by_role("status")).to_contain_text("selection updated")
    assert people.selected("bob", "example", policy=policy)[0].choice.owner == "alice"
    page.get_by_role("button", name="Leave account", exact=True).click()
    playwright.expect(page.get_by_role("status")).to_contain_text("owner must share again")
    assert people.namespace("bob", "example")["selection"]["choice"] is None
    assert people.namespace("alice", "example")["shares"] == {}
    assert (
        "Disconnecting example removes your saved provider connection"
        in page.locator("article").inner_text()
    )
    page.get_by_text("Disconnect example…", exact=True).click()
    page.get_by_role("button", name="Confirm disconnect", exact=True).click()
    assert page.locator("body").inner_text() == "Existing provider flow"
    assert controls.status("bob", "example")["state"] == "disconnected"
    assert calls == [("bob", "example", prefix + "/disconnect")]
    context.close()


def test_unknown_write_keeps_form_and_requires_an_explicit_refresh(management_browser):
    people, _, _, browser, origin, prefix, _, submissions, _ = management_browser
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("Person", exact=True).select_option("bob")
    page.route("**/share", lambda route: route.abort("failed"))
    dialog.locator("[data-save]").click()
    playwright.expect(dialog.get_by_role("alert")).to_contain_text("result is unknown")
    assert dialog.locator("[data-save]").is_disabled()
    assert dialog.get_by_label("Person", exact=True).input_value() == "bob"
    assert not submissions and people.namespace("alice", "example")["shares"] == {}
    context.close()


def test_policy_renewal_with_unchanged_permissions_is_an_explicit_save(management_browser):
    people, _, policy, browser, origin, prefix, _, _, _ = management_browser
    old = people.offer(
        "alice",
        "example",
        "bob",
        policy=Policy("0", policy.capabilities),
        capabilities=frozenset({"cart"}),
        expected=None,
    )
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-bob > summary").click()
    dialog = page.get_by_role("dialog")
    assert "access policy changed" in dialog.inner_text()
    assert dialog.locator("[data-save]").is_enabled()
    assert dialog.get_by_label("Basket", exact=True).is_checked()
    dialog.locator("[data-save]").click()
    playwright.expect(dialog).not_to_be_visible()
    updated = people.namespace("alice", "example")["shares"]["bob"]
    assert updated["policy"] == policy.version
    assert updated["revision"] != old.revision
    assert people.offers("bob", "example", policy=policy)[0][0]["grant"].capabilities == frozenset(
        {"cart"}
    )
    context.close()


@pytest.mark.parametrize("recover", [False, True])
def test_people_refresh_updates_all_availability_feedback(management_browser, recover):
    from account_connections.people import DirectoryPerson
    from account_connections.storage import StateError

    people, _, _, browser, origin, prefix, _, _, _ = management_browser

    def unavailable(identity):
        if identity.subject == "bob-sub":
            raise StateError("synthetic directory outage")
        return DirectoryPerson(True)

    def available(identity):
        return DirectoryPerson(True)

    people.directory = unavailable if recover else available
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("Order history", exact=True).check()
    revision = dialog.locator('[name="control_revision"]').input_value()
    people.directory = available if recover else unavailable
    dialog.locator(".people-help > summary").click()
    dialog.get_by_role("button", name="Refresh list", exact=True).click()
    playwright.expect(page.get_by_role("status")).to_contain_text("People list refreshed")
    feedback = dialog.locator("[data-people-feedback]")
    assert ("Some people are unavailable" in feedback.inner_text()) is (not recover)
    assert ("People couldn’t load" in feedback.inner_text()) is (not recover)
    assert (dialog.locator('select option[value="bob"]').count() == 1) is recover
    assert dialog.get_by_label("Order history", exact=True).is_checked()
    assert dialog.locator('[name="control_revision"]').input_value() == revision
    context.close()


@pytest.mark.parametrize("action", ["submit", "refresh-disconnected", "refresh-replaced"])
def test_no_script_account_race_keeps_choices_and_original_revision(management_browser, action):
    people, controls, _, browser, origin, prefix, _, submissions, _ = management_browser
    context = browser.new_context(java_script_enabled=False)
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    form = page.locator("#share-0-new-form")
    form.get_by_label("Person", exact=True).select_option("bob")
    form.get_by_label("Basket", exact=True).uncheck()
    form.get_by_label("Order history", exact=True).check()
    revision = form.locator('[name="control_revision"]').input_value()
    controls.disconnect("alice", "example", lambda: None)
    if action == "refresh-replaced":
        attempt = controls.begin("alice", "example")
        controls.publish("alice", "example", attempt, lambda: None, require_staged=False)
    if action == "submit":
        with page.expect_navigation() as navigation:
            form.locator("[data-save]").click()
        assert navigation.value.status == 409
    else:
        form.locator(".people-help > summary").click()
        form.get_by_role("button", name="Refresh list", exact=True).click()
    assert form.count() == 1
    assert page.locator("#share-0-new").get_attribute("open") is not None
    assert form.get_by_label("Person", exact=True).input_value() == "bob"
    assert form.get_by_label("Order history", exact=True).is_checked()
    assert not form.get_by_label("Basket", exact=True).is_checked()
    assert form.locator('[name="control_revision"]').input_value() == revision
    assert form.get_by_role("alert").inner_text()
    assert form.locator("[data-save]:enabled").count() == 0
    assert form.get_by_role("link", name="Refresh details before retrying").is_visible()
    assert people.namespace("alice", "example")["shares"] == {}
    assert len(submissions) == (1 if action == "submit" else 0)
    context.close()


def test_refresh_finishing_during_share_keeps_save_visibly_disabled(management_browser):
    people, _, _, browser, origin, prefix, _, submissions, _ = management_browser
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("Person", exact=True).select_option("bob")
    dialog.get_by_label("Order history", exact=True).check()
    dialog.locator(".people-help > summary").click()
    refreshes, writes = [], []
    page.route("**" + prefix + "/", lambda route: refreshes.append(route))
    page.route("**/share", lambda route: writes.append(route))
    with page.expect_request(origin + prefix + "/"):
        dialog.get_by_role("button", name="Refresh list", exact=True).click()
    with page.expect_request(origin + prefix + "/share"):
        dialog.locator("[data-save]").click()
    playwright.expect(dialog.locator("[data-save]")).to_be_disabled()
    refresh = refreshes.pop()
    refresh.fulfill(response=refresh.fetch())
    playwright.expect(page.get_by_role("status")).to_contain_text("People list refreshed")
    assert dialog.locator("[data-save]").is_disabled()
    assert dialog.get_by_role("button", name="Refresh list", exact=True).is_disabled()
    assert dialog.get_by_label("Person", exact=True).input_value() == "bob"
    assert dialog.get_by_label("Order history", exact=True).is_checked()
    assert len(writes) == 1 and not submissions
    page.unroute("**" + prefix + "/")
    writes.pop().continue_()
    playwright.expect(dialog).not_to_be_visible()
    assert len(submissions) == 1
    assert people.namespace("alice", "example")["shares"]["bob"]["capabilities"] == [
        "cart",
        "orders",
    ]
    context.close()


def test_people_refresh_clears_its_transport_error(management_browser):
    people, _, _, browser, origin, prefix, _, _, _ = management_browser
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("Person", exact=True).select_option("bob")
    dialog.get_by_label("Order history", exact=True).check()
    dialog.locator(".people-help > summary").click()
    page.route("**" + prefix + "/", lambda route: route.abort("failed"))
    dialog.get_by_role("button", name="Refresh list", exact=True).click()
    playwright.expect(dialog.locator("[data-form-error]")).to_contain_text("People couldn’t load")
    page.unroute("**" + prefix + "/")
    dialog.get_by_role("button", name="Refresh list", exact=True).click()
    playwright.expect(page.get_by_role("status")).to_contain_text("People list refreshed")
    assert dialog.locator("[data-form-error]").inner_text() == ""
    assert dialog.get_by_label("Person", exact=True).input_value() == "bob"
    assert dialog.get_by_label("Order history", exact=True).is_checked()
    dialog.locator("[data-save]").click()
    playwright.expect(dialog).not_to_be_visible()
    assert people.namespace("alice", "example")["shares"]["bob"]["capabilities"] == [
        "cart",
        "orders",
    ]
    context.close()


@pytest.mark.parametrize("refresh_fails", [False, True])
def test_late_people_refresh_preserves_blocked_write_error(management_browser, refresh_fails):
    people, controls, _, browser, origin, prefix, _, submissions, _ = management_browser
    context = browser.new_context()
    context.add_cookies([{"name": "actor", "value": "alice", "url": origin}])
    page = context.new_page()
    page.goto(origin + prefix + "/")
    page.locator("#share-0-new > summary").click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_label("Person", exact=True).select_option("bob")
    dialog.get_by_label("Order history", exact=True).check()
    dialog.locator(".people-help > summary").click()
    refreshes = []
    page.route("**" + prefix + "/", lambda route: refreshes.append(route))
    with page.expect_request(origin + prefix + "/"):
        dialog.get_by_role("button", name="Refresh list", exact=True).click()
    playwright.expect(
        dialog.get_by_role("button", name="Refresh list", exact=True)
    ).to_be_disabled()
    refresh = refreshes.pop()
    response = refresh.fetch()
    controls.disconnect("alice", "example", lambda: None)
    dialog.locator("[data-save]").click()
    playwright.expect(dialog.locator("[data-form-error]")).to_contain_text("changed")
    message = dialog.locator("[data-form-error]").inner_text()
    if refresh_fails:
        refresh.abort("failed")
    else:
        refresh.fulfill(response=response)
        playwright.expect(page.get_by_role("status")).to_contain_text("People list refreshed")
    assert dialog.locator("[data-form-error]").inner_text() == message
    assert dialog.get_by_role("link", name="Refresh details before retrying").is_visible()
    assert dialog.locator("[data-save]").is_disabled()
    assert dialog.get_by_label("Person", exact=True).input_value() == "bob"
    assert dialog.get_by_label("Order history", exact=True).is_checked()
    assert len(submissions) == 1 and people.namespace("alice", "example")["shares"] == {}
    context.close()
