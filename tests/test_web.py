import html
from dataclasses import replace
from html.parser import HTMLParser

import pytest
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, Response
from starlette.routing import Mount
from starlette.testclient import TestClient

from account_connections.controls import Controls
from account_connections.people import Identity, People, Policy
from account_connections.storage import StateError
from account_connections.web import Hooks, routes

ORIGIN = "https://app.example.com"


class Auth:
    def identity(self, request):
        if request.headers.get("x-session") != "present":
            return None
        return {
            "issuer": "https://identity.example.com",
            "sub": request.headers.get("x-sub", "alice-sub"),
            "label": request.headers.get("x-label", '<script>"&</script>'),
        }

    def require_fresh(self, request, *, next=None, action="continue"):
        if request.headers.get("x-fresh") == "1":
            return None
        return HTMLResponse(
            '<a href="' + html.escape(self.step_up_url(next), quote=True) + '">Confirm</a>',
            status_code=403,
        )

    def step_up_url(self, next=None):
        return "/connections/login?reauth=1"

    def refused(self, request):
        return Response("Request refused", status_code=403 if self.identity(request) else 401)


@pytest.fixture
def web(tmp_path):
    people = People(tmp_path / "authority")
    people.enroll(
        "alice",
        namespaces=["example"],
        identity=Identity("https://identity.example.com", "alice-sub"),
    )
    people.enroll("bob", namespaces=["example"])
    people.bind(
        "alice", Identity("https://identity.example.com", "alice-sub"), name='<script>"&</script>'
    )
    controls = Controls(people)
    attempt = controls.begin("alice", "example")
    controls.stage("alice", "example", attempt, lambda: None)
    controls.publish("alice", "example", attempt, lambda: None)
    policy = Policy("1", frozenset({"cart", "orders"}))
    calls = []

    async def connect(request, person, namespace, form):
        calls.append((person, namespace, dict(form)))
        return Response("provider action complete")

    def render(person, namespace):
        assert not getattr(people.store._local, "locked", False)
        return "<p>Provider connection controls</p>"

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: policy,
        actions={"connect": connect},
        render_namespace=render,
        default_capabilities=lambda namespace: frozenset({"cart"}),
    )
    client = TestClient(
        Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)), base_url=ORIGIN
    )
    client.headers.update({"x-session": "present", "x-fresh": "1", "origin": ORIGIN})
    return people, controls, client, calls


def fields(controls):
    return {
        "namespace": "example",
        "recipient": "bob",
        "capability": "cart",
        "control_revision": controls.status("alice", "example")["revision"],
    }


def test_home_escapes_display_and_renders_provider_hook(web):
    _, _, client, _ = web
    response = client.get("/connections/")
    assert response.status_code == 200
    assert "<script>" not in response.text and "&lt;script&gt;" in response.text
    assert "Provider connection controls" in response.text
    assert 'value="cart" checked' in response.text
    assert 'value="orders" checked' not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "form-action 'self'" in response.headers["content-security-policy"]


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("history", [False, True])
def test_recipient_sees_actual_offered_and_selected_permissions(web, selected, history):
    people, controls, _, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    attempt = controls.begin("bob", "example")
    controls.publish("bob", "example", attempt, lambda: None, require_staged=False)
    offered = people.offer(
        "bob",
        "example",
        "alice",
        policy=policy,
        capabilities=policy.capabilities if history else frozenset({"cart"}),
        expected=None,
    )
    if selected:
        people.select(
            "alice",
            "example",
            "bob",
            policy=policy,
            expected=people.namespace("alice", "example")["selection"]["revision"],
            grant_revision=offered.revision,
        )
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: policy,
        capability_labels=lambda namespace: {"cart": "Basket", "orders": "Order history"},
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    client.headers.update({"x-session": "present", "x-fresh": "1", "origin": ORIGIN})
    page = client.get("/connections/")
    granted = "Basket, Order history" if history else "Basket"
    assert page.text.count(f"<p>Granted permissions: {granted}.</p>") == (2 if selected else 1)
    assert ("<p>Not shared: Order history.</p>" in page.text) is not history
    assert ("Using bob's account" in page.text) is selected


def test_permission_labels_are_escaped_with_identifier_fallback_and_empty_grants(web):
    people, controls, _, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    attempt = controls.begin("bob", "example")
    controls.publish("bob", "example", attempt, lambda: None, require_staged=False)
    people.offer("bob", "example", "alice", policy=policy, capabilities=frozenset(), expected=None)
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: policy,
        capability_labels=lambda namespace: {"cart": '<img src="x"> & Basket'},
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    page = client.get("/connections/", headers={"x-session": "present", "x-fresh": "1"})
    assert "<p>Granted permissions: none.</p>" in page.text
    assert "<p>Not shared: &lt;img src=&quot;x&quot;&gt; &amp; Basket, orders.</p>" in page.text
    assert '<img src="x">' not in page.text
    assert 'value="cart"' in page.text and 'value="orders"' in page.text


def test_changed_grant_displays_current_offer_without_claiming_stale_selection_is_usable(web):
    people, controls, client, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    attempt = controls.begin("bob", "example")
    controls.publish("bob", "example", attempt, lambda: None, require_staged=False)
    old = people.offer(
        "bob", "example", "alice", policy=policy, capabilities=frozenset({"cart"}), expected=None
    )
    people.select(
        "alice",
        "example",
        "bob",
        policy=policy,
        expected=people.namespace("alice", "example")["selection"]["revision"],
        grant_revision=old.revision,
    )
    people.offer(
        "bob",
        "example",
        "alice",
        policy=policy,
        capabilities=frozenset({"orders"}),
        expected=old.revision,
    )
    page = client.get("/connections/")
    assert "The selected account is unavailable" in page.text
    assert "Using bob's account" not in page.text
    assert page.text.count("<p>Granted permissions: orders.</p>") == 1
    assert "<p>Not shared: cart.</p>" in page.text
    assert "<p>Granted permissions: cart.</p>" not in page.text


@pytest.mark.parametrize("fresh", [False, True])
def test_home_retains_status_but_hides_every_mutation_form_until_fresh(web, fresh):
    people, controls, _, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    people.offer(
        "alice", "example", "bob", policy=policy, capabilities=frozenset({"cart"}), expected=None
    )
    attempt = controls.begin("bob", "example")
    controls.publish("bob", "example", attempt, lambda: None, require_staged=False)
    offered = people.offer(
        "bob", "example", "alice", policy=policy, capabilities=frozenset({"orders"}), expected=None
    )
    people.select(
        "alice",
        "example",
        "bob",
        policy=policy,
        expected=people.namespace("alice", "example")["selection"]["revision"],
        grant_revision=offered.revision,
    )
    rendered = []

    def actions(person, namespace):
        assert not getattr(people.store._local, "locked", False)
        rendered.append("actions")
        return '<form method="post" action="/provider/connect"><button>Connect</button></form>'

    def status(person, namespace):
        assert not getattr(people.store._local, "locked", False)
        rendered.append("status")
        return "<p>Saved local session status</p>"

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: policy,
        render_namespace=actions,
        render_namespace_status=status,
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    client.headers.update({"x-session": "present", "x-fresh": str(int(fresh)), "origin": ORIGIN})
    before = (people.read("alice"), people.read("bob"))
    page = client.get("/connections/")
    assert page.status_code == 200
    assert "Saved local session status" in page.text
    assert "Using bob's account" in page.text
    assert "<p>Granted permissions: orders.</p>" in page.text
    assert ("<form" in page.text) is fresh
    assert rendered == (["actions", "status"] if fresh else ["status"])
    if not fresh:
        assert page.text.index("Confirm your sign-in") < page.text.index(
            "Saved local session status"
        )
        assert 'href="/connections/login?reauth=1"' in page.text
        assert client.post("/connections/share", data=fields(controls)).status_code == 403
    assert (people.read("alice"), people.read("bob")) == before


def test_first_contact_enrolls_without_pinning_until_an_explicit_action(tmp_path):
    people = People(tmp_path / "authority")
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart"})),
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    headers = {"x-session": "present", "x-fresh": "1", "origin": ORIGIN, "x-label": "Alice"}
    assert client.get("/connections/", headers=headers).status_code == 200
    assert people.read("alice")["identity"] is None
    assert people.read("alice")["name"] == "Alice"
    revision = people.namespace("alice", "example")["selection"]["revision"]
    assert (
        client.post(
            "/connections/choose",
            headers=headers,
            data={
                "namespace": "example",
                "owner": "alice",
                "expected": revision,
            },
            follow_redirects=False,
        ).status_code
        == 303
    )
    assert people.read("alice")["identity"]["sub"] == "alice-sub"


def test_share_picker_uses_labels_excludes_self_and_has_no_typed_id(web):
    people, _, client, _ = web
    people.bind("bob", Identity("https://identity.example.com", "bob-sub"), name="Same")
    response = client.get("/connections/", headers={"x-label": "Same"})
    assert "Signed in as Same (alice)" in response.text
    assert "<p>Same (bob)</p>" in response.text
    assert 'name="recipient" value="bob"' in response.text
    assert 'name="recipient" value="alice"' not in response.text
    assert "<label>Person <input" not in response.text


def test_disconnected_owner_explains_sharing_and_keeps_lost_recipient_revocable(web):
    people, controls, client, _ = web
    client.post("/connections/share", data=fields(controls))
    people.store.path("bob").unlink()
    controls.disconnect("alice", "example", lambda: None)
    response = client.get("/connections/")
    assert "Connect first to share" in response.text
    assert "Stop sharing with bob" in response.text
    assert 'action="/connections/share"' not in response.text


def test_old_browser_cookie_cannot_reactivate_removed_membership(web):
    people, _, client, _ = web
    people.set_inactive("alice", Identity("https://identity.example.com", "alice-sub"))
    assert client.get("/connections/").status_code == 403
    with pytest.raises(StateError, match="person_inactive"):
        people.require_admitted("alice")


@pytest.mark.parametrize("selected_own", [False, True])
@pytest.mark.parametrize("result", [False, 1, ValueError, RuntimeError])
def test_provider_readiness_hides_share_and_refuses_direct_share_post(web, selected_own, result):
    people, controls, _, _ = web
    if selected_own:
        people.select(
            "alice",
            "example",
            "alice",
            policy=Policy("1", frozenset({"cart"})),
            expected=people.namespace("alice", "example")["selection"]["revision"],
        )
    observed = []

    def ready(person, namespace):
        assert not getattr(people.store._local, "locked", False)
        observed.append((person, namespace))
        if isinstance(result, type):
            raise result("malformed provider status")
        return result

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart"})),
        connection_ready=ready,
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    client.headers.update({"x-session": "present", "x-fresh": "1", "origin": ORIGIN})
    page = client.get("/connections/")
    assert page.status_code == 200
    assert "Your account is not connected" in page.text
    assert "Connect first to share" in page.text
    assert 'action="/connections/share"' not in page.text
    assert client.post("/connections/share", data=fields(controls)).status_code == 409
    assert people.namespace("alice", "example")["shares"] == {}
    assert ("alice", "example") in observed


def test_provider_readiness_exception_isolates_its_owner(web):
    people, _, _, _ = web

    def ready(person, namespace):
        if person == "bob":
            raise ValueError("malformed provider status")
        return True

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart"})),
        connection_ready=ready,
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    client.headers.update({"x-session": "present", "x-fresh": "1", "origin": ORIGIN})
    page = client.get("/connections/")
    assert page.status_code == 200
    assert 'action="/connections/share"' in page.text


@pytest.mark.parametrize(
    "origin", ["https://other.example.com", "null", "https://app.example.com/", ""]
)
def test_cross_origin_changes_nothing(web, origin):
    people, controls, client, _ = web
    response = client.post("/connections/share", data=fields(controls), headers={"origin": origin})
    assert response.status_code == 403
    assert people.namespace("alice", "example")["shares"] == {}


def test_duplicate_origin_is_refused(web):
    _, controls, client, _ = web
    response = client.post(
        "/connections/share",
        data=fields(controls),
        headers=[("origin", ORIGIN), ("origin", ORIGIN)],
    )
    assert response.status_code == 403


def test_expired_browser_session_changes_nothing(web):
    people, controls, client, _ = web
    response = client.post(
        "/connections/share", data=fields(controls), headers={"x-session": "expired"}
    )
    assert response.status_code == 401
    assert people.namespace("alice", "example")["shares"] == {}


def test_post_step_up_is_page_with_link_and_does_not_replay(web):
    people, controls, client, _ = web
    response = client.post(
        "/connections/share",
        data=fields(controls),
        headers={"x-fresh": "0"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert (
        "location" not in response.headers and 'href="/connections/login?reauth=1"' in response.text
    )
    assert people.namespace("alice", "example")["shares"] == {}


def test_identity_claim_cannot_transfer_pinned_person(web):
    people, controls, client, _ = web
    headers = {"x-sub": "different-subject"}
    assert client.get("/connections/", headers=headers).status_code == 403
    assert (
        client.post("/connections/share", data=fields(controls), headers=headers).status_code == 403
    )
    assert people.read("alice")["identity"]["sub"] == "alice-sub"


def test_shared_offer_has_only_explicit_capability(web):
    people, controls, client, _ = web
    assert (
        client.post("/connections/share", data=fields(controls), follow_redirects=False).status_code
        == 303
    )
    offered = people.namespace("alice", "example")["shares"]["bob"]
    assert offered["capabilities"] == ["cart"]
    assert people.namespace("bob", "example")["selection"]["choice"] is None


def test_owner_can_update_permission_from_existing_share(web):
    people, controls, client, _ = web
    client.post("/connections/share", data=fields(controls))
    offered = people.namespace("alice", "example")["shares"]["bob"]
    response = client.get("/connections/")
    assert "Update permissions" in response.text
    assert offered["revision"] in response.text
    form = fields(controls)
    form["expected"] = offered["revision"]
    form["capability"] = ["cart", "orders"]
    assert client.post("/connections/share", data=form).status_code == 200
    updated = people.namespace("alice", "example")["shares"]["bob"]
    assert updated["capabilities"] == ["cart", "orders"]
    assert updated["revision"] != offered["revision"]


def test_stale_owner_revision_changes_nothing(web):
    people, controls, client, _ = web
    form = fields(controls)
    controls.begin("alice", "example")
    assert client.post("/connections/share", data=form).status_code == 409
    assert people.namespace("alice", "example")["shares"] == {}


def test_provider_action_uses_authenticated_actor(web):
    _, controls, client, calls = web
    form = fields(controls)
    form["owner"] = "bob"
    form["actor"] = "bob"
    assert client.post("/connections/connect", data=form).status_code == 200
    assert calls[0][:2] == ("alice", "example")


def test_provider_action_needs_fresh_auth(web):
    _, controls, client, calls = web
    response = client.post("/connections/connect", data=fields(controls), headers={"x-fresh": "0"})
    assert response.status_code == 403 and not calls


@pytest.mark.parametrize(
    "payload",
    (b"namespace=example&namespace=example", b"namespace=example&malformed", b"namespace=\xff"),
)
def test_malformed_provider_forms_are_bad_requests(web, payload):
    _, _, client, calls = web
    response = client.post(
        "/connections/connect",
        content=payload,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400 and not calls


def test_provider_form_content_type_and_size_are_bounded(web):
    _, _, client, calls = web
    assert client.post("/connections/connect", json={"namespace": "example"}).status_code == 400
    response = client.post(
        "/connections/connect",
        content="namespace=example&data=" + "x" * 16384,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413 and not calls


@pytest.mark.parametrize("namespace", ("../../other", "unknown", ""))
def test_unknown_namespace_is_bad_request(web, namespace):
    _, controls, client, calls = web
    form = fields(controls)
    form["namespace"] = namespace
    assert client.post("/connections/connect", data=form).status_code == 400
    assert not calls


@pytest.mark.parametrize("control_revision", (None, "stale"))
def test_provider_hook_receives_revision_without_generic_fencing(web, control_revision):
    _, _, client, calls = web
    form = {"namespace": "example"}
    if control_revision is not None:
        form["control_revision"] = control_revision
    assert client.post("/connections/connect", data=form).status_code == 200
    assert calls == [("alice", "example", form)]


def test_provider_namespace_field_preserves_application_form_contract(web):
    people, _, _, calls = web

    async def provider_action(request, person, namespace, form):
        calls.append((person, namespace, dict(form)))
        return Response("Provider handled the native form")

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart"})),
        actions={"start": provider_action},
        provider_namespace_field="site",
    )
    client = TestClient(
        Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)), base_url=ORIGIN
    )
    client.headers.update({"x-session": "present", "x-fresh": "1", "origin": ORIGIN})
    form = {"site": "example", "revision": "native-revision"}
    assert client.post("/connections/start", data=form).status_code == 200
    assert calls == [("alice", "example", form)]
    assert client.post("/connections/start", data={"namespace": "example"}).status_code == 400
    # Generic selection retains the library's own field contract.
    choice = {
        "namespace": "example",
        "owner": "alice",
        "expected": people.namespace("alice", "example")["selection"]["revision"],
    }
    assert (
        client.post("/connections/choose", data=choice, follow_redirects=False).status_code == 303
    )
    with pytest.raises(ValueError):
        routes(people, Auth(), replace(hooks, provider_namespace_field="../site"), origin=ORIGIN)


@pytest.mark.parametrize("scenario", ("unselected", "updated", "reissued"))
def test_leave_and_decline_use_the_current_offer_after_permission_changes(web, scenario):
    people, controls, client, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    attempt = controls.begin("bob", "example")
    controls.stage("bob", "example", attempt, lambda: None)
    controls.publish("bob", "example", attempt, lambda: None)
    offered = people.offer(
        "bob", "example", "alice", policy=policy, capabilities=frozenset({"cart"}), expected=None
    )
    if scenario != "unselected":
        people.select(
            "alice",
            "example",
            "bob",
            policy=policy,
            expected=people.namespace("alice", "example")["selection"]["revision"],
            grant_revision=offered.revision,
        )
        if scenario == "reissued":
            people.revoke("bob", "example", "alice", expected=offered.revision)
        offered = people.offer(
            "bob",
            "example",
            "alice",
            policy=policy,
            capabilities=policy.capabilities,
            expected=offered.revision if scenario == "updated" else None,
        )

    class Forms(HTMLParser):
        def __init__(self):
            super().__init__()
            self.leaves = []
            self.current = None

        def handle_starttag(self, tag, attrs):
            fields = dict(attrs)
            if tag == "form":
                self.current = {} if fields.get("action") == "/connections/leave" else None
            elif tag == "input" and self.current is not None:
                self.current[fields["name"]] = fields.get("value", "")

        def handle_endtag(self, tag):
            if tag == "form" and self.current is not None:
                self.leaves.append(self.current)
                self.current = None

    page = client.get("/connections/")
    parsed = Forms()
    parsed.feed(page.text)
    assert parsed.leaves == [{"namespace": "example", "owner": "bob", "expected": offered.revision}]
    assert (
        "Decline shared account" if scenario == "unselected" else "Leave shared account"
    ) in page.text
    assert (
        client.post("/connections/leave", data=parsed.leaves[0], follow_redirects=False).status_code
        == 303
    )
    assert "alice" not in people.namespace("bob", "example")["shares"]
    assert people.namespace("alice", "example")["selection"]["choice"] is None


def test_mount_path_keeps_route_matching_and_external_links_separate(web):
    people, _, _, _ = web
    policy = Policy("1", frozenset({"cart"}))
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: policy,
    )
    child = Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN, mount_path="/example"))
    client = TestClient(Starlette(routes=[Mount("/example", app=child)]), base_url=ORIGIN)
    response = client.get("/example/connections/", headers={"x-session": "present", "x-fresh": "1"})
    assert response.status_code == 200
    assert 'action="/example/connections/choose"' in response.text
    response = client.get("/example/connections/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/example/connections/login"
