import html
from dataclasses import replace
from html.parser import HTMLParser

import pytest
from starlette.applications import Starlette
from starlette.responses import Response
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
    client.headers.update({"x-session": "present", "origin": ORIGIN})
    return people, controls, client, calls


def fields(controls):
    return {
        "namespace": "example",
        "recipient": "bob",
        "capability": "cart",
        "control_revision": controls.status("alice", "example")["revision"],
    }


@pytest.fixture
def ordinary_session(web, tmp_path):
    from signin_window.oidc import BrowserAuth, OIDCConfig

    people, controls, _, calls = web
    now = [1000]
    auth = BrowserAuth(
        OIDCConfig(
            issuer="https://identity.example.com",
            client_id="synthetic-client",
            public_url=ORIGIN,
            state_dir=tmp_path / "browser",
        ),
        clock=lambda: now[0],
    )
    sid = "s" * 43
    auth.store.save(
        sid,
        {
            "issuer": "https://identity.example.com",
            "sub": "alice-sub",
            "groups": [],
            "claims": {},
            "label": '<script>"&</script>',
            "auth_time": 1000,
            "reauthenticated_at": 1000,
            "expires": 1900,
        },
    )

    async def provider(request, person, namespace, form):
        calls.append((request.url.path, person, namespace, dict(form)))
        return Response("provider action complete")

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart", "orders"})),
        actions=dict.fromkeys(("connect", "reconnect", "cancel", "disconnect"), provider),
        render_namespace=lambda person, namespace: (
            '<form method="post" action="/connections/reconnect"><button>Reconnect</button></form>'
        ),
    )
    client = TestClient(
        auth.middleware(
            Starlette(routes=auth.routes() + routes(people, auth, hooks, origin=ORIGIN))
        ),
        base_url=ORIGIN,
        follow_redirects=False,
    )
    client.cookies.set(auth.cookie, sid)
    client.headers["origin"] = ORIGIN
    now[0] = 1301
    return people, controls, client, calls, auth, now


@pytest.mark.parametrize(
    "action",
    ["share", "edit", "choose", "revoke", "leave", "connect", "reconnect", "cancel", "disconnect"],
)
def test_valid_session_at_301_seconds_can_manage_connections(ordinary_session, action):
    people, controls, client, calls, _, _ = ordinary_session
    form = fields(controls)
    policy = Policy("1", frozenset({"cart", "orders"}))
    if action in {"edit", "revoke"}:
        grant = people.offer(
            "alice",
            "example",
            "bob",
            policy=policy,
            capabilities=frozenset({"cart"}),
            expected=None,
        )
        form["expected"] = grant.revision
        form["capability"] = "orders"
    if action in {"choose", "leave"}:
        attempt = controls.begin("bob", "example")
        controls.publish("bob", "example", attempt, lambda: None, require_staged=False)
        grant = people.offer(
            "bob",
            "example",
            "alice",
            policy=policy,
            capabilities=frozenset({"cart"}),
            expected=None,
        )
        form.update(owner="bob", grant=grant.revision, expected=grant.revision)
        if action == "choose":
            form["expected"] = people.namespace("alice", "example")["selection"]["revision"]
    page = client.get("/connections/")
    assert page.status_code == 200
    assert 'action="/connections/share"' in page.text
    assert 'action="/connections/reconnect"' in page.text
    assert "Confirm your sign-in" not in page.text and "reauth=1" not in page.text
    endpoint = "share" if action == "edit" else action
    response = client.post("/connections/" + endpoint, data=form)
    if action in {"connect", "reconnect", "cancel", "disconnect"}:
        assert response.status_code == 200
        assert calls == [("/connections/" + action, "alice", "example", form)]
    else:
        assert response.status_code == 303
        assert response.headers["location"] == "/connections/"
        if action in {"share", "edit"}:
            assert people.namespace("alice", "example")["shares"]["bob"]["capabilities"] == [
                "orders" if action == "edit" else "cart"
            ]
        elif action == "choose":
            assert people.namespace("alice", "example")["selection"]["choice"]["owner"] == "bob"
        elif action == "revoke":
            assert people.namespace("alice", "example")["shares"] == {}
        else:
            assert people.namespace("bob", "example")["shares"] == {}


@pytest.mark.parametrize("action", ["share", "reconnect"])
def test_real_session_expiry_refuses_post_and_requires_sign_in_then_retry(
    ordinary_session, monkeypatch, action
):
    people, controls, client, calls, auth, now = ordinary_session
    before = (people.read("alice"), people.read("bob"))
    now[0] = 1900
    response = client.post("/connections/" + action, data=fields(controls))
    assert response.status_code == 401
    assert "location" not in response.headers
    assert 'href="/connections/login"' in response.text
    assert "repeat the action" in response.text
    assert "form-action 'self'" in response.headers["content-security-policy"]
    visit = client.get("/connections/")
    assert visit.status_code == 303
    assert visit.headers["location"] == "/connections/login"

    async def metadata():
        return {
            "issuer": auth.config.issuer,
            "authorization_endpoint": auth.config.issuer + "/authorize",
            "token_endpoint": auth.config.issuer + "/token",
            "jwks_uri": auth.config.issuer + "/keys",
        }

    async def authorize(request, callback, **kwargs):
        assert callback == ORIGIN + "/connections/callback"
        assert kwargs == {}  # Ordinary login allows an existing provider session.
        return Response(status_code=200)

    async def token(request, **kwargs):
        return {
            "id_token": "verified-id-token",
            "userinfo": {"iss": auth.config.issuer, "sub": "alice-sub", "exp": 2800},
        }

    monkeypatch.setattr(auth.client, "load_server_metadata", metadata)
    monkeypatch.setattr(auth.client, "authorize_redirect", authorize)
    monkeypatch.setattr(auth.client, "authorize_access_token", token)
    assert client.get("/connections/login").status_code == 200
    callback = client.get("/connections/callback")
    assert callback.status_code == 303
    assert callback.headers["location"] == "/connections/"
    assert (people.read("alice"), people.read("bob")) == before
    assert not calls
    # Login and its return never replay the refused write.
    assert client.post("/connections/" + action, data=fields(controls)).status_code == (
        303 if action == "share" else 200
    )


@pytest.mark.parametrize(
    ("protection", "status"),
    [
        ("actor", 403),
        ("admission", 403),
        ("origin", 403),
        ("duplicate_origin", 403),
        ("control_revision", 409),
        ("grant_revision", 409),
        ("recipient", 409),
        ("capability", 400),
    ],
)
def test_ordinary_session_preserves_authorization_fences(ordinary_session, protection, status):
    people, controls, client, calls, auth, _ = ordinary_session
    form = fields(controls)
    headers = {}
    if protection == "actor":
        # A valid session for another subject cannot take over a pinned person.
        sid = client.cookies.get(auth.cookie)
        session = auth.store.load(sid)
        session["sub"] = "bob-sub"
        auth.store.save(sid, session)
    elif protection == "admission":
        people.set_inactive("alice", Identity("https://identity.example.com", "alice-sub"))
    elif protection == "origin":
        headers = {"origin": "https://other.example.com"}
    elif protection == "duplicate_origin":
        headers = [("origin", ORIGIN), ("origin", ORIGIN)]
    elif protection == "control_revision":
        form["control_revision"] = "stale"
    elif protection == "grant_revision":
        form["expected"] = "stale"
    elif protection == "recipient":
        people.set_inactive("bob")
    else:
        form["capability"] = "undeclared"
    before = (people.read("alice"), people.read("bob"))
    response = client.post("/connections/share", data=form, headers=headers)
    assert response.status_code == status
    assert (people.read("alice"), people.read("bob")) == before
    assert not calls


def test_home_escapes_display_and_renders_provider_hook(web):
    _, _, client, _ = web
    response = client.get("/connections/")
    assert response.status_code == 200
    assert response.text.count("<script>") == 2 and "&lt;script&gt;" in response.text
    assert "Provider connection controls" in response.text
    assert 'value="cart" data-label="cart" checked' in response.text
    assert 'value="orders" data-label="orders" checked' not in response.text
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
    client.headers.update({"x-session": "present", "origin": ORIGIN})
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
    page = client.get("/connections/", headers={"x-session": "present"})
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


def test_home_renders_status_and_all_management_forms_with_ordinary_auth(web):
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
    client.headers.update({"x-session": "present", "origin": ORIGIN})
    before = (people.read("alice"), people.read("bob"))
    page = client.get("/connections/")
    assert page.status_code == 200
    assert "Saved local session status" in page.text
    assert "Using bob's account" in page.text
    assert "<p>Granted permissions: orders.</p>" in page.text
    for action in ("choose", "share", "revoke", "leave"):
        assert f'action="/connections/{action}"' in page.text
    assert 'action="/provider/connect"' in page.text
    assert rendered == ["actions", "status"]
    assert "Confirm your sign-in" not in page.text
    assert "reauth=1" not in page.text
    assert (people.read("alice"), people.read("bob")) == before


def test_first_contact_enrolls_without_pinning_until_an_explicit_action(tmp_path):
    people = People(tmp_path / "authority")
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart"})),
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    headers = {"x-session": "present", "origin": ORIGIN, "x-label": "Alice"}
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
    assert "Signed in to Connections as Same (alice)" in response.text
    assert 'value="bob">Same (bob)</option>' in response.text
    assert 'name="recipient" required' in response.text
    assert '<option value="">Choose a person</option>' in response.text
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
    assert '<button type="submit" data-save' not in response.text
    assert 'formaction="/connections/revoke"' in response.text


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
    client.headers.update({"x-session": "present", "origin": ORIGIN})
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
    client.headers.update({"x-session": "present", "origin": ORIGIN})
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
    assert "Edit access for bob" in response.text
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
    client.headers.update({"x-session": "present", "origin": ORIGIN})
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
    assert ("Decline access" if scenario == "unselected" else "Leave account") in page.text
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
    response = client.get("/example/connections/", headers={"x-session": "present"})
    assert response.status_code == 200
    assert 'action="/example/connections/choose"' in response.text
    response = client.get("/example/connections/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/example/connections/login"


def test_home_uses_one_accessible_styled_shell(web):
    from signin_window.connections import SCRIPT_SOURCE

    _, _, client, _ = web
    response = client.get("/connections/")
    assert response.status_code == 200
    assert response.text.count("<!doctype html>") == 1
    assert response.text.count("<main>") == 1
    assert response.text.count("<h1>") == 1
    assert '<html lang="en">' in response.text
    assert '<meta name="viewport"' in response.text
    assert '<article aria-labelledby="connection-0"' in response.text
    assert '<h2 id="connection-0">example</h2>' in response.text
    assert 'data-login-url="/connections/login"' in response.text
    policy = response.headers["content-security-policy"]
    assert "style-src 'unsafe-inline'" in policy
    assert f"script-src {SCRIPT_SOURCE}" in policy
    assert "default-src 'none'" in policy
    assert "<form" in response.text


def _identity_client(web, identity):
    people, _, _, calls = web

    async def connect(request, person, namespace, form):
        calls.append((person, namespace, dict(form)))
        return Response("provider action complete", headers={"x-provider": "preserved"})

    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart", "orders"})),
        actions={"connect": connect},
    )
    child = Starlette(
        routes=routes(
            people,
            Auth(),
            hooks,
            origin=ORIGIN,
            prefix="/accounts",
            mount_path="/workspace",
            identity=identity,
        )
    )
    client = TestClient(Starlette(routes=[Mount("/workspace", app=child)]), base_url=ORIGIN)
    client.headers.update({"x-session": "present", "origin": ORIGIN})
    return client


@pytest.fixture
def identity_web(web, monkeypatch):
    import account_connections.web as web_module

    original_page = web_module.page
    supplied = object()
    rendered = []

    def identity_page(
        title,
        body,
        *,
        intro="",
        refresh=False,
        login_url="/connections/login",
        identity=None,
    ):
        rendered.append((identity, login_url))
        return original_page(
            title,
            body + "<p>Forwarded build identity</p>",
            intro=intro,
            refresh=refresh,
            login_url=login_url,
        )

    monkeypatch.setattr(web_module, "page", identity_page)
    return _identity_client(web, supplied), supplied, rendered


def _assert_owned_identity_page(response, supplied, rendered, status):
    from account_connections.web import HEADERS

    assert response.status_code == status
    assert rendered == [(supplied, "/workspace/accounts/login")]
    assert rendered[0][0] is supplied
    assert "Forwarded build identity" in response.text
    assert 'data-login-url="/workspace/accounts/login"' in response.text
    assert response.text.count("<!doctype html>") == 1
    for name, value in HEADERS.items():
        assert response.headers[name] == value


def test_omitted_build_identity_keeps_the_old_renderer_call_contract(web, monkeypatch):
    import account_connections.web as web_module

    people, _, _, _ = web
    original_page = web_module.page
    rendered = []

    def old_page(title, body, *, intro="", refresh=False, login_url="/connections/login"):
        rendered.append(login_url)
        return original_page(title, body, intro=intro, refresh=refresh, login_url=login_url)

    monkeypatch.setattr(web_module, "page", old_page)
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"cart"})),
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    response = client.get("/connections/", headers={"x-session": "present"})
    assert response.status_code == 200
    assert rendered == ["/connections/login"]
    assert 'id="connection-identity"' not in response.text
    with pytest.raises(ValueError, match="identity"):
        routes(people, Auth(), hooks, origin=ORIGIN, identity=object())


def test_build_identity_is_forwarded_to_home(web, identity_web):
    people, _, _, calls = web
    client, supplied, rendered = identity_web
    before = (people.read("alice"), people.read("bob"))
    response = client.get("/workspace/accounts/")
    _assert_owned_identity_page(response, supplied, rendered, 200)
    assert (people.read("alice"), people.read("bob")) == before
    assert not calls
    assert "<form" in response.text


def test_build_identity_is_forwarded_when_home_controls_are_unavailable(
    web, identity_web, monkeypatch
):
    people, _, _, calls = web
    client, supplied, rendered = identity_web
    before = (people.read("alice"), people.read("bob"))

    def unavailable(person, namespace):
        raise StateError("<script>private failure detail</script>")

    monkeypatch.setattr(people, "namespace", unavailable)
    response = client.get("/workspace/accounts/")
    _assert_owned_identity_page(response, supplied, rendered, 409)
    assert "Connection controls unavailable." in response.text
    assert "private failure detail" not in response.text
    assert (people.read("alice"), people.read("bob")) == before
    assert not calls


@pytest.mark.parametrize(
    ("scenario", "status"),
    [
        ("mime", 400),
        ("oversized", 413),
        ("utf8", 400),
        ("malformed", 400),
        ("duplicate", 400),
        ("unknown", 400),
        ("invalid_namespace", 400),
        ("missing_field", 400),
        ("conflict", 409),
    ],
)
def test_build_identity_is_forwarded_to_owned_mutation_failures(
    web, identity_web, scenario, status
):
    people, controls, _, calls = web
    client, supplied, rendered = identity_web
    action = "connect"
    payload = b"namespace=example"
    content_type = "application/x-www-form-urlencoded"
    if scenario == "mime":
        content_type = "application/json"
    elif scenario == "oversized":
        payload += b"&data=" + b"x" * 16384
    elif scenario == "utf8":
        payload = b"namespace=\xff"
    elif scenario == "malformed":
        payload += b"&malformed"
    elif scenario == "duplicate":
        payload += b"&namespace=example"
    elif scenario == "unknown":
        payload = b"namespace=unknown"
    elif scenario == "invalid_namespace":
        payload = b"namespace=%3Cscript%3E"
    elif scenario == "missing_field":
        action = "choose"
    elif scenario == "conflict":
        action = "share"
        payload += b"&recipient=bob&capability=cart&control_revision=stale"
    before = (people.read("alice"), people.read("bob"))
    response = client.post(
        "/workspace/accounts/" + action,
        content=payload,
        headers={"content-type": content_type},
    )
    _assert_owned_identity_page(response, supplied, rendered, status)
    assert "<script>private failure detail</script>" not in response.text
    assert (people.read("alice"), people.read("bob")) == before
    assert controls.status("alice", "example")["state"] == "active"
    assert not calls


def test_build_identity_does_not_wrap_authentication_or_provider_responses(web, identity_web):
    people, _, _, calls = web
    client, _, rendered = identity_web
    before = (people.read("alice"), people.read("bob"))
    redirect = client.get(
        "/workspace/accounts/", headers={"x-session": "expired"}, follow_redirects=False
    )
    assert redirect.status_code == 303
    assert redirect.headers["location"] == "/workspace/accounts/login"
    refused = client.post("/workspace/accounts/connect", headers={"origin": "null"})
    assert refused.status_code == 403 and refused.text == "Request refused"
    provider = client.post("/workspace/accounts/connect", data={"namespace": "example"})
    assert provider.status_code == 200 and provider.text == "provider action complete"
    assert provider.headers["x-provider"] == "preserved"
    assert calls == [("alice", "example", {"namespace": "example"})]
    assert rendered == []
    assert (people.read("alice"), people.read("bob")) == before


@pytest.mark.parametrize("scenario", ["home", "unavailable", "error"])
def test_candidate_renderer_build_footer_on_every_owned_page(web, monkeypatch, scenario):
    import signin_window.connections as renderer

    identity_type = getattr(renderer, "PageIdentity", None)
    if identity_type is None:
        pytest.skip(
            "Installed signin-window predates PageIdentity; run with the candidate renderer"
        )
    supplied = identity_type(
        service='<img src=x> & "Service"',
        version='1.2.3<&"',
        source_revision='0123456789abcdef0123456789abcdef01234567<script>&"',
    )
    people, _, _, calls = web
    client = _identity_client(web, supplied)
    before = (people.read("alice"), people.read("bob"))
    if scenario == "unavailable":

        def unavailable(person, namespace):
            raise StateError("private failure detail")

        monkeypatch.setattr(people, "namespace", unavailable)
    if scenario == "error":
        response = client.post("/workspace/accounts/connect", json={"namespace": "example"})
    else:
        response = client.get("/workspace/accounts/")
    assert response.status_code == {"home": 200, "unavailable": 409, "error": 400}[scenario]
    assert response.text.count('id="connection-identity"') == 1
    assert f'data-service="{html.escape(supplied.service, quote=True)}"' in response.text
    assert f'data-version="{html.escape(supplied.version, quote=True)}"' in response.text
    escaped_revision = html.escape(supplied.source_revision, quote=True)
    assert f'data-source-revision="{escaped_revision}"' in response.text
    assert f'title="Source revision: {escaped_revision}"' in response.text
    footer = response.text.split('<footer id="connection-identity"', 1)[1].split("</footer>", 1)[0]
    visible = []
    parser = HTMLParser()
    parser.handle_data = visible.append
    parser.feed("<footer" + footer + "</footer>")
    text = "".join(visible)
    assert f"{supplied.service} v{supplied.version} · {supplied.source_revision[:12]}" in text
    assert "Source revision" in text and supplied.source_revision in text
    assert supplied.service not in response.text
    assert supplied.version not in response.text
    assert supplied.source_revision not in response.text
    assert 'data-login-url="/workspace/accounts/login"' in response.text
    assert (people.read("alice"), people.read("bob")) == before
    assert not calls


@pytest.mark.parametrize("capabilities", [frozenset(), frozenset({"orders"})])
def test_edit_form_keeps_actual_empty_or_narrow_grant(web, capabilities):
    people, controls, client, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    offered = people.offer(
        "alice", "example", "bob", policy=policy, capabilities=capabilities, expected=None
    )
    response = client.get("/connections/")
    edit = response.text.split('id="share-0-bob"', 1)[1].split("</details>", 1)[0]
    assert "<select" not in edit
    assert ('value="cart" data-label="cart" checked' in edit) is ("cart" in capabilities)
    assert ('value="orders" data-label="orders" checked' in edit) is ("orders" in capabilities)
    form = fields(controls)
    form["expected"] = offered.revision
    form["capability"] = list(capabilities)
    assert client.post("/connections/share", data=form).status_code == 400
    assert people.namespace("alice", "example")["shares"]["bob"]["revision"] == offered.revision


@pytest.mark.parametrize("state", ["empty", "unavailable", "failed"])
def test_people_picker_distinguishes_empty_unavailable_and_lookup_failure(web, monkeypatch, state):
    people, _, client, _ = web
    if state == "empty":
        roster = people.roster
        monkeypatch.setattr(
            people, "roster", lambda: [row for row in roster() if row.id == "alice"]
        )
    elif state == "unavailable":
        people.set_inactive("bob")
    else:

        def failed():
            raise StateError("private lookup detail")

        monkeypatch.setattr(people, "roster", failed)
    response = client.get("/connections/")
    assert response.status_code == 200
    assert ("People couldn’t load. Try again." in response.text.split("<script>")[0]) is (
        state == "failed"
    )
    assert ("Some people are unavailable." in response.text) is (state == "unavailable")
    assert "private lookup detail" not in response.text
    assert 'data-setup-link href="/connections/"' in response.text
    assert "They do not need their own provider account" in response.text


def test_fixed_single_permission_is_explained_without_a_redundant_picker(web):
    people, _, _, _ = web
    hooks = Hooks(
        actor=lambda identity: "alice",
        namespaces=lambda person: ["example"],
        policy=lambda namespace: Policy("1", frozenset({"read"})),
        default_capabilities=lambda namespace: frozenset({"read"}),
        capability_labels=lambda namespace: {"read": "Read subscription articles"},
    )
    client = TestClient(Starlette(routes=routes(people, Auth(), hooks, origin=ORIGIN)))
    response = client.get("/connections/", headers={"x-session": "present"})
    assert "Read subscription articles: included." in response.text
    assert '<input type="checkbox"' not in response.text
    assert '<input type="hidden" name="capability" value="read"' in response.text


def test_failed_no_script_share_keeps_choices_and_submitted_revision(web):
    people, controls, client, _ = web
    form = fields(controls)
    form["control_revision"] = "stale"
    form["capability"] = "orders"
    response = client.post("/connections/share", data=form)
    assert response.status_code == 409
    assert 'id="share-0-new" open' in response.text
    assert '<option value="bob" selected>' in response.text
    assert 'name="control_revision" value="stale"' in response.text
    assert 'value="orders" data-label="orders" checked' in response.text
    assert "data-save disabled" in response.text
    assert "Refresh details before retrying" in response.text
    assert people.namespace("alice", "example")["shares"] == {}


def test_removed_grant_keeps_failed_no_script_edit_without_recreating_access(web):
    people, controls, client, _ = web
    policy = Policy("1", frozenset({"cart", "orders"}))
    offered = people.offer(
        "alice", "example", "bob", policy=policy, capabilities=frozenset({"cart"}), expected=None
    )
    people.revoke("alice", "example", "bob", expected=offered.revision)
    form = fields(controls)
    form.update(expected=offered.revision, capability="orders")
    response = client.post("/connections/share", data=form)
    assert response.status_code == 409
    assert 'id="share-0-changed" open' in response.text
    assert 'name="expected" value="' + offered.revision + '"' in response.text
    assert 'value="orders" data-label="orders" checked' in response.text
    assert people.namespace("alice", "example")["shares"] == {}


def test_directory_callback_failure_is_not_reported_as_an_empty_people_list(web):
    from account_connections.people import DirectoryPerson

    people, _, client, _ = web
    people.bind("bob", Identity("https://identity.example.com", "bob-sub"))

    def directory(identity):
        if identity.subject == "bob-sub":
            raise RuntimeError("synthetic outage")
        return DirectoryPerson(True)

    people.directory = directory
    response = client.get("/connections/")
    markup = response.text.split("<script>")[0]
    assert "People couldn’t load. Try again." in markup
    assert "No eligible people are available" not in markup
    assert 'value="bob"' not in markup
