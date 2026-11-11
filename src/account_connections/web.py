"""Optional Starlette management routes using signin-window 0.7 authentication.

The host supplies verified identity mapping and provider-only actions. Route
handlers never accept an actor or credential payload from submitted fields.
"""

from __future__ import annotations

import html
import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

from signin_window.connections import SCRIPT_SOURCE, page
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from .controls import Controls
from .people import Identity, People, Policy
from .rules import ConnectionError
from .storage import StateError, identifier

HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        f"default-src 'none'; style-src 'unsafe-inline'; script-src {SCRIPT_SOURCE}; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    # no-referrer makes HTML POST use Origin:null in browsers, which our exact
    # Origin fence correctly refuses. Keep same-origin forms usable while
    # withholding the page URL from cross-origin destinations.
    "Referrer-Policy": "same-origin",
}


class Authentication(Protocol):
    def identity(self, request: Any) -> dict[str, Any] | None: ...
    def require_fresh(
        self,
        request: Any,
        *,
        next: str | None = None,
        action: str = "continue",
    ) -> Response | None: ...
    def step_up_url(self, next: str | None = None) -> str: ...
    def refused(self, request: Any) -> Response: ...


ProviderAction = Callable[[Request, str, str, Mapping[str, str]], Awaitable[Response]]


@dataclass(frozen=True)
class Hooks:
    actor: Callable[[dict[str, Any]], str | None]
    namespaces: Callable[[str], Sequence[str]]
    policy: Callable[[str], Policy]
    actions: Mapping[str, ProviderAction] = field(default_factory=dict)
    render_namespace: Callable[[str, str], str] | None = None
    default_capabilities: Callable[[str], frozenset[str]] | None = None
    provider_namespace_field: str = "namespace"
    enroll: Callable[[str], None] | None = None
    connection_ready: Callable[[str, str], bool] | None = None
    capability_labels: Callable[[str], Mapping[str, str]] | None = None
    render_namespace_status: Callable[[str, str], str] | None = None


def _connection_ready(hooks: Hooks, owner: str, namespace: str) -> bool:
    try:
        return hooks.connection_ready(owner, namespace) is True if hooks.connection_ready else True
    except Exception:
        # Local provider status is optional availability, never authority.
        return False


def _form(action: str, label: str, fields: Mapping[str, str]) -> str:
    escape = html.escape
    hidden = "".join(
        f'<input type="hidden" name="{escape(key, quote=True)}" '
        f'value="{escape(value, quote=True)}">'
        for key, value in fields.items()
    )
    return (
        f'<form method="post" action="{escape(action, quote=True)}">{hidden}'
        f'<button type="submit">{escape(label)}</button></form>'
    )


def _permissions(granted: frozenset[str], policy: Policy, labels: Mapping[str, str]) -> str:
    def names(capabilities: frozenset[str]) -> str:
        return (
            ", ".join(html.escape(labels.get(item, item)) for item in sorted(capabilities))
            or "none"
        )

    parts = [f"<p>Granted permissions: {names(granted)}.</p>"]
    withheld = policy.capabilities - granted
    if withheld:
        parts.append(f"<p>Not shared: {names(withheld)}.</p>")
    return "".join(parts)


def _share_form(
    action: str,
    namespace: str,
    control_revision: str,
    policy: Policy,
    selected: frozenset[str],
    *,
    recipient: str,
    label: str,
    expected: str = "",
    capability_labels: Mapping[str, str] | None = None,
) -> str:
    escape = html.escape
    fields = {
        "namespace": namespace,
        "control_revision": control_revision,
        "expected": expected,
        "recipient": recipient,
    }
    parts = [f'<form method="post" action="{escape(action, quote=True)}">']
    parts.extend(
        f'<input type="hidden" name="{escape(key, quote=True)}" '
        f'value="{escape(value, quote=True)}">'
        for key, value in fields.items()
    )
    parts.append(f"<p>{escape(label)}</p>")
    for capability in sorted(policy.capabilities):
        checked = " checked" if capability in selected else ""
        parts.append(
            f'<label><input type="checkbox" name="capability" '
            f'value="{escape(capability, quote=True)}"{checked}>'
            f"{escape((capability_labels or {}).get(capability, capability))}</label>"
        )
    button = "Update permissions" if expected else "Share"
    parts.append(f'<button type="submit">{button}</button></form>')
    return "".join(parts)


def routes(
    people: People,
    auth: Authentication,
    hooks: Hooks,
    *,
    origin: str,
    prefix: str = "/connections",
    mount_path: str = "",
    identity: object | None = None,
) -> list[Route]:
    """Generic home/choose/share/revoke/leave and provider action routes.

    Mount alongside signin-window's OIDC routes, not over its login/callback
    paths. Provider actions receive only the authenticated owner. All mutations
    require a fresh session, one exact Origin and a pinned immutable identity.
    Optional identity is the host's signin-window PageIdentity; the library
    forwards it unchanged to the shared renderer, never substituting its version.
    """
    if identity is not None and "identity" not in inspect.signature(page).parameters:
        raise ValueError("host build identity requires a renderer with identity support")
    page_options: dict[str, Any] = {"identity": identity} if identity is not None else {}
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("exact web origin required")
    if not prefix.startswith("/") or "//" in prefix or "?" in prefix or "#" in prefix:
        raise ValueError("local route prefix required")
    if mount_path and (
        not mount_path.startswith("/")
        or "//" in mount_path
        or "?" in mount_path
        or "#" in mount_path
    ):
        raise ValueError("local mount path required")
    route_prefix = prefix.rstrip("/")
    prefix = mount_path.rstrip("/") + route_prefix
    controls = Controls(people)

    def failure(message: str, status: int) -> HTMLResponse:
        return HTMLResponse(
            page(
                "My connections",
                f'<p role="alert">{html.escape(message)}</p>',
                login_url=prefix + "/login",
                **page_options,
            ),
            status_code=status,
            headers=HEADERS,
        )

    def contact(person: str, identity: dict[str, Any], *, explicit: bool = False) -> None:
        if hooks.enroll is not None:
            hooks.enroll(person)
        people.contact(
            person,
            namespaces=hooks.namespaces(person),
            identity=Identity(identity["issuer"], identity["sub"]),
            label=identity.get("label"),
            explicit=explicit,
        )

    def actor(
        request: Request, *, first_contact: bool = False
    ) -> tuple[str, dict[str, Any]] | None:
        identity = auth.identity(request)
        if identity is None:
            return None
        person = hooks.actor(identity)
        if person is None:
            return None
        identifier(person)
        try:
            if first_contact:
                contact(person, identity)
            elif not people.store.exists(person):
                return person, identity
            binding = people.read(person)["identity"]
            if (
                binding is not None
                and binding != Identity(identity["issuer"], identity["sub"]).record()
            ):
                return None
            people.require_admitted(person)
        except (StateError, KeyError, ValueError):
            return None
        return person, identity

    async def home(request: Request) -> Response:
        if auth.identity(request) is None:
            return RedirectResponse(prefix + "/login", status_code=303, headers=HEADERS)
        found = actor(request, first_contact=True)
        if found is None:
            return auth.refused(request)
        person, _ = found
        fresh = auth.require_fresh(request, next=prefix + "/", action="manage connections") is None
        roster = people.roster()
        unavailable_people: set[str] = set()
        for entry in roster:
            if entry.available:
                try:
                    people.refresh(entry.id)
                except StateError:
                    unavailable_people.add(entry.id)
        roster = people.roster()
        labels = {entry.id: entry.label for entry in roster}

        def label(member: str) -> str:
            return labels.get(member, member)

        namespaces = list(hooks.namespaces(person))
        capability_names = {
            namespace: dict(hooks.capability_labels(namespace)) if hooks.capability_labels else {}
            for namespace in namespaces
        }
        ready: dict[tuple[str, str], bool] = {}
        for entry in roster:
            if entry.available:
                for namespace in namespaces:
                    ready[entry.id, namespace] = _connection_ready(hooks, entry.id, namespace)
        # Provider rendering runs before the authority transaction. The hook
        # returns trusted markup and must escape its own provider-sourced data.
        fragments = {
            namespace: hooks.render_namespace(person, namespace)
            if fresh and hooks.render_namespace
            else ""
            for namespace in namespaces
        }
        status_fragments = {
            namespace: hooks.render_namespace_status(person, namespace)
            if hooks.render_namespace_status
            else ""
            for namespace in namespaces
        }
        parts: list[str] = []
        if not fresh:
            parts.append(
                "<p>Confirm your sign-in to manage connections. "
                f'<a href="{html.escape(auth.step_up_url(prefix + "/"), quote=True)}">'
                "Confirm your sign-in</a></p>"
            )

        def mutation_form(action: str, label: str, fields: Mapping[str, str]) -> str:
            return _form(action, label, fields) if fresh else ""

        try:
            with people.store.lock():
                people.require_admitted(person)
                parts.append(
                    '<p class="muted">Signed in to Connections as '
                    + html.escape(label(person))
                    + "</p>"
                )
                for index, namespace in enumerate(namespaces):
                    row = people.namespace(person, namespace)
                    policy = hooks.policy(namespace)
                    control = row["control"]
                    parts.append(
                        f'<article aria-labelledby="connection-{index}">'
                        f'<h2 id="connection-{index}">{html.escape(namespace)}</h2>'
                    )
                    parts.append(status_fragments[namespace])
                    parts.append(fragments[namespace])
                    choice = row["selection"]["choice"]
                    own_active = control["state"] == "active" and ready.get(
                        (person, namespace), False
                    )
                    if choice and choice["owner"] == person and not own_active:
                        parts.append(
                            "<p>Your account is not connected. "
                            "Connect it or choose a shared account.</p>"
                        )
                    elif choice:
                        try:
                            _, selected_grant = people.selected(person, namespace, policy=policy)
                            if choice["owner"] in unavailable_people:
                                raise StateError()
                            if not ready.get((choice["owner"], namespace), False):
                                raise StateError()
                            controls.require_active(choice["owner"], namespace)
                        except (StateError, ConnectionError):
                            parts.append(
                                "<p>The selected account is unavailable. "
                                "Choose an account to continue.</p>"
                            )
                        else:
                            parts.append(
                                f"<p>Using {html.escape(label(choice['owner']))}'s account</p>"
                            )
                            if selected_grant is not None:
                                parts.append(
                                    _permissions(
                                        selected_grant.capabilities,
                                        policy,
                                        capability_names[namespace],
                                    )
                                )
                    elif not own_active:
                        parts.append(
                            "<p>Your account is not connected. "
                            "Connect it or choose a shared account.</p>"
                        )
                    else:
                        parts.append("<p>Choose an account to continue.</p>")
                    parts.append(
                        mutation_form(
                            prefix + "/choose",
                            "Use my account",
                            {
                                "namespace": namespace,
                                "owner": person,
                                "grant": "",
                                "expected": row["selection"]["revision"],
                            },
                        )
                    )
                    parts.append("<h3>Shared accounts available to me</h3>")
                    offers, unavailable = people.offers(person, namespace, policy=policy)
                    if not offers and not unavailable and not unavailable_people:
                        parts.append('<p class="muted">No shared accounts are available.</p>')
                    for offer in offers:
                        if offer["owner"] in unavailable_people:
                            continue
                        parts.append(f"<p>Shared by {html.escape(label(offer['owner']))}</p>")
                        parts.append(
                            _permissions(
                                offer["grant"].capabilities, policy, capability_names[namespace]
                            )
                        )
                        parts.append(
                            mutation_form(
                                prefix + "/choose",
                                "Use " + label(offer["owner"]),
                                {
                                    "namespace": namespace,
                                    "owner": offer["owner"],
                                    "grant": offer["grant"].revision,
                                    "expected": row["selection"]["revision"],
                                },
                            )
                        )
                        parts.append(
                            mutation_form(
                                prefix + "/leave",
                                "Leave shared account"
                                if choice and choice["owner"] == offer["owner"]
                                else "Decline shared account",
                                {
                                    "namespace": namespace,
                                    "owner": offer["owner"],
                                    "expected": offer["grant"].revision,
                                },
                            )
                        )
                    if unavailable or unavailable_people:
                        parts.append("<p>Some connections are unavailable.</p>")
                    parts.append("<h3>Shared with</h3>")
                    if not own_active:
                        parts.append("<p>Connect first to share.</p>")
                    elif not row["shares"]:
                        parts.append('<p class="muted">You are not sharing this account.</p>')
                    for member, offered in row["shares"].items():
                        parts.append(f"<p>Shared with {html.escape(label(member))}</p>")
                        if (
                            fresh
                            and own_active
                            and any(
                                entry.id == member
                                and entry.active
                                and entry.available
                                and entry.id not in unavailable_people
                                for entry in roster
                            )
                        ):
                            parts.append(
                                _share_form(
                                    prefix + "/share",
                                    namespace,
                                    control["revision"],
                                    policy,
                                    frozenset(offered["capabilities"]),
                                    recipient=member,
                                    label=label(member),
                                    expected=offered["revision"],
                                    capability_labels=capability_names[namespace],
                                )
                            )
                        parts.append(
                            mutation_form(
                                prefix + "/revoke",
                                "Stop sharing with " + label(member),
                                {
                                    "namespace": namespace,
                                    "recipient": member,
                                    "expected": offered["revision"],
                                    "control_revision": control["revision"],
                                },
                            )
                        )
                    defaults = (
                        hooks.default_capabilities(namespace)
                        if hooks.default_capabilities
                        else frozenset()
                    )
                    if not defaults <= policy.capabilities:
                        raise ValueError("default capabilities must be declared")
                    if fresh and own_active:
                        for entry in roster:
                            if (
                                entry.id == person
                                or entry.id in row["shares"]
                                or not entry.active
                                or not entry.available
                                or entry.id in unavailable_people
                            ):
                                continue
                            parts.append(
                                _share_form(
                                    prefix + "/share",
                                    namespace,
                                    control["revision"],
                                    policy,
                                    defaults,
                                    recipient=entry.id,
                                    label=entry.label,
                                    capability_labels=capability_names[namespace],
                                )
                            )
                    parts.append("</article>")
        except StateError:
            return failure("Connection controls unavailable.", 409)
        if fresh:
            parts.append(
                f'<p><a href="{html.escape(auth.step_up_url(prefix + "/"), quote=True)}">'
                "Confirm your sign-in</a></p>"
            )
        return HTMLResponse(
            page("My connections", "".join(parts), login_url=prefix + "/login", **page_options),
            headers=HEADERS,
        )

    def mutation(action: str) -> Callable[[Request], Awaitable[Response]]:
        async def handle(request: Request) -> Response:
            found = actor(request)
            if found is None or request.headers.getlist("origin") != [origin]:
                return auth.refused(request)
            person, identity = found
            fresh = auth.require_fresh(request, next=prefix + "/", action="change this connection")
            if fresh is not None:
                return fresh
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/x-www-form-urlencoded"
            ):
                return failure("Invalid connection form.", 400)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 16384:
                    return failure("Connection form too large.", 413)
            try:
                parsed_form = parse_qs(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                    max_num_fields=128,
                    strict_parsing=True,
                )
                if any(
                    len(values) != 1 for key, values in parsed_form.items() if key != "capability"
                ):
                    return failure("Invalid connection form.", 400)
                form = {key: values[0] for key, values in parsed_form.items()}
                try:
                    namespace_field = (
                        hooks.provider_namespace_field if action in hooks.actions else "namespace"
                    )
                    namespace = identifier(form[namespace_field])
                except (KeyError, ValueError):
                    return failure("Invalid connection namespace.", 400)
                if namespace not in hooks.namespaces(person):
                    return failure("Invalid connection namespace.", 400)
                contact(person, identity, explicit=True)
                if action in {"choose", "share"}:
                    people.refresh(form["owner"] if action == "choose" else form["recipient"])
                if action == "share" and not _connection_ready(hooks, person, namespace):
                    raise StateError("owner_reconnect")
                with people.store.lock():
                    policy = hooks.policy(namespace)
                    if action == "choose":
                        people.select(
                            person,
                            namespace,
                            form["owner"],
                            policy=policy,
                            expected=form["expected"],
                            grant_revision=form.get("grant") or None,
                        )
                    elif action == "leave":
                        people.leave(person, namespace, form["owner"], expected=form["expected"])
                    elif action in ("share", "revoke"):
                        value = controls.status(person, namespace)
                        if form.get("control_revision") != value["revision"]:
                            raise StateError("account_changed")
                        if action == "share":
                            controls.require_active(person, namespace)
                            people.offer(
                                person,
                                namespace,
                                form["recipient"],
                                policy=policy,
                                capabilities=frozenset(parsed_form.get("capability", [])),
                                expected=form.get("expected") or None,
                            )
                        elif action == "revoke":
                            people.revoke(
                                person, namespace, form["recipient"], expected=form["expected"]
                            )
                if action in hooks.actions:
                    # Provider/browser I/O runs outside the short authority lock.
                    return await hooks.actions[action](request, person, namespace, form)
            except (KeyError, ValueError, UnicodeError):
                return failure("Invalid connection form.", 400)
            except (StateError, ConnectionError):
                return failure("This connection changed. Reload and try again.", 409)
            return RedirectResponse(prefix + "/", status_code=303, headers=HEADERS)

        return handle

    reserved = {"choose", "share", "revoke", "leave", "login", "callback", "logout"}
    identifier(hooks.provider_namespace_field)
    if set(hooks.actions) & reserved:
        raise ValueError("provider actions cannot replace generic or authentication routes")
    actions = {"choose", "share", "revoke", "leave", *hooks.actions}
    for action in actions:
        identifier(action)
    return [
        Route(route_prefix + "/", home, methods=["GET"]),
        *[
            Route(route_prefix + "/" + action, mutation(action), methods=["POST"])
            for action in sorted(actions)
        ],
    ]
