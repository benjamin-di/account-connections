"""Optional Starlette management routes using signin-window authentication.

The host supplies verified identity mapping and provider-only actions. Route
handlers never accept an actor or credential payload from submitted fields.
"""

from __future__ import annotations

import html
import inspect
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

from signin_window.connections import SCRIPT_SOURCE, Suite, badge, page
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from . import management
from .controls import Controls
from .people import Identity, People, Policy
from .rules import ConnectionError
from .storage import StateError, identifier

HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src {SCRIPT_SOURCE} {management.SCRIPT_SOURCE}; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    # no-referrer makes HTML POST use Origin:null in browsers, which our exact
    # Origin fence correctly refuses. Keep same-origin forms usable while
    # withholding the page URL from cross-origin destinations.
    "Referrer-Policy": "same-origin",
}


class Authentication(Protocol):
    def identity(self, request: Any) -> dict[str, Any] | None: ...
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


def _form(action: str, label: str, fields: Mapping[str, str], *, button_class: str = "") -> str:
    escape = html.escape
    hidden = "".join(
        f'<input type="hidden" name="{escape(key, quote=True)}" '
        f'value="{escape(value, quote=True)}">'
        for key, value in fields.items()
    )
    cls = f' class="{escape(button_class, quote=True)}"' if button_class else ""
    return (
        f'<form data-management data-account="{escape(fields.get("namespace", ""), quote=True)}" '
        f'method="post" action="{escape(action, quote=True)}">{hidden}'
        f'<button type="submit"{cls}>{escape(label)}</button></form>'
    )


def _avatar(text: str) -> str:
    initial = text.strip()[:1] or "?"
    return f'<span class="avatar" aria-hidden="true">{html.escape(initial)}</span>'


def _permission_facts(granted: frozenset[str], policy: Policy, labels: Mapping[str, str]) -> str:
    def names(capabilities: frozenset[str]) -> str:
        return (
            ", ".join(html.escape(labels.get(item, item)) for item in sorted(capabilities))
            or "none"
        )

    parts = [f"<dt>Granted permissions</dt><dd>{names(granted)}</dd>"]
    withheld = policy.capabilities - granted
    if withheld:
        parts.append(f"<dt>Not shared</dt><dd>{names(withheld)}</dd>")
    return "".join(parts)


def _hero(
    title: str,
    namespaces: Sequence[str],
    summaries: Sequence[tuple[str, str, str]],
) -> str:
    """One top-of-page hero card summarizing assistant connection status."""
    connected = [(ns, detail) for ns, state, detail in summaries if state in ("own", "shared")]
    unavailable = [ns for ns, state, _ in summaries if state == "unavailable"]
    choose_needed = [ns for ns, state, _ in summaries if state == "choose"]
    heading = "Your assistant’s account" if len(namespaces) == 1 else title
    if len(namespaces) == 1 and summaries:
        ns, state, detail = summaries[0]
        safe_ns, safe_detail = html.escape(ns), html.escape(detail)
        if state == "own":
            pill = badge("Connected", "ok")
            body = f'<p><strong>{safe_ns}</strong></p><p class="muted">{safe_detail}</p>'
            actions = ""
        elif state == "shared":
            pill = badge("In use", "ok")
            body = f'<p><strong>{safe_detail}</strong></p><p class="muted">Shared with you.</p>'
            actions = ""
        elif state == "unavailable":
            pill = badge("Action needed", "warn")
            body = (
                '<p class="muted">The selected account is unavailable. Choose an account below.</p>'
            )
            actions = (
                '<div class="actions">'
                '<a class="button" href="#connection-0">Review account</a></div>'
            )
        elif state == "choose":
            pill = badge("Choose account", "info")
            body = '<p class="muted">Choose an account below for your assistant to use.</p>'
            actions = (
                '<div class="actions">'
                '<a class="button" href="#connection-0">Choose account</a></div>'
            )
        else:
            pill = badge("Sign-in needed", "warn")
            body = '<p class="muted">Connect your account below or choose a shared account.</p>'
            actions = (
                f'<div class="actions"><a class="button" href="#connection-0">'
                f"Connect {html.escape(ns)}</a></div>"
            )
    elif connected:
        pill = (
            badge("Connected", "ok")
            if len(connected) == len(namespaces)
            else badge(f"{len(connected)} of {len(namespaces)} connected", "ok")
        )
        names = ", ".join(html.escape(ns) for ns, _ in connected)
        body = f'<p><strong>{names}</strong></p><p class="muted">Ready for your assistant.</p>'
        actions = ""
    elif unavailable:
        pill = badge("Action needed", "warn")
        body = '<p class="muted">A selected account is unavailable. Review your accounts below.</p>'
        actions = (
            '<div class="actions"><a class="button" href="#connection-0">Review accounts</a></div>'
        )
    elif choose_needed:
        pill = badge("Choose account", "info")
        body = '<p class="muted">Choose an account below for your assistant to use.</p>'
        actions = (
            '<div class="actions"><a class="button" href="#connection-0">Choose account</a></div>'
        )
    else:
        pill = badge("Sign-in needed", "warn")
        body = '<p class="muted">Connect an account below or choose a shared account.</p>'
        target = html.escape(namespaces[0]) if namespaces else "account"
        actions = (
            f'<div class="actions"><a class="button" href="#connection-0">'
            f"Connect {target}</a></div>"
            if namespaces
            else ""
        )
    return (
        '<section class="panel hero"><div class="card-head">'
        f"<h2>{html.escape(heading)}</h2>{pill}</div>{body}{actions}</section>"
    )


def routes(
    people: People,
    auth: Authentication,
    hooks: Hooks,
    *,
    origin: str,
    prefix: str = "/connections",
    mount_path: str = "",
    home_path: str | None = None,
    identity: object | None = None,
    title: str = "My connections",
    intro: str = "",
    suite: Suite | Callable[[Request], Suite | None] | None = None,
) -> list[Route]:
    """Generic home/choose/share/revoke/leave and provider action routes.

    Mount alongside signin-window's OIDC routes, not over its login/callback
    paths. Provider actions receive only the authenticated owner. All mutations
    require a valid app session, one exact Origin and a pinned immutable identity.
    Optional identity is the host's signin-window PageIdentity; the library
    forwards it unchanged to the shared renderer, never substituting its version.
    Optional title, intro and suite (a Suite or request callable such as
    BrowserAuth.suite) brand the shared shell and expose the Apps switcher.
    """
    page_params = inspect.signature(page).parameters
    if identity is not None and "identity" not in page_params:
        raise ValueError("host build identity requires a renderer with identity support")
    if suite is not None and "suite" not in page_params:
        raise ValueError("suite navigation requires a renderer with suite support")
    page_options: dict[str, Any] = {"identity": identity} if identity is not None else {}
    supports_suite = "suite" in page_params
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
    if home_path is not None and (
        not isinstance(home_path, str)
        or not re.fullmatch(r"/(?:[A-Za-z0-9_.~-]+/)*[A-Za-z0-9_.~-]*", home_path)
        or any(segment in (".", "..") for segment in home_path.split("/"))
    ):
        raise ValueError("local home path required")
    route_prefix = prefix.rstrip("/")
    prefix = mount_path.rstrip("/") + route_prefix
    home_route = home_path if home_path is not None else route_prefix + "/"
    public_home = mount_path.rstrip("/") + home_route
    has_logout = callable(getattr(auth, "logout", None))
    controls = Controls(people)

    def resolve_suite(request: Request | None) -> Suite | None:
        if not supports_suite:
            return None
        if suite is not None:
            if callable(suite):
                return suite(request) if request is not None else None
            return suite
        if request is not None:
            auth_suite = getattr(auth, "suite", None)
            if callable(auth_suite):
                resolved = auth_suite(request)
                return resolved if isinstance(resolved, Suite) else None
        return None

    def render_page(body: str, *, request: Request | None = None, page_intro: str = "") -> str:
        options = dict(page_options)
        resolved = resolve_suite(request)
        if resolved is not None:
            options["suite"] = resolved
        if page_intro:
            return page(title, body, intro=page_intro, login_url=prefix + "/login", **options)
        return page(title, body, login_url=prefix + "/login", **options)

    def failure(message: str, status: int, request: Request | None = None) -> HTMLResponse:
        body = (
            '<section class="panel"><div class="card-head">'
            "<h2>Action could not finish</h2>"
            + badge("Error", "bad")
            + "</div>"
            + f'<div class="callout bad" role="alert"><p>{html.escape(message)}</p></div>'
            + '<div class="actions">'
            + f'<a class="button" href="{html.escape(public_home, quote=True)}">'
            "Back to connections</a></div></section>"
        )
        return HTMLResponse(
            render_page(body, request=request),
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

    async def home(
        request: Request,
        *,
        failed: tuple[dict[str, str], frozenset[str], str, int] | None = None,
    ) -> Response:
        if auth.identity(request) is None:
            return RedirectResponse(prefix + "/login", status_code=303, headers=HEADERS)
        found = actor(request, first_contact=True)
        if found is None:
            return auth.refused(request)
        person, _ = found
        unavailable_people: set[str] = set()
        roster_failed = False
        try:
            roster = people.roster()
            for entry in roster:
                if entry.available:
                    try:
                        people.refresh(entry.id)
                    except StateError as error:
                        unavailable_people.add(entry.id)
                        if error.code == "directory_unavailable":
                            roster_failed = True
            roster = people.roster()
        except StateError:
            roster = []
            roster_failed = True
        labels = {entry.id: entry.label for entry in roster}

        def label(member: str) -> str:
            return labels.get(member, member)

        namespaces = list(hooks.namespaces(person))
        capability_names = {
            namespace: dict(hooks.capability_labels(namespace)) if hooks.capability_labels else {}
            for namespace in namespaces
        }
        ready: dict[tuple[str, str], bool] = {
            (person, namespace): _connection_ready(hooks, person, namespace)
            for namespace in namespaces
        }
        for entry in roster:
            if entry.available:
                for namespace in namespaces:
                    ready[entry.id, namespace] = _connection_ready(hooks, entry.id, namespace)
        # Provider rendering runs before the authority transaction. The hook
        # returns trusted markup and must escape its own provider-sourced data.
        fragments = {
            namespace: hooks.render_namespace(person, namespace) if hooks.render_namespace else ""
            for namespace in namespaces
        }
        status_fragments = {
            namespace: hooks.render_namespace_status(person, namespace)
            if hooks.render_namespace_status
            else ""
            for namespace in namespaces
        }
        parts: list[str] = []
        summaries: list[tuple[str, str, str]] = []
        try:
            with people.store.lock():
                people.require_admitted(person)
                for index, namespace in enumerate(namespaces):
                    row = people.namespace(person, namespace)
                    policy = hooks.policy(namespace)
                    control = row["control"]
                    choice = row["selection"]["choice"]
                    own_active = control["state"] == "active" and ready.get(
                        (person, namespace), False
                    )
                    parts.append(
                        f'<article aria-labelledby="connection-{index}" tabindex="-1" '
                        f'data-namespace="{html.escape(namespace, quote=True)}">'
                    )
                    if status_fragments[namespace]:
                        parts.append(f'<h2 id="connection-{index}">{html.escape(namespace)}</h2>')
                        parts.append(status_fragments[namespace])
                    else:
                        parts.append(
                            f'<div class="card-head"><h2 id="connection-{index}">'
                            f"{html.escape(namespace)}</h2>"
                            + (
                                badge("Connected", "ok")
                                if own_active
                                else badge("Sign-in needed", "warn")
                            )
                            + "</div>"
                        )
                    selected_usable = False
                    if choice and choice["owner"] == person and not own_active:
                        summaries.append((namespace, "disconnected", ""))
                        parts.append(
                            '<p class="muted">Your account is not connected. '
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
                            summaries.append((namespace, "unavailable", ""))
                            parts.append(
                                '<div class="callout warn"><p>The selected account is unavailable. '
                                "Choose an account to continue.</p></div>"
                            )
                        else:
                            selected_usable = True
                            if choice["owner"] == person:
                                summaries.append((namespace, "own", "Using your account."))
                                facts = "<dt>Assistant uses</dt><dd>Your account</dd>"
                            else:
                                owner_name = html.escape(label(choice["owner"]))
                                summaries.append(
                                    (
                                        namespace,
                                        "shared",
                                        f"{label(choice['owner'])}’s {namespace} account",
                                    )
                                )
                                facts = (
                                    f"<dt>Assistant uses</dt><dd>Using {owner_name}'s account</dd>"
                                )
                            if selected_grant is not None:
                                facts += _permission_facts(
                                    selected_grant.capabilities,
                                    policy,
                                    capability_names[namespace],
                                )
                            parts.append(f'<dl class="facts">{facts}</dl>')
                    elif not own_active:
                        summaries.append((namespace, "disconnected", ""))
                        parts.append(
                            '<p class="muted">Your account is not connected. '
                            "Connect it or choose a shared account.</p>"
                        )
                    else:
                        summaries.append((namespace, "choose", ""))
                        parts.append(
                            '<div class="callout info"><p>Choose an account to continue.</p></div>'
                        )
                    if own_active and not (
                        selected_usable and choice and choice["owner"] == person
                    ):
                        parts.append(
                            '<div class="actions">'
                            + _form(
                                prefix + "/choose",
                                "Use my account",
                                {
                                    "namespace": namespace,
                                    "owner": person,
                                    "grant": "",
                                    "expected": row["selection"]["revision"],
                                },
                                button_class="secondary" if selected_usable else "",
                            )
                            + "</div>"
                        )
                    if fragments[namespace]:
                        if own_active:
                            if row["shares"]:
                                affected = ", ".join(label(member) for member in row["shares"])
                                parts.append(
                                    f'<div class="callout warn"><p>Disconnecting '
                                    f"{html.escape(namespace)} removes your saved provider "
                                    f"connection and stops access for {html.escape(affected)}."
                                    "</p></div>"
                                )
                            else:
                                parts.append(
                                    f'<p class="muted">Disconnecting {html.escape(namespace)} '
                                    "removes your saved provider connection.</p>"
                                )
                        parts.append(fragments[namespace])
                    defaults = (
                        hooks.default_capabilities(namespace)
                        if hooks.default_capabilities
                        else frozenset()
                    )
                    if not defaults <= policy.capabilities:
                        raise ValueError("default capabilities must be declared")
                    eligible = [
                        (entry.id, entry.label)
                        for entry in roster
                        if entry.id != person
                        and entry.id not in row["shares"]
                        and entry.active
                        and entry.available
                        and entry.id not in unavailable_people
                    ]
                    submitted = (
                        failed[0]
                        if failed
                        and failed[0].get("namespace") == namespace
                        and not failed[0].get("expected")
                        else None
                    )
                    refreshing = request.query_params.get("refresh_people") == namespace
                    if row["shares"]:
                        parts.append(
                            '<section class="sharing-list">'
                            '<h3>People with access</h3><ul class="rows">'
                        )
                        for member, offered in row["shares"].items():
                            member_name = label(member)
                            member_submitted = (
                                failed[0]
                                if failed
                                and failed[0].get("namespace") == namespace
                                and failed[0].get("recipient") == member
                                and failed[0].get("expected")
                                else None
                            )
                            parts.append(
                                '<li><div class="who">'
                                + _avatar(member_name)
                                + f"<span><b>{html.escape(member_name)}</b></span></div>"
                                + '<div class="share-details"><dl class="facts">'
                                + _permission_facts(
                                    frozenset(offered["capabilities"]),
                                    policy,
                                    capability_names[namespace],
                                )
                                + "</dl>"
                                + management.share_form(
                                    prefix,
                                    namespace,
                                    member_submitted.get("control_revision", "")
                                    if member_submitted
                                    else control["revision"],
                                    policy,
                                    failed[1] & policy.capabilities
                                    if member_submitted and failed
                                    else frozenset(offered["capabilities"]),
                                    form_id=f"share-{index}-{member}",
                                    people=(),
                                    labels=capability_names[namespace],
                                    recipient=member,
                                    recipient_label=member_name,
                                    expected=member_submitted.get("expected", "")
                                    if member_submitted
                                    else offered["revision"],
                                    can_share=own_active
                                    and any(
                                        entry.id == member
                                        and entry.active
                                        and entry.available
                                        and member not in unavailable_people
                                        for entry in roster
                                    ),
                                    error=failed[2] if member_submitted and failed else "",
                                    opened=bool(member_submitted),
                                    renewing=offered["policy"] != policy.version,
                                    home_url=public_home,
                                )
                                + "</div></li>"
                            )
                        parts.append("</ul></section>")
                    if own_active or submitted or refreshing:
                        parts.append(
                            management.share_form(
                                prefix,
                                namespace,
                                submitted.get("control_revision", "")
                                if submitted
                                else (
                                    request.query_params.get(
                                        "control_revision", control["revision"]
                                    )
                                    if refreshing
                                    else control["revision"]
                                ),
                                policy,
                                failed[1] & policy.capabilities
                                if submitted and failed
                                else (
                                    frozenset(request.query_params.getlist("capability"))
                                    & policy.capabilities
                                    if request.query_params.get("refresh_people") == namespace
                                    else defaults
                                ),
                                form_id=f"share-{index}-new",
                                people=eligible,
                                labels=capability_names[namespace],
                                recipient=submitted.get("recipient", "")
                                if submitted
                                else (
                                    request.query_params.get("recipient", "")
                                    if request.query_params.get("refresh_people") == namespace
                                    else ""
                                ),
                                roster_failed=roster_failed,
                                unavailable=bool(unavailable_people)
                                or any(not entry.available or not entry.active for entry in roster),
                                can_share=own_active,
                                error=failed[2]
                                if submitted and failed
                                else (
                                    "This account changed or is unavailable. "
                                    "Refresh details before sharing."
                                    if refreshing
                                    and (
                                        not own_active
                                        or request.query_params.get("control_revision")
                                        != control["revision"]
                                    )
                                    else ""
                                ),
                                opened=bool(submitted) or refreshing,
                                home_url=public_home,
                            )
                        )
                    else:
                        parts.append('<p class="muted">Connect first to share.</p>')
                    if (
                        failed
                        and failed[0].get("namespace") == namespace
                        and failed[0].get("expected")
                        and failed[0].get("recipient") not in row["shares"]
                    ):
                        submitted = failed[0]
                        member = submitted.get("recipient", "")
                        parts.append(
                            management.share_form(
                                prefix,
                                namespace,
                                submitted.get("control_revision", ""),
                                policy,
                                failed[1] & policy.capabilities,
                                form_id=f"share-{index}-changed",
                                people=(),
                                labels=capability_names[namespace],
                                recipient=member,
                                recipient_label=label(member),
                                expected=submitted["expected"],
                                can_share=False,
                                error=failed[2],
                                opened=True,
                                home_url=public_home,
                            )
                        )
                    offers, unavailable = people.offers(person, namespace, policy=policy)
                    if offers or unavailable:
                        parts.append('<section class="incoming"><h3>Accounts shared with you</h3>')
                        visible_offers = [
                            offer for offer in offers if offer["owner"] not in unavailable_people
                        ]
                        if visible_offers:
                            parts.append('<ul class="rows">')
                        for offer in visible_offers:
                            owner_name = label(offer["owner"])
                            changed = bool(
                                choice
                                and choice["owner"] == offer["owner"]
                                and choice["grant"] != offer["grant"].revision
                            )
                            available = ready.get((offer["owner"], namespace), False)
                            try:
                                controls.require_active(offer["owner"], namespace)
                            except StateError:
                                available = False
                            selected = bool(
                                choice
                                and choice["owner"] == offer["owner"]
                                and not changed
                                and available
                            )
                            offer_badge = (
                                badge("In use", "ok")
                                if selected
                                else badge("Access changed", "warn")
                                if changed
                                else badge("Unavailable", "neutral")
                                if not available
                                else ""
                            )
                            parts.append(
                                '<li><div class="who">'
                                + _avatar(owner_name)
                                + f"<span><b>{html.escape(owner_name)}</b>"
                                "<small>Shared with you</small></span></div>"
                                + offer_badge
                                + '<div class="share-details"><dl class="facts">'
                                + _permission_facts(
                                    offer["grant"].capabilities,
                                    policy,
                                    capability_names[namespace],
                                )
                                + "</dl>"
                            )
                            if changed:
                                parts.append(
                                    '<div class="callout warn"><p>Access changed. '
                                    "Choose this account again.</p></div>"
                                )
                            if not available:
                                parts.append(
                                    '<div class="callout warn"><p>This shared account is '
                                    "unavailable. The owner may need to reconnect.</p></div>"
                                )
                            action_buttons: list[str] = []
                            if available:
                                action_buttons.append(
                                    _form(
                                        prefix + "/choose",
                                        "Use this account again" if changed else "Use this account",
                                        {
                                            "namespace": namespace,
                                            "owner": offer["owner"],
                                            "grant": offer["grant"].revision,
                                            "expected": row["selection"]["revision"],
                                        },
                                        button_class="secondary" if selected else "",
                                    )
                                )
                            action_buttons.append(
                                _form(
                                    prefix + "/leave",
                                    "Leave account"
                                    if choice and choice["owner"] == offer["owner"]
                                    else "Decline access",
                                    {
                                        "namespace": namespace,
                                        "owner": offer["owner"],
                                        "expected": offer["grant"].revision,
                                    },
                                    button_class="quiet",
                                )
                            )
                            parts.append(
                                '<div class="actions">'
                                + "".join(action_buttons)
                                + '</div><p class="muted">Leaving or declining removes this '
                                "access. The owner must share again; no replacement account "
                                "is selected.</p></div></li>"
                            )
                        if visible_offers:
                            parts.append("</ul>")
                        if unavailable or unavailable_people:
                            parts.append('<p class="muted">Some connections are unavailable.</p>')
                        parts.append("</section>")
                    elif unavailable_people:
                        parts.append('<p class="muted">Some connections are unavailable.</p>')
                    parts.append("</article>")
        except StateError:
            return failure("Connection controls unavailable.", 409, request)
        if namespaces:
            parts.insert(0, _hero(title, namespaces, summaries))
        if failed:
            parts.insert(
                0, f'<div class="callout bad" role="alert"><p>{html.escape(failed[2])}</p></div>'
            )
        if has_logout:
            saved_note = (
                "Signing out keeps your saved connection."
                if len(namespaces) == 1
                else "Signing out keeps your saved connections."
            )
            parts.append(
                '<section class="panel"><div class="card-head">'
                f'<p class="muted">{saved_note}</p>'
                f'<form method="post" action="{html.escape(prefix + "/logout", quote=True)}">'
                '<button type="submit" class="quiet">Sign out</button></form>'
                "</div></section>"
            )
        parts.append(f"<style>{management.STYLE}</style><script>{management.SCRIPT}</script>")
        page_intro = intro or f"Signed in as {label(person)}."
        return HTMLResponse(
            render_page("".join(parts), request=request, page_intro=page_intro),
            status_code=failed[3] if failed else 200,
            headers=HEADERS,
        )

    def mutation(action: str) -> Callable[[Request], Awaitable[Response]]:
        async def handle(request: Request) -> Response:
            found = actor(request)
            if found is None or request.headers.getlist("origin") != [origin]:
                return auth.refused(request)
            person, identity = found
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/x-www-form-urlencoded"
            ):
                return failure("Invalid connection form.", 400, request)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 16384:
                    return failure("Connection form too large.", 413, request)
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
                    return failure("Invalid connection form.", 400, request)
                form = {key: values[0] for key, values in parsed_form.items()}
                try:
                    namespace_field = (
                        hooks.provider_namespace_field if action in hooks.actions else "namespace"
                    )
                    namespace = identifier(form[namespace_field])
                except (KeyError, ValueError):
                    return failure("Invalid connection namespace.", 400, request)
                if namespace not in hooks.namespaces(person):
                    return failure("Invalid connection namespace.", 400, request)
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
                            current = people.namespace(person, namespace)["shares"].get(
                                form["recipient"]
                            )
                            if (
                                current
                                and current["revision"] == form.get("expected")
                                and current["policy"] == policy.version
                                and frozenset(current["capabilities"])
                                == frozenset(parsed_form.get("capability", []))
                            ):
                                raise ValueError("permissions_unchanged")
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
                if action == "share" and "form" in locals():
                    return await home(
                        request,
                        failed=(
                            form,
                            frozenset(parsed_form.get("capability", [])),
                            "Invalid connection form. Check the person and permissions, "
                            "then refresh details.",
                            400,
                        ),
                    )
                return failure("Invalid connection form.", 400, request)
            except (StateError, ConnectionError):
                if action in {"share", "revoke"} and "form" in locals():
                    return await home(
                        request,
                        failed=(
                            form,
                            frozenset(parsed_form.get("capability", [])),
                            "This connection changed. Refresh details before retrying.",
                            409,
                        ),
                    )
                return failure("This connection changed. Reload and try again.", 409, request)
            return RedirectResponse(public_home, status_code=303, headers=HEADERS)

        return handle

    async def legacy_home(_request: Request) -> Response:
        return RedirectResponse(public_home, status_code=308, headers=HEADERS)

    reserved = {"choose", "share", "revoke", "leave", "login", "callback", "logout"}
    identifier(hooks.provider_namespace_field)
    if set(hooks.actions) & reserved:
        raise ValueError("provider actions cannot replace generic or authentication routes")
    actions = {"choose", "share", "revoke", "leave", *hooks.actions}
    for action in actions:
        identifier(action)
    if home_route.rstrip("/") in {route_prefix + "/" + name for name in reserved | actions}:
        raise ValueError("home path cannot collide with action or authentication routes")
    result = [
        Route(home_route, home, methods=["GET"]),
        *[
            Route(route_prefix + "/" + action, mutation(action), methods=["POST"])
            for action in sorted(actions)
        ],
    ]
    if home_route != route_prefix + "/":
        result.append(Route(route_prefix + "/", legacy_home, methods=["GET"]))
        if route_prefix and home_route != route_prefix:
            result.append(Route(route_prefix, legacy_home, methods=["GET"]))
    return result
