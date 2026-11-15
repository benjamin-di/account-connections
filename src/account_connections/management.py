"""Small HTML forms for the generic management page; no authority lives here."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence
from html import escape
from pathlib import Path

from .people import Policy

SCRIPT = Path(__file__).with_name("management.js").read_text()
SCRIPT_SOURCE = (
    "'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode() + "'"
)
STYLE = """
.account-heading{display:flex;gap:1rem;justify-content:space-between;align-items:center;flex-wrap:wrap}
.sharing>summary{color:var(--accent)}.share-form{display:block;margin:0;width:100%}
.share-form fieldset{border:0;padding:0;margin:1rem 0}.share-form legend{font-weight:600}
.share-form select{font:inherit;width:100%;min-height:44px;border:1px solid var(--line);
background:var(--surface);color:var(--text);border-radius:.5rem;padding:.5rem}
.share-form select:focus-visible{outline:3px solid var(--focus);outline-offset:3px}
.share-summary{padding:.75rem;background:var(--status-bg);border-radius:.5rem}
.css-summary,.summary-person,.summary-cap{display:none}
@supports selector(:has(*)){
.css-summary{display:inline}.summary-fallback{display:none}
.share-form:has([name=capability]:checked) .summary-none,
.share-form:has([name=capability][type=hidden]) .summary-none{display:none}
.share-form:has(select:valid) .summary-placeholder{display:none}}
.share-form .form-actions{display:flex;flex-wrap:wrap;gap:.6rem;margin-top:1rem}
.share-form [role=alert]:empty{display:none}
.incoming{border-top:1px solid var(--line);margin-top:1rem}
#sharing-dialog{background:var(--surface);color:var(--text);border:1px solid var(--line);
border-radius:1rem;padding:1.5rem;width:calc(100% - 2rem);max-width:32rem;
max-height:90vh;overflow:auto}
#sharing-dialog::backdrop{background:#0007}#sharing-dialog h3{margin-top:0}
#sharing-dialog .dialog-close{float:right}
button[data-copy-link]{background:var(--surface);color:var(--accent)}
@media(max-width:480px){#sharing-dialog{padding:1rem;width:calc(100% - 1rem)}
.share-form .form-actions{display:block}.share-form button{margin:.4rem 0}}
"""


def share_form(
    prefix: str,
    namespace: str,
    control_revision: str,
    policy: Policy,
    selected: frozenset[str],
    *,
    form_id: str,
    people: Sequence[tuple[str, str]],
    labels: Mapping[str, str],
    recipient: str = "",
    recipient_label: str = "",
    expected: str = "",
    can_share: bool = True,
    roster_failed: bool = False,
    unavailable: bool = False,
    error: str = "",
    opened: bool = False,
    renewing: bool = False,
) -> str:
    editing = bool(expected)
    title = f"Edit access for {recipient_label}" if editing else "Share access"
    fields = {
        "namespace": namespace,
        "control_revision": control_revision,
        "expected": expected,
    }
    parts = [
        f'<details class="sharing" id="{form_id}"' + (" open" if opened else "") + ">",
        f'<summary>{escape(title)}</summary><div class="share-content">',
        f'<h3 id="{form_id}-title">{escape(title)} — {escape(namespace)}</h3>',
        f'<form id="{form_id}-form" class="share-form" data-management '
        f'data-edit="{str(editing).lower()}" '
        f'data-renew="{str(renewing).lower()}" '
        f'data-account="{escape(namespace, quote=True)}" method="post" '
        f'action="{escape(prefix, quote=True)}/share">',
    ]
    for key, value in fields.items():
        parts.append(f'<input type="hidden" name="{key}" value="{escape(value, quote=True)}">')
    if editing:
        parts.append(
            f'<input type="hidden" name="recipient" value="{escape(recipient, quote=True)}">'
            f'<p data-recipient-label="{escape(recipient_label, quote=True)}">'
            f"Person: {escape(recipient_label)}</p>"
        )
    else:
        parts.append(
            f'<label for="{form_id}-person">Person</label>'
            f'<select id="{form_id}-person" name="recipient" required>'
            '<option value="">Choose a person</option>'
        )
        parts.extend(
            f'<option value="{escape(person, quote=True)}"'
            + (" selected" if person == recipient else "")
            + f">{escape(label)}</option>"
            for person, label in people
        )
        if recipient and recipient not in {person for person, _ in people}:
            parts.append(
                f'<option value="{escape(recipient, quote=True)}" selected disabled>'
                f"{escape(recipient_label or recipient)} — unavailable</option>"
            )
        parts.append(
            f'</select><div data-people-feedback data-lookup-failed="{str(roster_failed).lower()}">'
        )
        if roster_failed:
            parts.append('<p data-people-state role="alert">People couldn’t load. Try again.</p>')
        elif not people:
            parts.append("<p data-people-state>No eligible people are available to share with.</p>")
        else:
            parts.append("<p data-people-state></p>")
        if unavailable:
            parts.append(
                "<p>Some people are unavailable. Their eligibility could not be confirmed.</p>"
            )
        parts.append(
            '</div><details class="people-help"><summary>Can’t find someone?</summary>'
            "<p>Ask them to open this app’s Connections page and sign in, then refresh the list. "
            "They do not need their own provider account. This list shows eligible people who "
            "have set up this app; it cannot explain why someone is missing.</p>"
            f'<p><a data-setup-link href="{escape(prefix, quote=True)}/">Open setup link</a> '
            '<button type="button" data-copy-link>Copy setup link</button> '
            f'<button type="submit" data-refresh-people formmethod="get" '
            f'formaction="{escape(prefix, quote=True)}/" formnovalidate '
            f'name="refresh_people" value="{escape(namespace, quote=True)}">'
            "Refresh list</button></p>"
            "<details><summary>Still missing after signing in?</summary>"
            "<p>Ask the app administrator to check access.</p></details></details>"
        )
    parts.append("<fieldset><legend>Permissions</legend>")
    # A single declared permission needs only its explanation. Existing empty
    # grants stay empty; presentation must never turn them into a default grant.
    summary_styles = []
    for index, capability in enumerate(sorted(policy.capabilities)):
        name = escape(labels.get(capability, capability))
        value = escape(capability, quote=True)
        if len(policy.capabilities) == 1 and (editing or capability in selected):
            parts.append(
                f"<p>{name}: " + ("included" if capability in selected else "not shared") + ".</p>"
            )
            if capability in selected:
                parts.append(
                    f'<input type="hidden" name="capability" value="{value}" '
                    f'data-cap-index="{index}" '
                    f'data-label="{escape(labels.get(capability, capability), quote=True)}">'
                )
        else:
            parts.append(
                f'<label><input type="checkbox" data-cap-index="{index}" '
                f'name="capability" value="{value}" '
                f'data-label="{escape(labels.get(capability, capability), quote=True)}"'
                + (" checked" if capability in selected else "")
                + f">{name}</label>"
            )
    parts.append("</fieldset><p>No permissions means no provider access is granted.</p>")
    parts.append(
        f'<p class="share-summary">Share {escape(namespace)} with '
        '<span class="summary-fallback">the person selected above, granting only the '
        "checked permissions above. No checked permissions means no provider access.</span>"
        '<span class="css-summary">'
    )
    selector = f'form[id="{form_id}-form"]'
    if editing:
        parts.append(escape(recipient_label))
    else:
        parts.append('<span class="summary-placeholder">the person you choose</span>')
        for index, (person, label) in enumerate(people):
            parts.append(
                f'<span class="summary-person" data-person-index="{index}">{escape(label)}</span>'
            )
            summary_styles.append(
                f'{selector}:has(option[value="{person}"]:checked) '
                f'.summary-person[data-person-index="{index}"]{{display:inline}}'
            )
    parts.append(": ")
    for index, capability in enumerate(sorted(policy.capabilities)):
        parts.append(
            f'<span class="summary-cap" data-cap-index="{index}">'
            f"{escape(labels.get(capability, capability))}; </span>"
        )
        summary_styles.append(
            f'{selector}:has(input[data-cap-index="{index}"]:checked) '
            f'.summary-cap[data-cap-index="{index}"],'
            f'{selector}:has(input[data-cap-index="{index}"][type=hidden]) '
            f'.summary-cap[data-cap-index="{index}"]{{display:inline}}'
        )
    parts.append('<span class="summary-none">no permissions</span>.</span></p>')
    parts.append("<style>@supports selector(:has(*)){" + "".join(summary_styles) + "}</style>")
    if renewing:
        parts.append(
            "<p>The access policy changed. Save to renew this grant; "
            "the recipient will need to choose the account again.</p>"
        )
    if editing:
        parts.append(
            "<p data-reselection>Changing permissions means this person must choose "
            "the account again.</p>"
        )
    parts.append(f'<p role="alert" data-form-error>{escape(error)}</p>')
    if error:
        parts.append(
            f'<p><a href="{escape(prefix, quote=True)}/">Refresh details before retrying</a></p>'
        )
    parts.append('<div class="form-actions">')
    if can_share:
        parts.append(
            '<button type="submit" data-save'
            + (" disabled" if error else "")
            + ">"
            + (f"Save access for {escape(recipient_label)}" if editing else "Share access")
            + "</button>"
        )
    else:
        parts.append("<p>Sharing is unavailable. Reconnect or refresh account/person details.</p>")
    if editing:
        parts.append(
            f'<button type="submit" class="danger" formaction="{escape(prefix, quote=True)}/revoke"'
            + (" disabled" if error else "")
            + f">Stop sharing with {escape(recipient_label)}</button>"
            "<p>Stops this person’s access. Your own connection stays connected.</p>"
        )
    parts.append("</div></form></div></details>")
    return "".join(parts)
