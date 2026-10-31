"""Escaped native HTML; presentation confers no authority."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html import escape


def action_form(action: str, fields: Mapping[str, str], label: str, *, danger: bool = False) -> str:
    """The host checks identity, Origin and revisions on every submission."""
    if (
        not action.startswith("/")
        or action.startswith("//")
        or "\\" in action
        or any(ord(c) < 32 or ord(c) == 127 for c in action)
    ):
        raise ValueError("local absolute action required")
    hidden = "".join(
        f'<input type="hidden" name="{escape(key, quote=True)}" '
        f'value="{escape(value, quote=True)}">'
        for key, value in fields.items()
    )
    style = "danger" if danger else "secondary"
    return (
        f'<form method="post" action="{escape(action, quote=True)}">{hidden}'
        f'<button class="{style}">{escape(label, quote=False)}</button></form>'
    )


@dataclass(frozen=True)
class Offer:
    label: str
    action: str
    fields: Mapping[str, str]
    button: str
    detail: str = ""


def selection_controls(summary: str, offers: Sequence[Offer]) -> str:
    """Show selection alongside independent owned-connection management."""
    body = (
        '<section aria-label="Account selection"><p role="status">'
        f"{escape(summary, quote=False)}</p>"
    )
    for item in offers:
        body += f"<div><p>{escape(item.label, quote=False)}</p>"
        if item.detail:
            body += f'<p class="muted">{escape(item.detail, quote=False)}</p>'
        body += action_form(item.action, item.fields, item.button) + "</div>"
    return body + "</section>"
