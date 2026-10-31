import pytest

from account_connections.ui import Offer, action_form, selection_controls


def test_escaped_labels_fields_and_status():
    body = selection_controls(
        "<Selected>",
        [
            Offer(
                "Alice <owner>", "/choose", {"owner": '"<alice>'}, "Use this account", "Read & save"
            )
        ],
    )
    assert "&lt;Selected&gt;" in body and "&lt;owner&gt;" in body
    assert 'value="&quot;&lt;alice&gt;"' in body
    assert "Read &amp; save" in body


@pytest.mark.parametrize(
    "action",
    [
        "//example.com",
        "https://example.com",
        "/x\ny",
        "/\\example.invalid/collect",
        "/\t/example.invalid/collect",
    ],
)
def test_external_actions_refused(action):
    with pytest.raises(ValueError):
        action_form(action, {}, "Use")


@pytest.mark.parametrize("codepoint", [*range(32), 127])
def test_all_ascii_controls_are_refused(codepoint):
    with pytest.raises(ValueError):
        action_form("/" + chr(codepoint) + "/example.invalid", {}, "Use")
