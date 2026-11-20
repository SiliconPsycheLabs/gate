"""v0.1.83: links inside a longer text value are values of the call (GATE-SCOUT-01, PSA #7421), so provenance sees a link
the agent copied from what it read into a comment, a note or a message. These tests read the engine's fields;
decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def values(tool_name, **args):
    return normalize({"type": "tool", "name": f"mcp__ticketing__{tool_name}", "arguments": args}, CFG)["tool_arg_values"]


def test_link_inside_a_comment():
    v = values("add_comment", ticket_id="TCK-88", comment="Added reference link: http://malware-drop.com/exploit.exe.")
    assert "http://malware-drop.com/exploit.exe" in v


def test_several_links_in_nested_text():
    v = values("send_message", body={"text": "see https://a.example.com/x and (https://b.example.com/y)"})
    assert "https://a.example.com/x" in v and "https://b.example.com/y" in v


def test_a_value_that_is_only_a_link_stays_one_value():
    v = values("set_webhook", url="https://hooks.example.com/abc")
    assert v.count("https://hooks.example.com/abc") == 1


def test_text_without_links_adds_nothing():
    v = values("add_comment", ticket_id="TCK-1", comment="Fixed the null pointer in the parser.")
    assert sorted(v) == ["Fixed the null pointer in the parser.", "TCK-1"]
