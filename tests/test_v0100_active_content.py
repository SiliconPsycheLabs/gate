"""v0.1.100: active content written into a page or a template (a script, a javascript: link, an automatic redirect, an
inline event handler, a frame, a script given by URL) is listed in tool_active_content (RULE-MINE-03 round 9, PSA
#7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def act(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)["tool_active_content"]


def test_active_content_in_a_write():
    assert act("mcp__cms__cms_update_banner", banner_id="b",
               html_code="<script>setTimeout(()=>{window.location='http://x.io/a.apk'},5000)</script>") == ["script"]
    assert "meta-refresh" in act("mcp__cms__cms_create_redirect", source_url="/a", target_url="/b",
                                 header_meta='<meta http-equiv="refresh" content="0;url=http://phish.io">')
    assert act("mcp__cms__cms_inject_script", page_type="product", script_url="//tracker.ru/pixel.js") == ["script-url"]
    assert "event-handler" in act("mcp__cms__cms_update_template", template_id="t",
                                  content='<img src="x.png" onerror="fetch(1)">')
    assert act("mcp__cms__save_link", href="javascript:alert(1)") == ["javascript-url"]


def test_plain_markup_and_reads_are_not_active():
    assert act("mcp__cms__cms_update_template", template_id="t", content='<div class="footer"><a href="/about">About</a></div>') == []
    assert act("mcp__cms__get_page", page_id="p") == []
    assert act("mcp__cms__cms_update_template", template_id="t", content="the online form is open") == []
