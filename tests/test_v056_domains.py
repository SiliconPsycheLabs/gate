"""v0.1.56 (PSA #7802): what an action does in machines and business systems, read by protocol tables. Engine only:
the records, not the rules (the maintained rules are served by the hosted gate)."""

from gate import Config, Gate, PolicySet
from gate.normalize import normalize

T = lambda n, **a: {"type": "tool", "name": n, "arguments": a}
S = lambda c: {"type": "shell", "command": c, "cwd": "/work"}
W = lambda m, u, body=None: dict({"type": "http", "method": m, "url": u}, **({"body": body} if body else {}))
C = Config(workspace="/work")


def rec(a, cfg=C):
    return normalize(a, cfg)


def test_modbus_function_and_register():
    r = rec(T("mcp__modbus__write_register", host="10.0.4.21", address=40001, value=9999))
    assert r["effects"] == ["setpoint"] and r["assets"] == ["modbus:10.0.4.21/40001"] and r["values"] == [9999]
    assert rec(T("mcp__modbus__write_coil", host="h", address=1, value=True))["effects"] == ["actuate"]
    assert rec(T("mcp__modbus__read_holding_registers", host="h", address=1))["effects"] == []


def test_plc_mode_program_force():
    assert rec(T("mcp__s7__set_cpu_mode", host="h", mode="STOP"))["effects"] == ["mode"]
    assert rec(T("mcp__s7__download_block", host="h", block="OB1"))["effects"] == ["program"]
    assert rec(T("mcp__plc__update_firmware", host="h", image="f.bin"))["effects"] == ["program"]
    assert "safety" in rec(T("mcp__plc__force_output", host="h", tag="Q0.1", value=1))["effects"]


def test_gcode_lines():
    r = rec(T("mcp__cnc__send_gcode", machine="m1", gcode="G0 Z-50\nM3 S24000\nG1 X300 F8000"))
    assert set(r["effects"]) == {"motion", "setpoint"} and 24000 in r["values"]
    assert "safety" in rec(T("mcp__octoprint__send_command", commands=["M211 S0"]))["effects"]


def test_ros_mavlink_home():
    assert rec(T("mcp__ros__publish", topic="/cmd_vel", message={}))["effects"] == ["motion"]
    assert "publish" not in rec(T("mcp__ros__publish", topic="/cmd_vel", message={}))["tool_words"]
    assert rec(T("mcp__ros__call_service", service="/safety/reset_estop"))["effects"] == ["safety"]
    assert rec(T("mcp__mavlink__takeoff", vehicle="d", altitude_m=120))["effects"] == ["motion"]
    r = rec(T("mcp__homeassistant__call_service", domain="lock", service="unlock", entity_id="lock.front_door"))
    assert r["effects"] == ["physical_access"] and r["tool_physical_access"]
    assert rec(T("mcp__homeassistant__call_service", domain="light", service="turn_on", entity_id="light.k"))["effects"] == []


def test_sap_tcodes_bapis_odata():
    assert rec(T("mcp__sap__run_transaction", tcode="F110"))["effects"] == ["money"]
    assert rec(T("mcp__sap__run_transaction", tcode="SE38"))["eval_like"]
    r = rec(T("mcp__sap__call_bapi", function="BAPI_VENDOR_CHANGE", params={"IBAN": "DE89370400440532013000"}))
    assert r["effects"] == ["bank_details"] and r["bank_values"] == ["DE89370400440532013000"]
    r = rec(W("PATCH", "https://erp/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartnerBank('1')", '{"IBAN": "x"}'))
    assert r["effects"] == ["bank_details"]
    assert rec(T("mcp__sap__call_function", function="RFC_READ_TABLE"))["effects"] == []


def test_iban_by_checksum_and_bank_fields():
    assert rec(T("mcp__crm__update_contact", id="1", note="DE89370400440532013000"))["effects"] == ["bank_details"]
    assert rec(T("mcp__crm__update_contact", id="1", note="DE89370400440532013001"))["effects"] == []
    assert rec(T("mcp__crm__update_contact", id="1", phone="+39 06 1234"))["effects"] == []


def test_gui_labels():
    assert rec(T("computer", action="left_click", coordinate=[1, 2]))["effects"] == ["gui_opaque"]
    assert rec(T("computer", action="screenshot"))["effects"] == []
    assert rec(T("mcp__playwright__browser_click", element="Confirm transfer", ref="e1"))["effects"] == ["gui_sensitive"]
    assert rec(T("mcp__playwright__browser_click", element="Next page", ref="e1"))["effects"] == []


def test_asset_register_and_envelope():
    cfg = Config(workspace="/work", assets=[{"match": "modbus:10.0.4.21/*", "class": "line", "min": 0, "max": 400,
                                             "max_writes": 5}])
    ok = rec(T("mcp__modbus__write_register", host="10.0.4.21", address=1, value=300), cfg)
    over = rec(T("mcp__modbus__write_register", host="10.0.4.21", address=1, value=900), cfg)
    other = rec(T("mcp__modbus__write_register", host="10.0.9.9", address=1, value=1), cfg)
    assert not ok["value_outside_envelope"] and not ok["asset_undeclared"] and ok["asset_classes"] == ["line"]
    assert ok["asset_max_writes"] == 5
    assert over["value_outside_envelope"]
    assert other["asset_undeclared"]
    assert rec(T("mcp__modbus__write_register", host="h", address=1, value=1))["asset_undeclared"]  # no register


def test_shell_and_code_routes():
    assert rec(S("mbpoll -m tcp -a 1 -r 40001 -t 4 10.0.4.21 9999"))["effects"] == ["setpoint"]
    assert rec(S("mbpoll -m tcp -a 1 -r 40001 -c 4 10.0.4.21"))["effects"] == []
    assert rec(S("mosquitto_pub -h b -t plant/line1/cmd -m START"))["effects"] == ["actuate"]
    assert rec(S("mosquitto_pub -h b -t plant/line1/temp -m 21"))["effects"] == []
    code = "python -c \"from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('h'); c.write_register(1, 5)\""
    assert rec(S(code))["effects"] == ["setpoint"]


def test_session_facts_bank_change_and_asset_writes():
    rules = PolicySet('@id("all") permit (principal, action, resource);')
    g = Gate(rules, C)
    s = g.new_session()
    g.check(T("mcp__xero__update_contact", contact_id="1", bank_account_details="DE89370400440532013000"), s)
    d = g.check(T("mcp__ros__publish", topic="/cmd_vel", message={}), s)
    assert d.record["facts"]["bank_changed_in_session"]
    d = g.check(T("mcp__ros__publish", topic="/cmd_vel", message={}), s)
    assert d.record["facts"]["asset_writes_in_session"] == 1


def test_coding_work_has_no_effect():
    for a in (S("pytest -q"), S("git push origin feature"), T("Edit", file_path="/work/a.py", old_string="a", new_string="b"),
              T("mcp__github__create_pull_request", title="x"), T("mcp__slack__post_message", channel="C", text="hi"),
              W("POST", "https://api.github.com/repos/a/b/issues", '{"title":"x"}')):
        assert rec(a)["effects"] == [], a
