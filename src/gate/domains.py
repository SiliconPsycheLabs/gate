"""What an action does outside software: industrial control, machines, robots, buildings, energy, ERP, accounting,
payroll, signatures, screens, phones and printers (v0.1.56, PSA #7802, GATE-DOMAINS-01).

Every decoder is a closed table: the same call gives the same record. A tool call is read by what its protocol says
(a Modbus function, an OPC UA node, a G-code line, a SAP transaction code, a Home Assistant domain and service), not
by the English words of its name, so a generic dispatcher (`call_service`, `call_bapi`, `run_transaction`,
`write_property`, `computer`) is read as the action it carries.

Fields added to the record:
    effects: what the action does, a set of
        setpoint, actuate, motion, mode, program, safety, physical_access,           (machines and buildings)
        bank_details, ledger_post, money, commitment, filing, pay_change, grant, price, delete,   (business systems)
        gui_opaque, gui_sensitive, call.                                              (screens, phones)
    domain: the protocol or system that was decoded ("modbus", "opcua", "s7", "plc", "bacnet", "mqtt", "gcode",
        "ros", "mavlink", "vehicle", "home", "energy", "sap", "accounting", "payroll", "signature", "commerce",
        "gui", "phone", "print").
    assets: the machine-side targets the action writes to, as "<domain>:<target>" (modbus:10.0.4.21/40001,
        opcua:ns=2;s=Line1.Oven.Setpoint, home:lock.front_door, mqtt:factory/line1/press/cmd, ros:/cmd_vel).
    values: the integer values the action writes (rounded), read against the owner's envelopes.
    asset_classes, asset_undeclared, value_outside_envelope, asset_max_writes: the action read against the owner's
        asset register (Config.assets).
    amount_max: the largest amount in the action's money arguments, in whole units.
    bank_values: bank account values the action writes (an IBAN, an account number), for provenance.
"""

from __future__ import annotations

import fnmatch
import json
import re
from urllib.parse import unquote, urlsplit

PHYSICAL_EFFECTS = {"setpoint", "actuate", "motion", "mode", "program", "safety", "physical_access"}


def default_fields() -> dict:
    return {
        "effects": [],
        "domain": "",
        "assets": [],
        "values": [],
        "asset_classes": [],
        "asset_undeclared": False,
        "value_outside_envelope": False,
        "asset_max_writes": 0,
        "amount_max": 0,
        "bank_values": [],
    }


# ---------------------------------------------------------------------------------------------------------- helpers

def _words(s: str) -> list[str]:
    return [w.lower() for w in re.split(r"[_\-.\s/:]|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", s or "") if w]


def _flat(arguments, depth: int = 0):
    """(key, value) pairs of every scalar in the arguments, keys lower-cased."""
    if depth > 6:
        return
    if isinstance(arguments, dict):
        for k, v in arguments.items():
            if isinstance(v, (dict, list)):
                yield from _flat(v, depth + 1)
            else:
                yield str(k).lower(), v
    elif isinstance(arguments, list):
        for v in arguments:
            if isinstance(v, (dict, list)):
                yield from _flat(v, depth + 1)
            else:
                yield "", v


def _get(arguments, *keys, default=None):
    if not isinstance(arguments, dict):
        return default
    low = {str(k).lower(): v for k, v in arguments.items()}
    for k in keys:
        if k in low and low[k] not in (None, ""):
            return low[k]
    return default


def _num(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return int(round(v))
    if isinstance(v, str):
        m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*", v.replace(",", ""))
        if m:
            return int(round(float(m.group(1))))
    return None


def _nums(v) -> list[int]:
    if isinstance(v, list):
        return [n for x in v for n in _nums(x)]
    n = _num(v)
    return [] if n is None else [n]



def _srv(srv: str, names) -> bool:
    """Whether a server name names one of these systems, by whole words: "ros" is the token ros or ros2-style
    compound, never the letters inside "microsoft"; "ot" never matches "remote" (v0.1.58: v0.1.56 matched substrings,
    so claude-code-remote read as an OT server). Names of 6 letters or more also match as the start or the end of a
    token (homeassistant in homeassistantmcp, charger in evcharger)."""
    toks = [t for t in re.split(r"[_\-.\s:/]+", (srv or "").lower()) if t]
    joined = "".join(toks)
    for n in names:
        nt = [t for t in re.split(r"[_\-.\s]+", n.lower()) if t]
        if not nt:
            continue
        if len(nt) > 1:
            if any(toks[i:i + len(nt)] == nt for i in range(len(toks))) or joined.startswith("".join(nt)):
                return True
        elif nt[0] in toks:
            return True
        elif len(nt[0]) >= 6 and any(t.startswith(nt[0]) or t.endswith(nt[0]) for t in toks):
            return True
    return False

class _Out:
    def __init__(self):
        self.effects: set[str] = set()
        self.domain = ""
        self.assets: list[str] = []
        self.values: list[int] = []
        self.amounts: list[int] = []
        self.bank: list[str] = []
        self.hidden_exec = False

    def add(self, domain: str, effect: str | None = None, asset: str | None = None, values=()):
        if domain and not self.domain:
            self.domain = domain
        if effect:
            self.effects.add(effect)
        if asset:
            a = f"{domain}:{asset}"
            if a not in self.assets:
                self.assets.append(a)
            if _SAFETY_RE.search(str(asset)) and effect in PHYSICAL_EFFECTS - {"physical_access"}:
                self.effects.add("safety")
        self.values.extend(values)


# a target whose name says it is a safety function: writing to it overrides that function (IEC 61508, ISO 13849)
_SAFETY_RE = re.compile(r"(?i)(?:^|[^a-z])(?:safety|interlock|e-?stop|estop|emergency|sis|guard|bypass|lockout|"
                        r"light[_ ]?curtain|fire|sprinkler|smoke|gas[_ ]?detect|overpressure|relief)(?:[^a-z]|$)")

_WRITE_WORDS = {"write", "set", "put", "update", "change", "modify", "patch", "create", "add", "post", "send",
                "apply", "edit", "insert", "save", "replace", "assign", "submit", "execute", "run", "call", "force",
                "start", "stop", "open", "close", "toggle", "turn", "enable", "disable", "operate", "trigger",
                "publish", "command", "cmd", "upload", "download", "flash", "load", "release", "approve", "sign",
                "dispatch", "arm", "takeoff", "launch", "move", "goto", "drive", "make", "place", "print", "lock",
                "unlock", "reset", "clear", "trip", "void", "reverse", "file", "pay", "transfer"}
_READ_FIRST = {"get", "list", "read", "search", "query", "find", "fetch", "view", "show", "describe", "count",
               "lookup", "check", "status", "inspect", "preview", "download", "export", "browse", "subscribe",
               "monitor", "watch", "screenshot", "capture", "snapshot", "history", "discover", "scan"}


def _is_read(tool_words: list[str]) -> bool:
    return bool(tool_words) and tool_words[0] in _READ_FIRST and tool_words[0] != "download"


# --------------------------------------------------------------------------------------- industrial control (OT)

_MODBUS_WRITE_FC = {5: "actuate", 6: "setpoint", 15: "actuate", 16: "setpoint", 22: "setpoint", 23: "setpoint"}


def _modbus(tw, args, o: _Out):
    # (v0.1.81, RULE-MINE-03 round 8: plc_download_firmware on a Modbus server was allowed) a program or a firmware
    # sent to the controller
    if set(tw) & {"firmware", "flash"} or (set(tw) & {"download", "upload", "deploy", "transfer"} and
                                           set(tw) & {"program", "logic", "project", "firmware", "plc"}):
        host = str(_get(args, "host", "ip", "device", "unit_id", "slave_id", "unit", default="") or "")
        o.add("modbus", "program", host or "controller")
        return
    # modbus_read_coils names the protocol first: a read word with no write word is a read wherever it stands
    if _is_read(tw) or (set(tw) & {"read", "get", "poll", "scan", "monitor"} and not set(tw) & _WRITE_WORDS):
        return
    host = str(_get(args, "host", "ip", "address_ip", "device", "slave_host", "endpoint", "slave_id", "slave",
                    "unit_id", "unit", "device_id", default="") or "")
    addr = _get(args, "address", "register", "start_address", "coil", "offset", "start", "coil_address",
                "register_address", "coil_addr", "register_addr", "addr", default="")
    fc = _num(_get(args, "function_code", "fc", default=None))
    vals = _nums(_get(args, "value", "values", default=[]))
    if fc in _MODBUS_WRITE_FC:
        eff = _MODBUS_WRITE_FC[fc]
    elif "coil" in tw or "coils" in tw:
        eff = "actuate"
    elif tw and tw[0] in _WRITE_WORDS:
        eff = "setpoint"
    else:
        return
    o.add("modbus", eff, f"{host}/{addr}".strip("/"), vals)


def _opcua(tw, args, o: _Out):
    if _is_read(tw):
        return
    node = str(_get(args, "node_id", "nodeid", "node", "tag", "variable", default="") or "")
    if "call" in tw or "method" in tw:
        method = str(_get(args, "method_id", "method", default="") or "")
        obj = str(_get(args, "object_id", "object", default="") or node)
        target = method or obj
        o.add("opcua", "mode" if re.search(r"(?i)(?:^|[^a-z])(stop|start|halt|shutdown|run)(?:[^a-z]|$)", target)
              else "actuate", target)
        return
    o.add("opcua", "setpoint", node, _nums(_get(args, "value", "values", default=[])))


def _plc(server, tw, args, o: _Out, dom: str):
    """S7, Logix/CIP, CODESYS, ADS, FINS, MELSEC and generic PLC servers."""
    if _is_read(tw):
        return
    host = str(_get(args, "host", "ip", "plc", "device", "endpoint", default="") or "")
    tag = str(_get(args, "tag", "tag_name", "variable", "var", "address", "db", "block", "node_id", default="") or "")
    words = set(tw)
    if words & {"firmware", "flash"} or ("update" in words and "firmware" in words):
        o.add(dom, "program", host or tag)
    elif words & {"download", "program", "upload", "deploy", "block", "logic", "transfer", "project"} and \
            not words & {"tag", "var", "variable"}:
        o.add(dom, "program", f"{host}/{tag}".strip("/"))
    elif words & {"mode", "cpu", "state", "stop", "start", "run", "halt", "restart", "reboot", "cold", "warm"}:
        o.add(dom, "mode", host or tag)
    elif "force" in words:
        o.add(dom, "safety", f"{host}/{tag}".strip("/"), _nums(_get(args, "value", default=[])))
    elif tw and tw[0] in _WRITE_WORDS:
        o.add(dom, "setpoint", f"{host}/{tag}".strip("/") if tag else host,
              _nums(_get(args, "value", "values", default=[])))


def _bacnet(tw, args, o: _Out):
    if _is_read(tw):
        return
    dev = _get(args, "device", "device_id", "device_instance", default="")
    obj = _get(args, "object", "object_id", "object_identifier", default="")
    pr = _num(_get(args, "priority", default=None))
    o.add("bacnet", "setpoint", f"{dev}/{obj}".strip("/"), _nums(_get(args, "value", default=[])))
    if pr in (1, 2):           # BACnet priorities 1 and 2: manual and automatic life safety
        o.effects.add("safety")


_MQTT_CMD_RE = re.compile(r"(?i)(?:^|/)(?:cmd|cmnd|command|commands|set|control|ctrl|write|actuate|action|"
                          r"setpoint|output|rpc|invoke)(?:/|$)")


def _mqtt_topic(topic: str, payload, o: _Out):
    if not topic:
        return
    if _MQTT_CMD_RE.search(topic):
        text = payload if isinstance(payload, str) else json.dumps(payload) if payload is not None else ""
        eff = "physical_access" if re.search(r"(?i)\bunlock\b|\"state\"\s*:\s*\"unlock", text) else "actuate"
        o.add("mqtt", eff, topic, _nums(payload) if not isinstance(payload, str) else [])


# ---------------------------------------------------------------------------------------- CNC and 3D printers

_GCODE_LINE_RE = re.compile(r"(?i)^\s*(?:N\d+\s*)?([GM])\s*(\d+)(.*)$")
_GCODE_PARAM_RE = re.compile(r"(?i)\b([SFPRTZXY])\s*(-?\d+(?:\.\d+)?)")
_GCODE_TEXT_RE = re.compile(r"(?im)^\s*(?:N\d+\s*)?[GM]\s*\d+")


# (v0.1.81, RULE-MINE-03 round 8: "G90 G1 X-450.0 F500" read only its first word) one line may hold several G and M words
_GRBL_RE = re.compile(r"^\s*\$(H|X|\d+\s*=)", re.I)
_GCODE_WORD_SPLIT_RE = re.compile(r"(?i)\s+(?=[GM]\s*\d)")


def _gcode_text(text: str, machine: str, o: _Out):
    lines = []
    for line in str(text).replace(";", "\n").splitlines():
        lines.extend(_GCODE_WORD_SPLIT_RE.split(line.split("(")[0]))
    for line in lines:
        g = _GRBL_RE.match(line)
        if g:
            # Grbl system commands: $H homes (motion), $X clears the alarm lock (safety), $<n>=<v> changes a setting
            o.add("gcode", "motion" if g.group(1).upper() == "H" else "safety" if g.group(1).upper() == "X"
                  else "program", machine)
            continue
        m = _GCODE_LINE_RE.match(line)
        if not m:
            continue
        letter, code, rest = m.group(1).upper(), int(m.group(2)), m.group(3)
        params = {k.upper(): float(v) for k, v in _GCODE_PARAM_RE.findall(rest)}
        s = [int(round(params["S"]))] if "S" in params else []
        if letter == "G" and code in (0, 1, 2, 3, 28, 29, 30):
            o.add("gcode", "motion", machine, [int(round(params["F"]))] if "F" in params else [])
        elif letter == "M" and code in (3, 4):
            o.add("gcode", "setpoint", machine, s)
        elif letter == "M" and code in (104, 109, 140, 190, 141, 191):
            o.add("gcode", "setpoint", machine, s)
        elif letter == "M" and code == 211 and params.get("S", 1) == 0:
            o.add("gcode", "safety", machine)              # software endstops off
        elif letter == "M" and code in (120, 121, 999, 502, 500):
            o.add("gcode", "safety" if code in (121, 999) else "program", machine)
        elif letter == "M" and code in (18, 84, 106, 107, 5, 7, 8, 9, 42, 280):
            o.add("gcode", "actuate", machine, s)
        elif letter == "M" and code in (23, 24, 32):
            o.add("gcode", "motion", machine)              # select and start a stored program
        elif letter == "M" and code in (30, 997, 928):
            o.add("gcode", "program", machine)


def _cnc(tw, args, o: _Out):
    if _is_read(tw):
        return
    machine = str(_get(args, "machine", "printer", "device", "host", "machine_id", default="") or "machine")
    words = set(tw)
    text = _get(args, "gcode", "g_code", "commands", "command", "script", "lines", "code", default=None)
    # (v0.1.81) a program passed under these names is read as G-code too; when nothing in it decodes, the write still
    # counts as one to the machine (a stored program's name, a controller setting)
    program = _get(args, "program", "gcode_program", "gcode_text", "nc_program", default=None) if text is None else None
    if program is not None:
        text = program
    if text is not None:
        _gcode_text("\n".join(map(str, text)) if isinstance(text, list) else str(text), machine, o)
    if words & {"spindle", "rpm", "speed", "feed", "temperature", "temp", "heater", "bed", "hotend", "override"}:
        o.add("gcode", "setpoint", machine, _nums(_get(args, "rpm", "speed", "value", "temperature", "target",
                                                       "percent", default=[])))
    if words & {"limit", "limits", "endstop", "endstops", "interlock", "door", "probe"} and \
            (_get(args, "enabled", "enable", "active", default=None) is False or words & {"disable", "off", "override"}):
        o.add("gcode", "safety", machine)
    if words & {"start", "run", "cycle", "resume", "job", "print"} and words & {"program", "cycle", "job", "print", "file"}:
        o.add("gcode", "motion", machine)
    if words & {"jog", "home", "move", "goto"}:
        o.add("gcode", "motion", machine)
    if not o.effects and tw and tw[0] in _WRITE_WORDS and (text is None or program is not None):
        o.add("gcode", "actuate", machine)


# ------------------------------------------------------------------------------------ robots, drones, vehicles

_ROS_MOTION_RE = re.compile(r"(?i)cmd_vel|twist|joint|trajector|goal|move|servo|navigate|nav|arm|gripper|velocity|"
                            r"drive|motor|wheel|teleop|pose|waypoint|follow")


def _ros(tw, args, o: _Out):
    if _is_read(tw):
        return
    words = set(tw)
    target = str(_get(args, "topic", "service", "action", "name", "action_name", "param", default="") or "")
    if words & {"param", "parameter", "parameters"} and words & {"set"}:
        o.add("ros", "setpoint", target, _nums(_get(args, "value", default=[])))
        return
    if not target:
        if tw and tw[0] in _WRITE_WORDS:
            o.add("ros", "motion", "robot")
        return
    if _SAFETY_RE.search(target) or re.search(r"(?i)brake|stop_?override|reset", target):
        o.add("ros", "safety" if _SAFETY_RE.search(target) else "actuate", target)
    elif _ROS_MOTION_RE.search(target):
        o.add("ros", "motion", target)
    else:
        o.add("ros", "actuate", target)


def _mavlink(tw, args, o: _Out):
    if _is_read(tw):
        return
    words = set(tw)
    vehicle = str(_get(args, "vehicle", "drone", "system_id", "target", "uav", default="") or "vehicle")
    if words & {"fence", "geofence", "failsafe", "rtl", "safety"} and \
            (words & {"disable", "off", "clear", "set", "param"} or _get(args, "enabled", "enable", default=None) is False):
        o.add("mavlink", "safety", vehicle)
    elif words & {"param", "parameter"}:
        name = str(_get(args, "param", "name", "param_id", default=""))
        o.add("mavlink", "safety" if re.search(r"(?i)fence|fs_|failsafe|arming_check|geof", name) else "setpoint",
              vehicle, _nums(_get(args, "value", default=[])))
    elif words & {"mode", "mission", "upload"}:
        o.add("mavlink", "mode" if "mode" in words else "program", vehicle)
    else:
        o.add("mavlink", "motion", vehicle, _nums(_get(args, "altitude", "altitude_m", "alt", "speed", default=[])))


_VEHICLE_SERVERS = ("tesla", "car", "vehicle", "fleet", "rivian", "fordpass", "bmw", "mercedes", "smartcar", "tractor",
                    "forklift", "agv", "amr")


def _vehicle(tw, args, o: _Out):
    if _is_read(tw):
        return
    words = set(tw)
    vid = str(_get(args, "vin", "vehicle", "vehicle_id", "truck", "id", default="") or "vehicle")
    if words & {"unlock", "trunk", "frunk", "window", "windows"}:
        o.add("vehicle", "physical_access", vid)
    elif words & {"summon", "drive", "start", "dispatch", "move", "navigate", "route", "remote", "honk", "go"}:
        o.add("vehicle", "motion", vid)
    elif words & {"charge", "charging", "climate", "temperature", "limit", "speed"}:
        o.add("vehicle", "setpoint", vid, _nums(_get(args, "value", "limit", "percent", "amps", default=[])))
    elif words & {"sentry", "alarm", "pin", "valet"}:
        o.add("vehicle", "safety", vid)


# ---------------------------------------------------------------------------------------- buildings and home

# Home Assistant domain.service (and the same shape in openHAB, Hubitat, SmartThings capabilities)
_HOME_TABLE = {
    ("lock", "unlock"): "physical_access", ("lock", "open"): "physical_access",
    ("alarm_control_panel", "alarm_disarm"): "safety", ("alarm_control_panel", "disarm"): "safety",
    ("cover", "open_cover"): "actuate", ("cover", "set_cover_position"): "actuate",
    ("climate", "set_temperature"): "setpoint", ("climate", "set_hvac_mode"): "setpoint",
    ("climate", "turn_off"): "actuate", ("water_heater", "set_temperature"): "setpoint",
    ("valve", "open_valve"): "actuate", ("valve", "close_valve"): "actuate", ("valve", "set_valve_position"): "actuate",
    ("switch", "turn_on"): "actuate", ("switch", "turn_off"): "actuate", ("switch", "toggle"): "actuate",
    ("siren", "turn_off"): "safety", ("camera", "turn_off"): "safety", ("camera", "disable_motion_detection"): "safety",
    ("homeassistant", "stop"): "mode", ("homeassistant", "restart"): "mode",
    ("button", "press"): "actuate", ("number", "set_value"): "setpoint", ("fan", "turn_off"): "actuate",
    ("vacuum", "start"): "motion", ("lawn_mower", "start_mowing"): "motion",
}
_HOME_ACCESS_RE = re.compile(r"(?i)garage|gate|door|entry|front|back_?door|portal|cancello|porta|shutter_?main")
_HOME_VALUE_KEYS = ("temperature", "target_temp_high", "target_temp_low", "position", "value", "percentage",
                    "brightness")


def _home_service(domain: str, service: str, entity: str, args, o: _Out):
    domain, service = domain.lower(), service.lower()
    eff = _HOME_TABLE.get((domain, service))
    if eff is None:
        if domain in ("lock",) and "unlock" in service:
            eff = "physical_access"
        elif domain == "alarm_control_panel" and "disarm" in service:
            eff = "safety"
        else:
            return
    if eff == "actuate" and domain == "cover" and _HOME_ACCESS_RE.search(entity):
        eff = "physical_access"
    vals = [n for k in _HOME_VALUE_KEYS for n in _nums(_get(args, k, default=[]))] if isinstance(args, dict) else []
    o.add("home", eff, entity or f"{domain}.{service}", vals)


def _home(tw, args, o: _Out):
    if _is_read(tw):
        return
    words = set(tw)
    domain = str(_get(args, "domain", default="") or "")
    service = str(_get(args, "service", "action", default="") or "")
    entity = _get(args, "entity_id", "entity", "entities", "target", default="")
    if isinstance(entity, dict):
        entity = entity.get("entity_id", "")
    if isinstance(entity, list):
        entity = ",".join(map(str, entity))
    entity = str(entity or "")
    if "." in service and not domain:
        domain, service = service.split(".", 1)
    if not domain and "." in entity:
        domain = entity.split(".", 1)[0]
    data = _get(args, "service_data", "data", default=None)
    data = data if isinstance(data, dict) else args
    if domain and service:
        _home_service(domain, service, entity, data, o)
        return
    # SmartThings / Hubitat / generic: capability + command, or the tool name itself
    cap = str(_get(args, "capability", default="") or "").lower()
    cmd = str(_get(args, "command", default="") or "").lower()
    dev = str(_get(args, "device_id", "device", "deviceid", "camera_id", "camera", "sensor_id", "id", default="") or entity)
    text = " ".join([cap, cmd, dev] + tw).lower()
    if re.search(r"\bunlock\b", text):
        o.add("home", "physical_access", dev)
    elif re.search(r"\bdisarm\b", text) or (words & {"camera", "recording", "alarm", "siren", "detector", "sensor"} and
                                             words & {"disable", "off", "stop", "mute", "bypass", "silence"}):
        o.add("home", "safety", dev)
    elif re.search(r"\b(?:valve|pump|heater|boiler|thermostat|hvac|relay|breaker|outlet|plug|switch)\b", text) and \
            (cmd or (tw and tw[0] in _WRITE_WORDS)):
        o.add("home", "setpoint" if re.search(r"\b(?:temperature|setpoint|thermostat|level)\b", text) else "actuate",
              dev, _nums(_get(args, "value", "temperature", "level", default=[])))
    elif cmd in ("open", "close") or ("open" in words or "close" in words):
        o.add("home", "physical_access" if _HOME_ACCESS_RE.search(text) else "actuate", dev)


# ------------------------------------------------------------------------------------------------------ energy

def _energy(tw, args, o: _Out):
    if _is_read(tw):
        return
    words = set(tw)
    target = str(_get(args, "breaker", "switch", "charger_id", "charger", "site", "device", "inverter", "point",
                      "station", "substation", default="") or "")
    sub = _get(args, "substation", "station", default="")
    if sub and target != sub:
        target = f"{sub}/{target}"
    if words & {"breaker", "trip", "recloser", "disconnector", "isolator", "switchgear", "feeder"} or \
            (words & {"open", "close"} and words & {"breaker", "switch"}):
        o.add("energy", "actuate", target or "breaker")
    elif words & {"protection", "relay"} and words & {"disable", "bypass", "block", "off"}:
        o.add("energy", "safety", target or "protection")
    elif words & {"limit", "current", "power", "export", "import", "setpoint", "curtail", "curtailment", "frequency",
                  "voltage", "charge", "discharge", "soc", "reserve", "mode"}:
        o.add("energy", "mode" if "mode" in words else "setpoint", target or "site",
              _nums(_get(args, "kw", "kwh", "amps", "watts", "value", "limit", "percent", "setpoint", default=[])))
    elif tw and tw[0] in _WRITE_WORDS:
        o.add("energy", "actuate", target or "site")


# -------------------------------------------------------------------------------------------------------- ERP

# SAP transaction codes and what they do (SAP Access Control critical-action lists)
SAP_TCODES = {
    **{t: "money" for t in ("F110", "F111", "F-53", "F-58", "FBZ2", "F-28", "FBZ1", "F110S", "FPY1", "PC00_M99_CIPE")},
    **{t: "ledger_post" for t in ("FB01", "FB50", "FB60", "FB70", "F-02", "F-43", "F-22", "FB08", "FBR2", "MIRO", "MIGO",
                                  "FB02", "OB52", "F.80", "FBS1", "F-04", "F-32", "VF01", "VF11", "MR8M", "KB11N",
                                  "VL02N", "VL09", "MB1A", "MB1C", "MB01")},
    **{t: "bank_details" for t in ("FK01", "FK02", "XK01", "XK02", "MK02", "FD01", "FD02", "XD01", "XD02", "BP", "FI01",
                                   "FI02", "FI12", "FBZP")},
    **{t: "grant" for t in ("SU01", "SU10", "SU02", "SU03", "PFCG", "SU24", "SU25", "SU53", "SM19", "RZ10", "SCC4",
                            "SE06")},
    **{t: "hidden_exec" for t in ("SE38", "SA38", "SE37", "SE80", "SE24", "SM49", "SM69", "SE16N", "SM59", "SE11",
                                  "SM37", "SM36", "SA39", "SE93")},
    **{t: "program" for t in ("STMS", "SE09", "SE10", "SCC1")},
    **{t: "commitment" for t in ("ME21N", "ME22N", "ME29N", "ME28", "ME51N", "ME31K", "VA01", "VA02", "ME54N")},
    **{t: "pay_change" for t in ("PA30", "PA40", "PA20")},
    **{t: "delete" for t in ("MM06", "XK06", "FK06", "XD06", "OBR1")},
}
_SAP_BAPI_RULES = [
    (re.compile(r"(?i)^(?:RFC_ABAP_INSTALL_AND_RUN|SXPG_COMMAND_EXECUTE|SXPG_CALL_SYSTEM|RFC_REMOTE_EXEC|"
                r"RFC_REMOTE_PIPE|TH_REMOTE_TRANSACTION|SUBST_START_REPORT|/SDF/.*EXEC.*|RS_TESTFRAME_CALL)$"),
     "hidden_exec"),
    (re.compile(r"(?i)^(?:BAPI_USER_(?!GET|GETLIST|EXISTENCE).*|PRGN_.*ASSIGN.*|SUSR_.*(?:CHANGE|CREATE|ASSIGN).*|"
                r"BAPI_.*ACTGROUPS.*)$"), "grant"),
    (re.compile(r"(?i)^(?:BAPI_ACC_.*(?:POST|REV_POST|CHECK_POST)|BAPI_INCOMINGINVOICE_(?:CREATE|POST).*|"
                r"BAPI_GOODSMVT_CREATE|BAPI_ACC_DOCUMENT_REV_POST|BAPI_BILLINGDOC_CREATE.*|BAPI_.*JOURNAL.*POST.*)$"),
     "ledger_post"),
    (re.compile(r"(?i)^(?:BAPI_PO_(?:CREATE|CREATE1|CHANGE|RELEASE)|BAPI_PR_(?:CREATE|CHANGE)|BAPI_REQUISITION_.*|"
                r"BAPI_SALESORDER_CREATE.*|BAPI_CONTRACT_CREATE.*)$"), "commitment"),
    (re.compile(r"(?i)^(?:BAPI_VENDOR_.*(?:CHANGE|CREATE|EDIT).*|BAPI_BUPA_BANKDETAIL_.*|BAPI_CUSTOMER_.*(?:CHANGE|CREATE).*|"
                r"BAPI_BUPA_.*(?:CHANGE|CREATE).*|VENDOR_UPDATE|BAPI_EMPLCOMM_.*|BAPI_BANKDETAIL_.*)$"), "master_change"),
    (re.compile(r"(?i)^(?:BAPI_PAYMENT.*|BAPI_.*PAYM.*RUN.*|FI_PAYMENT_.*)$"), "money"),
    (re.compile(r"(?i)^(?:BAPI_.*_DELETE.*|BAPI_MATERIAL_DELETE.*)$"), "delete"),
    (re.compile(r"(?i)^(?:BAPI_HRMASTER_SAVE_REPL_MULT|HR_INFOTYPE_OPERATION|BAPI_BASICPAY_.*)$"), "pay_change"),
]
_SAP_ODATA_RULES = [
    (re.compile(r"(?i)bank"), "bank_details"),
    (re.compile(r"(?i)journalentr|glaccountlineitem|supplierinvoice|billingdocument|goodsmovement|materialdocument"),
     "ledger_post"),
    (re.compile(r"(?i)purchaseorder|purchaserequisition|salesorder|contract"), "commitment"),
    (re.compile(r"(?i)paymentrun|payment|payout"), "money"),
    (re.compile(r"(?i)^(?:a_)?user|role|businessrole|authorization"), "grant"),
]
# (v0.1.84, RULE-MINE-03 round 8: new_iban, new_bank_account, remittance_account were not read) a bank field with a
# prefix that says which account it is or that it is the new one
_BANK_KEY_RE = re.compile(r"(?i)^(?:(?:new|updated|primary|alt|alternate|remittance|payroll|deposit|beneficiary|vendor|"
                          r"payout|settlement|receiving|destination|target)_?)?"
                          r"(?:iban|bic|swift|swift_?code|bank_?account(?:_?details|_?number|_?no)?|bankn|bankl|"
                          r"bank_?key|bank_?details|account_?number|routing(?:_?number)?|sort_?code|aba|"
                          r"direct_?deposit|payee_?account|bank_?acct|bankaccount|bank|clabe|bsb|transit_?number|"
                          r"bank_?code|blz|ifsc|ifsc_?code|bic_?code|swift_?bic|"
                          r"(?:remittance|payout|settlement|deposit|receiving|payroll|primary|preferred|secondary)"
                          r"_?(?:bank_?)?account|new_?account"
                          r"(?:_?number|_?no)?)$")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")


def _iban_ok(s: str) -> bool:
    s = re.sub(r"\s+", "", s).upper()
    if not _IBAN_RE.match(s):
        return False
    r = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


def _bank_values(arguments) -> list[str]:
    out = []
    for k, v in _flat(arguments):
        if not isinstance(v, (str, int)) or isinstance(v, bool):
            continue
        s = str(v).strip()
        if not s:
            continue
        kk = k.replace("-", "_")
        if _BANK_KEY_RE.match(kk) or _iban_ok(s):
            # a new_account given a ledger code (4010, 6050-Stationery) is a chart-of-accounts change, not a bank one
            if re.match(r"(?i)^(?:new|preferred|secondary)_?account$", kk) and len(re.sub(r"\D", "", s)) < 7:
                continue
            out.append(s)
    return sorted(set(out))


def _sap_effect_from_bapi(fn: str, args) -> str | None:
    for rx, eff in _SAP_BAPI_RULES:
        if rx.match(fn.strip()):
            if eff == "master_change":
                return "bank_details" if _bank_values(args) or re.search(r"(?i)bank", fn) else "grant_master"
            return eff
    return None


def _sap(tw, args, o: _Out):
    tcode = str(_get(args, "tcode", "transaction", "transaction_code", default="") or "").upper().strip()
    fn = str(_get(args, "function", "bapi", "function_module", "rfc", "fm", "name", default="") or "").strip()
    if tcode:
        tcode = tcode.lstrip("/N").lstrip("/O") if tcode.startswith("/") else tcode
        eff = SAP_TCODES.get(tcode)
        if eff:
            _sap_apply(eff, f"tcode/{tcode}", args, o)
        return
    if fn:
        eff = _sap_effect_from_bapi(fn, args)
        if eff:
            _sap_apply(eff, f"fm/{fn.upper()}", args, o)
        return
    method = str(_get(args, "method", "http_method", default="") or "").upper()
    entity = str(_get(args, "entity", "entity_set", "entityset", "path", "resource", default="") or "")
    if entity and method in ("POST", "PUT", "PATCH", "MERGE", "DELETE"):
        _sap_odata(entity, method, args, o)
        return
    # a typed SAP tool (create_purchase_order, post_goods_issue, release_purchase_order...): read through the
    # business words below by the caller
    return


def _sap_odata(entity: str, method: str, args, o: _Out):
    if method == "DELETE":
        o.add("sap", "delete", f"odata/{entity}")
        return
    for rx, eff in _SAP_ODATA_RULES:
        if rx.search(entity):
            _sap_apply(eff, f"odata/{entity}", args, o)
            return


def _sap_apply(eff: str, asset: str, args, o: _Out):
    if eff == "hidden_exec":
        o.hidden_exec = True
        o.add("sap", None, None)
        o.effects.add("program")
        return
    if eff == "grant_master":
        o.add("sap", None, None)
        return
    o.add("sap", eff, None)
    if eff == "grant":
        return
    o.bank.extend(_bank_values(args))
    o.amounts.extend(_amounts(args))


# ------------------------------------------------------------------------------------- business words (any system)

_AMOUNT_KEY_RE = re.compile(r"(?i)^(?:amount|amt|total|sum|value|price|net|gross|line_?amount|amt_?doccur|"
                            r"amount_?(?:cents|due|paid|total|local)|unit_?price|base_?salary|salary|wage|"
                            r"pay_?rate|annual_?salary|bonus)$")


def _amounts(arguments) -> list[int]:
    out = []
    for k, v in _flat(arguments):
        if _AMOUNT_KEY_RE.match(k):
            n = _num(v)
            if n is not None:
                out.append(abs(n) // 100 if k.endswith("cents") else abs(n))
    return out


_ACCOUNTING_SERVERS = ("quickbooks", "qbo", "xero", "sage", "netsuite", "freshbooks", "zoho", "zohobooks",
                       "fattureincloud", "datev", "odoo", "dynamics", "businesscentral", "exact", "wave", "myob",
                       "tally", "freeagent", "kashflow", "sevdesk", "lexoffice", "holded", "danea", "teamsystem",
                       "aruba", "fatturazione", "ledger", "accounting", "erp", "invoice", "billing", "pennylane",
                       "billy", "dinero", "e-conomic", "economic", "visma", "fortnox", "intuit", "brex", "ramp",
                       "expensify", "bill", "billcom", "tipalti", "coupa", "ariba")
_PAYROLL_SERVERS = ("workday", "gusto", "adp", "bamboohr", "rippling", "deel", "remote_com", "paychex", "personio",
                    "hibob", "zenefits", "paylocity", "successfactors", "oracle_hcm", "hcm", "payroll", "hr", "zucchetti")
_SIGN_SERVERS = ("docusign", "adobesign", "adobe_sign", "dropboxsign", "hellosign", "yousign", "pandadoc", "signnow",
                 "esign", "signwell", "namirial", "infocert", "zoho_sign", "zohosign")
_COMMERCE_SERVERS = ("shopify", "woocommerce", "bigcommerce", "magento", "prestashop", "amazon", "ebay", "etsy",
                     "stripe", "commercetools", "salesforce_commerce", "vtex", "wix", "squarespace")
_TAX_RE = re.compile(r"(?i)^(?:tax|vat|iva|f24|irs|hmrc|mtd|agenziaentrate|entrate|sdi|fisco|finanzamt|elster|"
                     r"avalara|taxjar|fiscal)")


def _business(server: str, tw: list[str], args, o: _Out):
    """Bank details, postings, filings, payroll, signatures and prices, by the system's words. Runs on every tool
    that writes, whatever its server, after the protocol decoders."""
    if _is_read(tw):
        return
    words = set(tw)
    srv = server.lower()
    dom = ("sap" if _srv(srv, ("sap",)) else "payroll" if _srv(srv, _PAYROLL_SERVERS) else
           "signature" if _srv(srv, _SIGN_SERVERS) else
           "commerce" if _srv(srv, _COMMERCE_SERVERS) else
           "accounting" if _srv(srv, _ACCOUNTING_SERVERS) or _TAX_RE.match(srv) else "")
    bank = _bank_values(args)
    money_words = {"pay", "payment", "payout", "transfer", "wire", "remit", "withdraw", "refund", "charge"}
    if bank and not words & money_words and not ({"payroll"} & words):
        o.add(dom or "accounting", "bank_details", None)
        o.bank.extend(bank)
    elif (words & {"bank", "deposit", "iban", "banking"} or (bank and words & {"account", "accounts", "payee",
                                                                               "beneficiary", "remittance"})) and \
            words & {"update", "change", "set", "edit", "add", "create", "modify", "replace", "patch"}:
        o.add(dom or "accounting", "bank_details", None)
        o.bank.extend(bank)
    # postings and corrections to the books
    if (words & {"journal", "journals", "ledger", "posting", "gl"} and not words & {"report"}) or \
            (words & {"void", "reverse", "reversal", "writeoff", "write", "credit", "delete", "cancel"} and
             words & {"invoice", "invoices", "bill", "bills", "payment", "receipt", "entry", "note", "transaction"} and
             dom in ("accounting", "sap")) or \
            (words & {"goods", "inventory", "stock", "movement", "issue", "receipt"} and dom == "sap" and
             words & {"post", "issue", "receipt", "create"}) or \
            _get(args, "period_lock_date", "lock_date", "end_of_year_lock_date", "closing_date", default=None) is not None or \
            (words & {"lock", "close", "reopen"} and words & {"period", "periods", "year", "month", "books"}):
        o.add(dom or "accounting", "ledger_post", None)
        o.amounts.extend(_amounts(args))
    # filings with a public body
    if (words & {"einvoice", "einvoicing", "sdi", "fattura", "fatturapa", "xrechnung", "peppol"} or
        ({"e", "invoice"} <= words) or ({"electronic", "invoice"} <= words)) and \
            words & {"send", "submit", "transmit", "file", "issue", "deliver"}:
        o.add(dom or "accounting", "filing", None)
    if (words & {"tax", "vat", "iva", "return", "declaration", "f24", "1099", "w2", "gst", "intrastat", "esterometro",
                 "dichiarazione", "lipe"} or _TAX_RE.match(srv)) and words & {"submit", "file", "send", "transmit",
                                                                              "lodge", "pay"}:
        o.add(dom or "accounting", "filing", None)
        o.amounts.extend(_amounts(args))
    # payroll and pay
    if words & {"payroll", "payrun", "pay_run"} and words & {"run", "submit", "approve", "process", "execute", "send",
                                                             "finalize", "create"}:
        o.add(dom or "payroll", "money", None)
    if words & {"compensation", "salary", "wage", "wages", "pay", "bonus", "raise", "rate", "payrate"} and \
            words & {"update", "change", "set", "edit", "create", "add", "modify", "adjust", "increase", "grant"} and \
            not words & {"payment", "transfer"}:
        o.add(dom or "payroll", "pay_change", None)
        o.amounts.extend(_amounts(args))
    # signatures and binding documents
    if dom == "signature" or words & {"envelope", "esign", "signature", "signatures", "contract", "agreement"}:
        if words & {"sign", "send", "submit", "countersign", "execute", "complete", "approve", "finalize"} or \
                (words & {"envelope"} and words & {"create"} and str(_get(args, "status", default="")).lower() == "sent"):
            o.add(dom or "signature", "commitment", None)
    if words & {"sign"} and words & {"document", "documents", "pdf", "contract", "agreement", "envelope"}:
        o.add(dom or "signature", "commitment", None)
    # orders that commit money to a supplier
    if words & {"purchase", "po"} and words & {"order", "orders"} and words & {"create", "release", "approve", "submit",
                                                                                "send", "place", "issue"}:
        o.add(dom or "accounting", "commitment", None)
        o.amounts.extend(_amounts(args))
    # prices and discounts
    if words & {"price", "prices", "pricing", "pricelist"} and words & {"update", "set", "change", "edit", "bulk",
                                                                        "modify", "create", "adjust"}:
        o.add(dom or "commerce", "price", None)
    if words & {"discount", "coupon", "voucher", "promo", "promotion", "pricerule", "giftcard", "gift"} and \
            words & {"create", "add", "generate", "issue", "update", "set"}:
        o.add(dom or "commerce", "price", None)
    # master data flagged or deleted in the books (a material, a vendor, an account)
    if words & {"deletion", "delete", "archive", "purge", "block"} and dom in ("sap", "accounting", "payroll") and \
            words & {"material", "vendor", "supplier", "customer", "account", "accounts", "employee", "record", "master",
                     "flag", "contact", "item", "asset", "cost", "center"}:
        o.add(dom, "delete", None)
    # cheques printed are payments
    if words & {"print"} and (words & {"cheque", "cheques", "checks", "check"} or
                              re.search(r"(?i)cheque|\bchecks?\b|assegn", json.dumps(args, default=str))):
        o.add("print", "money", None)


# ------------------------------------------------------------------------------------- screens, phones, printers

_GUI_SERVERS = ("playwright", "puppeteer", "browser", "browserbase", "browser_use", "browseruse", "selenium", "desktop",
                "computer", "windows", "macos", "xdotool", "pyautogui", "nut", "autogui", "screen", "chrome", "stagehand",
                "anchor", "hyperbrowser", "steel", "skyvern", "operator")
_GUI_WRITE = {"click", "double", "dblclick", "tap", "press", "type", "key", "keys", "keyboard", "fill", "select",
              "submit", "drag", "drop", "check", "uncheck", "upload", "input", "enter", "send", "hotkey", "write",
              "left", "right", "middle", "triple", "mouse"}
_GUI_READ = {"screenshot", "snapshot", "zoom", "wait", "scroll", "move", "hover", "navigate", "goto", "back",
             "forward", "tabs", "tab", "close", "resize", "console", "network", "evaluate", "extract", "observe",
             "cursor", "position", "get", "read", "list", "find", "query"}
_GUI_SENSITIVE_RE = re.compile(
    r"(?i)\b(?:confirm|pay|payment|transfer|send|submit|sign|delete|remove|approve|authori[sz]e|buy|purchase|order|"
    r"checkout|place\s+order|wire|bonifico|paga|conferma|invia|elimina|firma|acquista|ordina|publish|post|deploy|"
    r"grant|invite|share|withdraw|unlock|disarm|accept|agree|execute|run|install|reset|wipe|erase|transfer)\b")
_GUI_LABEL_KEYS = ("element", "label", "name", "text", "selector", "button", "target", "aria_label", "description",
                   "title", "intent", "instruction", "action_description")


def _gui(name: str, tw: list[str], args, o: _Out):
    words = set(tw)
    act = str(_get(args, "action", "type", "event", default="") or "").lower()
    awords = set(_words(act))
    allw = words | awords
    if (allw & _GUI_READ) and not (allw & _GUI_WRITE):
        return
    if not (allw & _GUI_WRITE):
        return
    if _bank_values(args):
        o.add("gui", "bank_details", None)
        o.bank.extend(_bank_values(args))
    label_parts = []
    for k in _GUI_LABEL_KEYS:
        v = _get(args, k, default=None)
        if isinstance(v, str) and v.strip() and not re.fullmatch(r"\s*[\d.,\s]+\s*", v):
            label_parts.append(v)
    for k, v in _flat(_get(args, "fields", "values", default=[])):
        if k in ("name", "label") and isinstance(v, str):
            label_parts.append(v)
    typed = _get(args, "text", "value", "keys", "key", default=None)
    label = " ".join(label_parts)
    if label and _GUI_SENSITIVE_RE.search(label):
        o.add("gui", "gui_sensitive", None)
    elif not label or (allw & {"type", "key", "keys", "keyboard", "press", "hotkey", "input"} and
                       isinstance(typed, str) and label.strip() == typed.strip()):
        o.add("gui", "gui_opaque", None)


_PHONE_SERVERS = ("twilio", "vapi", "bland", "retell", "vonage", "plivo", "telnyx", "sinch", "aircall", "ringcentral",
                  "dialpad", "phone", "voice", "telephony", "sip", "asterisk", "3cx", "elevenlabs_agents")


def _phone(tw, args, o: _Out):
    words = set(tw)
    if words & {"call", "calls", "dial", "phone"} and words & {"make", "create", "start", "place", "dial", "outbound",
                                                               "initiate", "call"} and not _is_read(tw):
        o.add("phone", "call", str(_get(args, "to", "phone_number", "number", "customer_number", default="") or ""))


# ------------------------------------------------------------------------------------------- tool route dispatch

def _tool(name: str, arguments, o: _Out):
    if name.startswith("mcp__"):
        server, _, tool = name[len("mcp__"):].partition("__")
        tool = tool or server
    else:
        server, tool = "", name
    srv = server.lower()
    tw = _words(tool)
    words = set(tw)
    args = arguments if isinstance(arguments, (dict, list)) else {}
    if _srv(srv, ("modbus",)) or "modbus" in words:
        _modbus(tw, args, o)
    elif _srv(srv, ("opcua", "opc_ua", "opc-ua", "opc")) or {"opc", "ua"} <= words or "opcua" in words:
        _opcua(tw, args, o)
    elif _srv(srv, ("s7", "snap7", "siemens", "tia", "simatic")):
        _plc(srv, tw, args, o, "s7")
    elif _srv(srv, ("plc", "logix", "rockwell", "ethernetip", "enip", "cip", "codesys", "beckhoff", "twincat",
                                "ads", "omron", "fins", "melsec", "mitsubishi", "schneider", "modicon", "allenbradley",
                                "pycomm", "scada", "hmi", "ignition", "kepware", "wonderware", "dnp3", "iec104",
                                "iec61850", "profinet", "ot")):
        if _srv(srv, ("scada", "dnp3", "iec104", "iec61850")) and words & {"breaker", "trip", "recloser",
                                                                                         "feeder", "substation"}:
            _energy(tw, args, o)
        else:
            _plc(srv, tw, args, o, "plc")
    elif _srv(srv, ("bacnet",)) or "bacnet" in words:
        _bacnet(tw, args, o)
    elif _srv(srv, ("mqtt", "mosquitto", "emqx", "hivemq", "aws_iot", "iot_core", "azure_iot", "zigbee2mqtt",
                                "tasmota", "thingsboard", "node_red", "nodered")) or "mqtt" in words:
        if not _is_read(tw) and (words & {"publish", "send", "pub", "command", "set", "write"}):
            _mqtt_topic(str(_get(args, "topic", "channel", default="") or ""),
                        _get(args, "payload", "message", "msg", "data", "value", default=None), o)
    elif _srv(srv, ("cnc", "gcode", "octoprint", "klipper", "moonraker", "grbl", "marlin", "linuxcnc",
                                "fanuc", "haas", "mazak", "heidenhain", "mach3", "mach4", "duet", "reprap", "prusa",
                                "bambu", "printer3d", "3dprinter", "laser", "lightburn", "smoothie", "fluidnc")) or \
            words & {"gcode", "spindle"} or _gcode_arg(args):
        _cnc(tw, args, o)
    elif _srv(srv, ("ros", "ros2", "rosbridge", "moveit", "nav2", "robot", "ur", "universal_robots",
                                "fanuc_robot", "abb", "kuka", "franka", "spot", "boston")):
        _ros(tw, args, o)
    elif _srv(srv, ("mavlink", "mavsdk", "px4", "ardupilot", "dronekit", "dji", "drone", "uav", "skydio")):
        _mavlink(tw, args, o)
    elif _srv(srv, _VEHICLE_SERVERS):
        _vehicle(tw, args, o)
    elif _srv(srv, ("homeassistant", "home_assistant", "hass", "smartthings", "hubitat", "homey", "openhab",
                                "domoticz", "hue", "homekit", "google_home", "alexa", "tuya", "shelly", "nest",
                                "ecobee", "ring", "camera", "nvr", "unifi_protect", "frigate", "bms", "building",
                                "knx", "loxone", "crestron", "control4", "savant", "fibaro", "zwave", "zigbee",
                                "matter", "iot", "home")):
        _home(tw, args, o)
    elif _srv(srv, ("energy", "inverter", "solar", "battery", "evcharger", "ev_charger", "charger", "ocpp",
                                "wallbox", "grid", "substation", "powerwall", "enphase", "solaredge", "victron",
                                "fronius", "sma", "huawei_solar", "tibber", "utility", "meter")):
        _energy(tw, args, o)
    elif _srv(srv, ("sap",)) or "sap" in words or _get(args, "tcode", "transaction_code", "bapi", default=None):
        _sap(tw, args, o)
    if _srv(srv, _PHONE_SERVERS):
        _phone(tw, args, o)
    if tool.lower() == "computer" or _srv(srv, _GUI_SERVERS) or \
            (words & {"click", "type", "keypress", "key", "mouse"} and words & _GUI_WRITE and
             not o.effects and srv in ("", "computer")):
        _gui(name, tw, args, o)
    if not (o.effects & PHYSICAL_EFFECTS):
        _business(srv, tw, args, o)


def _gcode_arg(args) -> bool:
    v = _get(args, "gcode", "g_code", default=None)
    if v is not None:
        return True
    v = _get(args, "commands", "lines", default=None)
    if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
        return all(_GCODE_TEXT_RE.match(x) for x in v)
    return False


# ------------------------------------------------------------------------------------------- shell and code routes

_TTY_RE = re.compile(r">\s*/dev/tty(?:USB|ACM|S|AMA)\d+")
_PY_MODBUS_RE = re.compile(r"ModbusTcpClient\(\s*['\"]([^'\"]+)['\"]")
_PY_MODBUS_WRITE_RE = re.compile(r"\.write_(register|registers|coil|coils)\(\s*(\d+)\s*,\s*([^)]*)\)")
_PY_RFC_RE = re.compile(r"\.call\(\s*['\"]([A-Z0-9_/]+)['\"]")
_PY_S7_RE = re.compile(r"\.(plc_stop|plc_cold_start|plc_hot_start|download|full_upload|db_write|write_area|"
                       r"set_plc_datetime|delete)\(")
_PY_OPCUA_RE = re.compile(r"\.(set_value|write_value|write_attribute|call_method)\(")
_PY_MQTT_RE = re.compile(r"\.publish\(\s*['\"]([^'\"]+)['\"]")


def _shell(command: str, o: _Out):
    try:
        import shlex
        words = shlex.split(command, posix=True)
    except ValueError:
        words = command.split()
    if not words:
        return
    lw = [w.lower() for w in words]
    # mbpoll -m tcp -a 1 -r 40001 -t 4 HOST VALUE...
    for i, w in enumerate(lw):
        base = w.rsplit("/", 1)[-1]
        rest = words[i + 1:]
        if base == "mbpoll":
            opts, pos, j = {}, [], 0
            while j < len(rest):
                if rest[j].startswith("-") and len(rest[j]) == 2 and j + 1 < len(rest) and rest[j][1] in "martcpbdPRo":
                    opts[rest[j][1]] = rest[j + 1]
                    j += 2
                    continue
                if not rest[j].startswith("-"):
                    pos.append(rest[j])
                j += 1
            if len(pos) >= 2:      # a host and at least one value to write
                t = opts.get("t", "4")
                eff = "actuate" if t.startswith("0") else "setpoint"
                o.add("modbus", eff, f"{pos[0]}/{opts.get('r', '')}".strip("/"), _nums(pos[1:]))
        elif base in ("modbus", "modbus-cli", "modpoll") and "write" in [x.lower() for x in rest]:
            o.add("modbus", "setpoint", " ".join(rest[:2]), _nums([x for x in rest if x.lstrip("-").isdigit()][-1:]))
        elif base in ("mosquitto_pub", "mqttx", "mqtt-pub"):
            topic = next((rest[k + 1] for k in range(len(rest) - 1) if rest[k] in ("-t", "--topic")), "")
            msg = next((rest[k + 1] for k in range(len(rest) - 1) if rest[k] in ("-m", "--message")), "")
            _mqtt_topic(topic, msg, o)
        elif base in ("ros2", "rostopic", "rosservice") and rest:
            sub = [x for x in rest if not x.startswith("-")]
            if base == "ros2" and len(sub) >= 3 and sub[0] in ("topic", "service", "action", "param") and \
                    sub[1] in ("pub", "call", "send_goal", "set"):
                _ros(["publish" if sub[1] == "pub" else "set" if sub[1] == "set" else "call"] +
                     (["param"] if sub[0] == "param" else []),
                     {"topic": sub[2]} if sub[0] != "param" else {"param": sub[-2] if len(sub) > 3 else sub[2]}, o)
            elif base != "ros2" and len(sub) >= 2 and sub[0] in ("pub", "call"):
                _ros(["publish"], {"topic": sub[1]}, o)
        elif base in ("mavproxy.py", "mavproxy") or (base == "mavlink" and rest):
            o.add("mavlink", "motion", "vehicle")
        elif base in ("ha", "hass-cli") and len(rest) >= 2 and rest[0] in ("service", "action"):
            svc = next((x for x in rest[1:] if "." in x and not x.startswith("-")), "")
            ent = next((rest[k + 1] for k in range(len(rest) - 1) if rest[k] in ("--entity", "--entity_id",
                                                                                  "--arguments")), "")
            if "." in svc:
                d, s = svc.split(".", 1)
                _home_service(d, s, ent.replace("entity_id=", ""), {}, o)
    if _TTY_RE.search(command):
        _gcode_text(re.sub(r">\s*/dev/\S+", "", command).replace("echo", "").strip(" '\""), "serial", o)
        if not o.effects:
            o.add("gcode", "actuate", "serial")
    # inline code in the command line (python -c, here-documents): the libraries of each protocol
    host = _PY_MODBUS_RE.search(command)
    for m in _PY_MODBUS_WRITE_RE.finditer(command):
        o.add("modbus", "actuate" if "coil" in m.group(1) else "setpoint",
              f"{host.group(1) if host else ''}/{m.group(2)}".strip("/"), _nums(m.group(3).split(",")[0].strip()))
    for m in _PY_RFC_RE.finditer(command):
        eff = _sap_effect_from_bapi(m.group(1), {})
        if eff:
            _sap_apply("bank_details" if eff == "grant_master" and "BANK" in m.group(1) else eff, f"fm/{m.group(1)}",
                       {}, o)
    for m in _PY_S7_RE.finditer(command):
        f = m.group(1)
        o.add("s7", "mode" if f.startswith(("plc_", "set_plc")) else "program" if f in ("download", "delete")
              else "setpoint", "plc")
    for m in _PY_OPCUA_RE.finditer(command):
        o.add("opcua", "actuate" if m.group(1) == "call_method" else "setpoint", "node")
    for m in _PY_MQTT_RE.finditer(command):
        _mqtt_topic(m.group(1), None, o)


# ------------------------------------------------------------------------------------------------- HTTP route

def _http(method: str, url: str, body, o: _Out):
    method = (method or "GET").upper()
    if method in ("GET", "HEAD", "OPTIONS"):
        return
    try:
        parts = urlsplit(url)
    except ValueError:
        return
    path = unquote(parts.path or "")
    data = body
    if isinstance(body, str):
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = body
    m = re.search(r"/api/services/([a-z_]+)/([a-z_]+)", path)
    if m:
        ent = data.get("entity_id", "") if isinstance(data, dict) else ""
        _home_service(m.group(1), m.group(2), str(ent), data if isinstance(data, dict) else {}, o)
        return
    if re.search(r"/api/(?:printer/command|printer/printhead|printer/tool|printer/bed|job)\b", path) or \
            re.search(r"/printer/gcode/script|/machine/", path):
        cmds = data.get("commands") or data.get("command") or data.get("script") if isinstance(data, dict) else data
        if cmds:
            _gcode_text("\n".join(map(str, cmds)) if isinstance(cmds, list) else str(cmds), parts.hostname or "", o)
        if "/api/job" in path or not o.effects:
            o.add("gcode", "motion" if "/api/job" in path else "actuate", parts.hostname or "")
        return
    m = re.search(r"/sap/opu/odata4?/[^/]+/([A-Za-z0-9_]+)/([A-Za-z0-9_]+)", path)
    if m:
        _sap_odata(m.group(2), method, data if isinstance(data, dict) else {}, o)
        return
    if re.search(r"(?i)/(?:plc|scada|hmi|modbus|opcua|opc-ua|bacnet|tags?|io|outputs?|coils?|registers?|setpoints?)/",
                 path + "/") and re.search(r"(?i)/(?:plc|scada|hmi|modbus|opcua|opc-ua|bacnet)(?:/|$)", path):
        val = data.get("value") if isinstance(data, dict) else None
        eff = "actuate" if isinstance(val, bool) or re.search(r"(?i)run|start|stop|on|off|open|close", path) else "setpoint"
        o.add("plc", eff, f"{parts.hostname}{path}", _nums(val) if not isinstance(val, bool) else [])


# --------------------------------------------------------------------------------------------------- annotate

def _match_assets(assets: list[str], register: list[dict]):
    classes: set[str] = set()
    undeclared = False
    envelopes: list[dict] = []
    max_writes = 0
    for a in assets:
        hits = [r for r in register if any(fnmatch.fnmatch(a.lower(), str(p).lower())
                                           for p in ([r.get("match")] if isinstance(r.get("match"), str)
                                                     else r.get("match") or []))]
        if not hits:
            undeclared = True
            continue
        for r in hits:
            if r.get("class"):
                classes.add(str(r["class"]).lower())
            if "min" in r or "max" in r:
                envelopes.append(r)
            mw = int(r.get("max_writes") or 0)
            if mw and (not max_writes or mw < max_writes):
                max_writes = mw
    return classes, undeclared, envelopes, max_writes


def annotate(action: dict, rec: dict, config) -> dict:
    """Add the domain fields to a normalised record, in place, and return it."""
    for k, v in default_fields().items():
        rec.setdefault(k, v)
    o = _Out()
    t = action.get("type", "")
    try:
        if t == "tool":
            args = action.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args or "{}")
                except json.JSONDecodeError:
                    args = {}
            _tool(str(action.get("name", "") or ""), args, o)
            cmd = rec.get("tool_shell_command") or ""
            if cmd:
                _shell(cmd, o)
            if rec.get("urls") and isinstance(args, dict):
                for u in rec["urls"]:
                    _http(str(_get(args, "method", default="POST") or "POST"), u, _get(args, "body", "data", "json"), o)
        elif t in ("shell", "git", "package.install", "service"):
            cmd = action.get("command") or (" ".join(action.get("argv") or []))
            _shell(str(cmd), o)
            for u in rec.get("urls", []):
                if re.search(r"(?i)\b(?:-X|--request)\s*(POST|PUT|PATCH|DELETE)\b|\s(?:-d|--data\S*|--json)\s", cmd):
                    _http("POST", u, None, o)
        elif t == "http":
            _http(str(action.get("method", "GET")), str(action.get("url", "")), action.get("body"), o)
    except Exception:  # noqa: BLE001  a decoder never breaks a decision; the record stays as the other routes made it
        o = _Out()
    rec["effects"] = sorted(o.effects)
    rec["domain"] = o.domain
    rec["assets"] = list(o.assets)
    rec["values"] = sorted(set(o.values))
    rec["amount_max"] = max(o.amounts) if o.amounts else 0
    rec["bank_values"] = sorted(set(o.bank))
    if o.hidden_exec:
        rec["eval_like"] = True
    # protocol verbs that are not the English words the generic rules read: "publish" on a ROS or MQTT topic sends a
    # message to a machine (not a software release), "key" in key_press is a keystroke (not an access key). The
    # machine and screen packs read these actions by their effect instead.
    proto_words = {"ros": {"publish", "pub"}, "mqtt": {"publish", "pub"}, "gui": {"key", "keys"}}.get(o.domain)
    if proto_words and rec.get("tool_words"):
        rec["tool_words"] = [w for w in rec["tool_words"] if w not in proto_words]
    if "physical_access" in o.effects:
        rec["tool_physical_access"] = True
    register = list(getattr(config, "assets", []) or [])
    # a write to a machine whose target is not decoded (no address, no entity, no topic) is matched as "<domain>:?":
    # only a register entry that covers every target of that domain ("*", "modbus:*") declares it
    targets = o.assets or ([f"{o.domain or 'machine'}:?"] if o.effects & PHYSICAL_EFFECTS else [])
    if targets and register:
        classes, undeclared, envelopes, max_writes = _match_assets(targets, register)
        rec["asset_classes"] = sorted(classes)
        rec["asset_undeclared"] = undeclared
        rec["asset_max_writes"] = max_writes
        outside = False
        for r in envelopes:
            lo, hi = r.get("min"), r.get("max")
            for v in o.values:
                if (lo is not None and v < lo) or (hi is not None and v > hi):
                    outside = True
        rec["value_outside_envelope"] = outside
    elif targets and o.effects & PHYSICAL_EFFECTS:
        rec["asset_undeclared"] = True
    return rec
