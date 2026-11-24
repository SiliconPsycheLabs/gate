"""The engine on the example tables: what the table allows passes, everything else does not pass."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from gate_table import manager  # noqa: E402
from gate_table.engine import Gate  # noqa: E402
from gate_table.reader_mail import read_mail  # noqa: E402
from gate_table.reader_url import read_url  # noqa: E402
from quickstart import Records  # noqa: E402


def table(name):
    return json.loads((ROOT / "examples" / f"{name}.json").read_text())


def outcome(tbl, tool, args, view=None):
    rec, _ = manager.decide(tbl, {"tool": tool, "args": args}, view or Records())
    return rec


# Payments: tools with forms and conditions on the company's records.

def test_a_validated_invoice_under_the_limit_is_paid():
    rec = outcome(table("payments"), "pay_invoice", {"number": "INV-1"})
    assert rec["outcome"] == "pass"


@pytest.mark.parametrize("args, rule, words", [
    ({"number": "INV-2"}, "pay_invoice#1", "only a validated invoice"),       # wrong state
    ({"number": "INV-3"}, "pay_invoice#2", "over 5,000"),                      # over the limit
    ({"number": "INV-9"}, "pay_invoice#1", "INV-9"),                           # no such record
])
def test_an_invoice_the_rules_do_not_allow_is_not_paid(args, rule, words):
    rec = outcome(table("payments"), "pay_invoice", args)
    assert rec["outcome"] == "nopass" and rec["rule"] == rule and words in rec["reason"]


def test_a_field_outside_the_form_does_not_pass():
    rec = outcome(table("payments"), "pay_invoice", {"number": "INV-1", "iban": "XX00"})
    assert rec["outcome"] == "nopass" and rec["rule"] == "form"


def test_a_missing_field_does_not_pass():
    assert outcome(table("payments"), "pay_invoice", {})["outcome"] == "nopass"


def test_a_closed_tool_does_not_pass_with_its_fixed_reason():
    rec = outcome(table("payments"), "delete_supplier", {"id": "S-7"})
    assert rec["outcome"] == "nopass" and rec["reason"] == "suppliers are removed by a person, not by the agent"


def test_a_tool_not_in_the_table_does_not_pass():
    rec = outcome(table("payments"), "wire_money", {"to": "anyone"})
    assert rec["outcome"] == "nopass" and rec["rule"] == "menu"


def test_the_same_action_on_the_same_facts_gets_the_same_answer():
    answers = {json.dumps(outcome(table("payments"), "pay_invoice", {"number": n})["outcome"])
               for n in ["INV-2"] * 20}
    assert answers == {'"nopass"'}


class Down(Records):
    def record(self, kind, key):
        raise ConnectionError("the company's system does not answer")


def test_a_system_that_does_not_answer_lets_nothing_pass():
    rec = outcome(table("payments"), "pay_invoice", {"number": "INV-1"}, view=Down())
    assert rec["outcome"] == "nopass"


def test_a_person_opens_one_exact_action_once():
    tbl = table("payments")
    why, state = manager.open_once(tbl, "delete_supplier", {"id": "S-7"}, "owner", Records())
    assert why is None
    rec, state = manager.decide(tbl, {"tool": "delete_supplier", "args": {"id": "S-7"}}, Records(), state=state)
    assert rec["outcome"] == "pass" and rec["opening"] == "once"
    other, _ = manager.decide(tbl, {"tool": "delete_supplier", "args": {"id": "S-8"}}, Records(), state=state)
    assert other["outcome"] == "nopass"                                       # only that exact action


# Mail: a language door, the text read into operations by a translator.

MAIL = Gate(table("mail"), readers={"mail": read_mail})


def mail(sender="agent@example.com", to=("bob@example.com",), cc=(), bcc=(), files=()):
    args = {"from": sender, "to": list(to), "cc": list(cc), "bcc": list(bcc), "subject": "", "body": "x",
            "attachments": [{"filename": f} for f in files]}
    return MAIL.form("send_mail", args) or MAIL.decide("send_mail", args, None)


@pytest.mark.parametrize("kw", [
    {}, {"to": ["bob@partner.example"], "cc": ["Alice@Example.Com"]}, {"to": ["a@example.com"] * 5},
    {"files": ["Report.PDF", "data.csv"]},
])
def test_mail_the_rules_allow_passes(kw):
    assert mail(**kw) is None


@pytest.mark.parametrize("kw", [
    {"sender": "boss@example.com"},                                            # not an address to send as
    {"to": ["ceo@example.com"]}, {"bcc": ["PAYROLL@example.com"]},             # closed inside an open domain
    {"to": ['"payroll "@example.com']}, {"to": ["ceo+x@example.com"]},         # the same address written another way
    {"to": ["bob@sub.example.com"]}, {"to": ["bob@example.com.evil"]},         # not the domain
    {"to": ["a@example.com"] * 6},                                             # more than 5 recipients
    {"files": ["x.exe"]}, {"files": ["report.pdf.exe"]},                       # attachment types not listed
    {"to": []},
])
def test_mail_the_rules_do_not_allow_does_not_pass(kw):
    assert mail(**kw)


# Web addresses: only the declared hosts are reached.

WEB = Gate(table("web"), readers={"url": read_url})


@pytest.mark.parametrize("url", ["https://docs.example.org/a", "https://API.example.org./v1/x"])
def test_a_declared_host_passes(url):
    assert WEB.decide("fetch", {"url": url}, None) is None


@pytest.mark.parametrize("url", ["https://evil.example/", "https://user:pw@docs.example.org/",
                                 "http://docs.example.org:99999/", "https://docs.example.org.evil/"])
def test_any_other_address_does_not_pass(url):
    assert WEB.decide("fetch", {"url": url}, None)


def test_the_engine_reads_limits_and_closed_parts_generically():
    g = Gate({"doors": {"d": {"language": "x", "arg": "*", "form": {}}}, "limits": {"n": 2},
              "containers": {"c": {"w": ["a", "b"], "except": ["b"]}}},
             readers={"x": lambda args, schema: {("limit", "n", args.get("k", 0)), ("w", "c", args.get("p"))}})
    assert g.decide("d", {"k": 2, "p": "a"}, None) is None
    assert g.decide("d", {"k": 3, "p": "a"}, None)                            # over the limit
    assert g.decide("d", {"k": 1, "p": "b"}, None)                            # listed, then closed by except
    assert g.decide("d", {"k": 1, "p": "z"}, None)                            # not listed


def test_the_example_tables_are_valid_and_a_table_with_a_session_memory_is_not():
    from gate_table import validate
    for name in ("payments", "mail", "web"):
        assert not validate.problems(table(name)), name
    assert validate.problems({**table("payments"), "counters": {"paid": {}}})
