"""The gate on an example table: every action passes or does not pass, with the rule that decided.

    pip install "git+https://github.com/SiliconPsycheLabs/gate"
    python examples/quickstart.py

The gate keeps no copy of the company's records. When a rule needs one (the state of an invoice, its amount), it
asks a view: here a few records in memory; in a company, a small connector next to its own system.
"""
import json
from pathlib import Path

from gate_table import manager

TABLE = json.loads((Path(__file__).parent / "payments.json").read_text())


class Records:
    """A view over a few records in memory. A connector answers the same calls from the company's system."""

    invoices = {
        "INV-1": {"state": "validated", "amount": 1200},
        "INV-2": {"state": "registered", "amount": 300},
        "INV-3": {"state": "validated", "amount": 9000},
    }

    def record(self, kind, key):
        return self.invoices.get(key) if kind == "invoice" else None

    def all(self, kind):
        return {}

    def listed(self, name):
        return []

    def count(self, language, probe):
        return 0

    def compiles(self, language, text):
        return False

    def schema(self, language):
        return {"tables": {}, "views": {}}

    def actor(self):
        return "billing-agent"

    def clock(self):
        return "10:00"

    def day(self):
        return "2026-11-24"


ACTIONS = [
    {"tool": "pay_invoice", "args": {"number": "INV-1"}},
    {"tool": "pay_invoice", "args": {"number": "INV-2"}},
    {"tool": "pay_invoice", "args": {"number": "INV-3"}},
    {"tool": "pay_invoice", "args": {"number": "INV-1", "iban": "XX00 0000"}},
    {"tool": "delete_supplier", "args": {"id": "S-7"}},
    {"tool": "wire_money", "args": {"to": "anyone"}},
]

if __name__ == "__main__":
    for action in ACTIONS:
        rec, _ = manager.decide(TABLE, action, Records())
        answer = "passes" if rec["outcome"] == "pass" else "does not pass: " + rec["reason"]
        print(f"{action['tool']} {json.dumps(action['args'])}\n    {answer}  (rule: {rec['rule']})")
