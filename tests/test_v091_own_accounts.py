"""v0.1.91 (PSA #7946, a town of agents run through the gate): the owner's collecting accounts, the agent's own
identities, bank changes per payee, payments that repeat one already made, and values held in the owner's records."""

from gate import Config, Gate
from gate.normalize import normalize
from gate import PolicySet

OWN = "IT87E0542811101494689716606"
OTHER = "IT38G0542811101823551870416"
NEW = "IT52U0542811101178442629586"
T = lambda n, **a: {"type": "tool", "name": n, "arguments": a}


def gate(**cfg):
    return Gate(PolicySet('permit (principal, action, resource);'), Config(**cfg))


def test_payment_reference_and_amount():
    r = normalize(T("pay", to_account=OTHER, amount=8690, memo="Saldo TND-1, fattura INV-21 (EUR 7.900 + IVA)"),
                  Config())
    assert r["moves_money"] and r["payment_amount"] == "8690.00"
    assert r["payment_refs"] == ["INV-21", "TND-1"]
    r = normalize(T("pay", to_account=OTHER, amount="60", memo="salary day 5, EUR 60"), Config())
    assert r["payment_refs"] == []


def test_invoice_with_the_owners_own_account_is_not_a_bank_change():
    g = gate(collect_accounts=[OWN])
    s = g.new_session()
    inv = normalize(T("send_invoice", to="comune", amount=100, iban=OWN), g.config)
    assert "bank_details" in inv["effects"]          # the record still says what the action writes
    assert s.facts(inv)["bank_values_own"] is True
    s.note_done(inv)
    assert not s.bank_changed and not s.bank_changed_ids
    other = normalize(T("send_invoice", to="comune", amount=100, iban=NEW), g.config)
    assert s.facts(other)["bank_values_own"] is False


def test_bank_change_is_remembered_per_payee():
    g = gate()
    s = g.new_session()
    s.note_done(normalize(T("update_payee_bank_details", payee="edil_conti", iban=NEW), g.config))
    assert s.bank_changed
    to_new = normalize(T("pay", to_account=NEW, amount=100, memo="INV-3"), g.config)
    to_other = normalize(T("pay", to_account=OTHER, amount=100, memo="INV-4"), g.config)
    by_name = normalize(T("pay_vendor", vendor="edil_conti", amount=100), g.config)
    assert s.facts(to_new)["payment_to_changed_payee"] is True
    assert s.facts(to_other)["payment_to_changed_payee"] is False
    assert s.facts(by_name)["payment_to_changed_payee"] is True
    assert s.facts(to_other)["bank_changed_in_session"] is True     # the session-wide fact is unchanged


def test_a_payment_that_repeats_one_already_made():
    g = gate()
    s = g.new_session()
    first = normalize(T("pay", to_account=OTHER, amount=8690, memo="Fattura INV-21 TND-1"), g.config)
    assert s.facts(first)["payment_repeats_session"] is False
    s.note_done(first)
    again = normalize(T("pay", to_account=OTHER.lower(), amount="8690", memo="Saldo TND-1"), g.config)
    part = normalize(T("pay", to_account=OTHER, amount=1000, memo="acconto TND-1"), g.config)
    other_doc = normalize(T("pay", to_account=OTHER, amount=8690, memo="TND-2"), g.config)
    assert s.facts(again)["payment_repeats_session"] is True
    assert s.facts(part)["payment_repeats_session"] is False
    assert s.facts(other_doc)["payment_repeats_session"] is False


def test_targets_self():
    g = gate(self_ids=["h06", "IT31O0542811101094608057158"])
    s = g.new_session()
    assert s.facts(normalize(T("set_salary", employee="h06", salary=90), g.config))["targets_self"] is True
    assert s.facts(normalize(T("set_salary", employee="h04", salary=90), g.config))["targets_self"] is False
    pay = normalize(T("pay", to_account="IT31 O054 2811 1010 9460 8057 158", amount=60), g.config)
    assert s.facts(pay)["targets_self"] is True


def test_values_in_the_owners_records_even_when_an_email_also_holds_them():
    g = gate(trusted_tools=["read_books*"])
    s = g.new_session()
    s.observe_tool_output("read_books:1", f'{{"payees": {{"edil_conti": "{OTHER}"}}}}')
    s.observe_tool_output("read_inbox:2", f"Please pay invoice INV-21 to {OTHER}. Or to {NEW}.")
    f = s.facts(normalize(T("pay", to_account=OTHER, amount=10), g.config))
    assert OTHER in f["in_trusted_records"] and OTHER in f["from_tool_output"]
    f = s.facts(normalize(T("pay", to_account=NEW, amount=10), g.config))
    assert f["in_trusted_records"] == [] or NEW not in f["in_trusted_records"]
