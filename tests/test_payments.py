"""The record of an action that moves money (PSA, 2026-11-18): `moves_money` and `payment_targets` are facts of the
record, computed by string match like every other field. The rules that read them are not shipped in these packs."""

import pytest

from gate import Config
from gate.normalize import normalize

A = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
C = Config(workspace="/work/repo")
T = lambda n, **a: {"type": "tool", "name": n, "arguments": a}
S = lambda c: {"type": "shell", "command": c}


@pytest.mark.parametrize("action", [
    T("mcp__wallet__send_bitcoin", to_address=A, amount_btc="0.01"),
    T("mcp__bank__create_transfer", iban="IT60X0542811101000000123456", amount="900"),
    T("mcp__stripe__create_refund", charge="ch_1123", amount=4000),
    T("mcp__billing__pay_bill", bill_id="b-77"),
    T("mcp__broker__place_order", symbol="ACME", quantity=10),
    S(f"bitcoin-cli sendtoaddress {A} 0.01"),
    S("stripe payouts create --amount 5000 --currency eur"),
    S("cast send 0xabc123def4567890 --value 1ether"),
    S("lncli payinvoice lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq"),
])
def test_an_action_that_moves_money_is_marked(action):
    assert normalize(action, C)["moves_money"] is True


@pytest.mark.parametrize("action", [
    T("mcp__wallet__send_bitcoin", to_address=A, amount_btc="0.01"),
    S(f"bitcoin-cli sendtoaddress {A} 0.01"),
])
def test_the_destination_is_recorded(action):
    assert A in normalize(action, C)["payment_targets"]


def test_a_shell_payment_records_only_the_destination():
    assert normalize(S("cast send 0xabc123def4567890 --value 1ether"), C)["payment_targets"] == ["0xabc123def4567890"]


@pytest.mark.parametrize("action", [
    T("mcp__mail__send_email", to="anna@x.io", subject="notes", body="x"),
    T("mcp__auth__send_verification_token", user_id="me"),
    T("mcp__billing__send_invoice", to="anna@x.io", invoice_id="1123"),
    T("mcp__fs__transfer_file", source="/work/repo/r.pdf", destination="/work/repo/out/r.pdf"),
    T("mcp__wallet__get_balance", account="main"),
    T("mcp__bank__list_payments", account="main"),
    S("bitcoin-cli getbalance"),
    S("bitcoin-cli getnewaddress"),
    T("mcp__github__transfer_repository", owner="o", repo="r", new_owner="org"),
])
def test_look_alikes_that_move_no_money_are_not_marked(action):
    assert normalize(action, C)["moves_money"] is False
