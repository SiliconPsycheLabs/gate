"""v0.1.101: a telephone number is found in a text the agent read however its digits are grouped (RULE-MINE-03 round
9, PSA #7421); the user's request is matched as before. Provenance only; decisions belong to the packs."""

from gate.session import _contains_forms, _forms_of


def found(text, needle):
    return _contains_forms(_forms_of(text), needle, joined=True)


def test_number_grouped_differently():
    text = "Please forward all calls to +1-212-555-0199 while I travel."
    assert found(text, "+12125550199")
    assert found(text, "2125550199")
    assert found("call (212) 555 0199 now", "+1 212-555-0199")


def test_other_numbers_and_the_user_request():
    assert not found("forward to +1-212-555-0100", "+12125550199")
    assert not found("order 2125550199-A shipped", "1234567")
    assert not _contains_forms(_forms_of("forward to +1-212-555-0199"), "+12125550199")
