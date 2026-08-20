import pytest

from policy import (
    ScannerOutcome,
    aggregate_scan_results,
    apply_encrypted_policy,
    resolve_encrypted_policy,
)

CLEAN = lambda name="s": ScannerOutcome(scanner_name=name, status="CLEAN")
INFECTED = lambda name="s", threat="EICAR": ScannerOutcome(scanner_name=name, status="INFECTED", threat=threat)
ERROR = lambda name="s": ScannerOutcome(scanner_name=name, status="ERROR")


def test_empty_results_fails_closed():
    decision = aggregate_scan_results([], "ALL_MUST_PASS")
    assert decision.status == "ERROR"
    assert decision.allowed is False


@pytest.mark.parametrize("policy_name", ["ALL_MUST_PASS", "ANY_DETECTION", "FIRST_DETECTION", "FIRST_SUCCESS"])
def test_all_clean_is_clean_under_every_policy(policy_name):
    decision = aggregate_scan_results([CLEAN("clamav"), CLEAN("yara")], policy_name)
    assert decision.status == "CLEAN"
    assert decision.allowed is True


@pytest.mark.parametrize("policy_name", ["ALL_MUST_PASS", "ANY_DETECTION", "FIRST_DETECTION"])
def test_any_infection_blocks_under_every_policy_except_first_success_ordering(policy_name):
    decision = aggregate_scan_results([CLEAN("clamav"), INFECTED("yara", "EICAR")], policy_name)
    assert decision.status == "INFECTED"
    assert decision.allowed is False
    assert decision.threat == "EICAR"


def test_all_must_pass_blocks_on_scanner_error_even_without_detection():
    decision = aggregate_scan_results([CLEAN("clamav"), ERROR("yara")], "ALL_MUST_PASS")
    assert decision.status == "ERROR"
    assert decision.allowed is False


def test_any_detection_tolerates_an_error_if_another_scanner_is_clean():
    # This is the deliberate behavioral difference from ALL_MUST_PASS -
    # see policy.py's docstring.
    decision = aggregate_scan_results([CLEAN("clamav"), ERROR("yara")], "ANY_DETECTION")
    assert decision.status == "CLEAN"
    assert decision.allowed is True


def test_any_detection_still_fails_closed_if_every_scanner_errors():
    decision = aggregate_scan_results([ERROR("clamav"), ERROR("yara")], "ANY_DETECTION")
    assert decision.status == "ERROR"
    assert decision.allowed is False


def test_first_detection_uses_first_matching_scanner_in_order():
    decision = aggregate_scan_results(
        [CLEAN("clamav"), INFECTED("yara", "Trojan.A"), INFECTED("eset", "Trojan.B")], "FIRST_DETECTION"
    )
    assert decision.threat == "Trojan.A"


def test_first_success_skips_errored_scanner_and_uses_next():
    decision = aggregate_scan_results([ERROR("clamav"), CLEAN("yara")], "FIRST_SUCCESS")
    assert decision.status == "CLEAN"
    assert decision.allowed is True


def test_first_success_reports_infected_from_first_completed_scanner():
    decision = aggregate_scan_results([ERROR("clamav"), INFECTED("yara", "EICAR")], "FIRST_SUCCESS")
    assert decision.status == "INFECTED"
    assert decision.allowed is False


def test_unknown_policy_fails_closed():
    decision = aggregate_scan_results([CLEAN("clamav")], "NOT_A_REAL_POLICY")
    assert decision.status == "ERROR"
    assert decision.allowed is False


def test_resolve_encrypted_policy_uses_category_then_default():
    policies = {"pdf_encrypted": "ALLOW", "default": "DENY"}
    assert resolve_encrypted_policy("pdf_encrypted", policies) == "ALLOW"
    assert resolve_encrypted_policy("unknown_encryption", policies) == "DENY"


def test_resolve_encrypted_policy_falls_back_when_default_missing():
    assert resolve_encrypted_policy("pdf_encrypted", {}) == "DENY"


@pytest.mark.parametrize("policy_value,expected_allowed,expected_quarantine,expected_review", [
    ("ALLOW", True, False, False),
    ("DENY", False, False, False),
    ("QUARANTINE", False, True, False),
    ("MARK_FOR_REVIEW", False, True, True),
])
def test_apply_encrypted_policy(policy_value, expected_allowed, expected_quarantine, expected_review):
    decision = apply_encrypted_policy(policy_value, "pdf_encrypted")
    assert decision.status == "ENCRYPTED"
    assert decision.allowed is expected_allowed
    assert decision.quarantine is expected_quarantine
    assert decision.needs_review is expected_review


def test_apply_encrypted_policy_unknown_value_fails_closed():
    decision = apply_encrypted_policy("NOT_A_REAL_POLICY", "pdf_encrypted")
    assert decision.allowed is False
