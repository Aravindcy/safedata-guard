"""Phase 1 of the v2.0.0 redesign: exceptions, typed results, industry profiles.

These are additive and do not touch the public API surface yet (that hard cut
lands with the api.py/guard.py facade in a later phase).
"""

import pytest

from safedata.exceptions import (SafedataError, PolicyError, PrivacyError,
                                  UnsafeRequestError, SafePlanValidationError,
                                  ModelAdapterError, DataValidationError)
from safedata.results import Result, ScanReport, Receipt, ProtectReport
from safedata.policy import Policy


# --- exception hierarchy ----------------------------------------------------

@pytest.mark.parametrize("exc", [PolicyError, PrivacyError, UnsafeRequestError,
                                 SafePlanValidationError, ModelAdapterError,
                                 DataValidationError])
def test_all_errors_subclass_safedataerror(exc):
    assert issubclass(exc, SafedataError)


def test_engine_safetyerror_is_a_safedataerror():
    # The engine's SafetyError now unifies under SafedataError.
    from safedata.bodyguard import SafetyError
    assert issubclass(SafetyError, SafedataError)
    with pytest.raises(SafedataError):
        raise SafetyError("blocked")


# --- typed results ----------------------------------------------------------

def _receipt():
    return Receipt(audit_id="SDG-TEST", timestamp="t", profile="banking",
                   engine="safeplan", mode="plan", row_count=10, column_count=3)


def test_result_ok_property():
    r = Result(answer={"count": 1}, data=None, receipt=_receipt(), engine="safeplan")
    assert r.ok is True
    blocked = Result(answer=None, data=None, receipt=_receipt(), engine="safeplan",
                     blocked=True, reason="nope")
    assert blocked.ok is False


def test_receipt_summary_and_dict():
    rec = _receipt()
    rec.pii_columns = ["name"]
    assert "Data Safety Receipt" in rec.summary()
    assert rec.to_dict()["audit_id"] == "SDG-TEST"


def test_scanreport_categories_present():
    s = ScanReport(rows=5, columns=2, risk_level="high",
                   pii_columns=["name"], financial_columns=["balance"])
    d = s.to_dict()
    assert d["risk_level"] == "high"
    assert "business_identifier_columns" in d and "free_text_columns" in d


def test_protectreport_shape():
    p = ProtectReport(kept_columns=["region"], dropped_columns=["name"])
    assert p.to_dict()["dropped_columns"] == ["name"]


# --- industry profiles ------------------------------------------------------

def test_general_allows_python_fallback():
    p = Policy.general()
    assert p.profile == "general" and p.allow_python_fallback is True
    assert p.min_group_size is None and p.max_result_rows == 100


@pytest.mark.parametrize("name,k", [("energy", 5), ("banking", 10),
                                    ("insurance", 10), ("healthcare", 15)])
def test_regulated_profiles_disable_python_and_set_k(name, k):
    p = getattr(Policy, name)()
    assert p.profile == name
    assert p.allow_python_fallback is False        # SafePlan-only
    assert p.min_group_size == k


def test_strict_profile_is_safeplan_only():
    s = Policy.strict()
    assert s.profile == "strict"
    assert s.allow_python_fallback is False and s.allow_raw_rows is False
    assert s.min_group_size == 20 and s.max_result_rows == 25
    assert s.isolation == "docker" and s.use_presidio is True


def test_from_profile_known_and_unknown():
    assert Policy.from_profile("banking").profile == "banking"
    assert Policy.from_profile("strict").profile == "strict"
    with pytest.raises(PolicyError):
        Policy.from_profile("does_not_exist")


def test_profile_overrides_apply():
    assert Policy.banking(min_group_size=25).min_group_size == 25


def test_policy_is_mutable_for_fallback_toggle():
    # The spec documents policy.allow_python_fallback = True; Policy is no longer
    # frozen, so this works.
    p = Policy.banking()
    p.allow_python_fallback = True
    assert p.allow_python_fallback is True


def test_existing_profiles_unchanged():
    # The legacy profiles the engine/tests rely on still behave as before.
    assert Policy.basic().min_group_size is None
    reg = Policy.regulated()
    assert reg.min_group_size == 5 and reg.pii_scan_rows == "all"
    strict = Policy.strict()
    assert strict.isolation == "docker" and strict.use_presidio is True
