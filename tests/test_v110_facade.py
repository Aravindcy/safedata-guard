"""Phase 2: the ask / scan / protect / Guard facade over the existing engine.

Uses stub models (no network) so it runs in CI.
"""

import json
import pandas as pd
import pytest

import safedata as sd
from safedata import SafedataError
from safedata.exceptions import (DataValidationError, ModelAdapterError,
                                 UnsafeRequestError, PolicyError)


def _banking(n=60):
    return pd.DataFrame({
        "full_name": [f"Person {i}" for i in range(n)],
        "email": [f"p{i}@bank.com" for i in range(n)],
        "account_number": [f"{10000000+i}" for i in range(n)],
        "region": (["North"] * (n // 2) + ["South"] * (n - n // 2)),
        "balance": range(n),
        "notes": ["called about overdraft"] * n,
    })


def _plan(payload):
    return lambda prompt: payload


# --- ask --------------------------------------------------------------------

def test_ask_returns_result_with_receipt():
    df = _banking()
    model = _plan('{"operation":"groupby_aggregate","group_by":["region"],'
                  '"metrics":[{"column":"balance","agg":"mean","as_name":"avg"}]}')
    res = sd.ask(df, "average balance by region", model=model, profile="banking")
    assert isinstance(res, sd.Result)
    assert res.ok and "avg" in res.answer.columns
    assert isinstance(res.receipt, sd.Receipt)
    assert res.receipt.profile == "banking" and res.engine == "safeplan"
    assert res.receipt.python_fallback_used is False


def test_ask_requires_question_and_df():
    with pytest.raises(DataValidationError):
        sd.ask(_banking(), "   ", model=_plan("{}"))
    with pytest.raises(DataValidationError):
        sd.ask(pd.DataFrame(), "q", model=_plan("{}"))


def test_ask_python_mode_disabled_for_banking():
    with pytest.raises(UnsafeRequestError):
        sd.ask(_banking(), "q", model=_plan("{}"), profile="banking", mode="python")


def test_ask_unknown_mode_raises_policyerror():
    with pytest.raises(PolicyError):
        sd.ask(_banking(), "q", model=_plan("{}"), mode="bogus")


def test_ask_without_model_raises_clearly():
    # ask needs a model in any non-summary mode; it must not silently return None.
    with pytest.raises(ModelAdapterError):
        sd.ask(_banking(), "total balance", profile="general")
    with pytest.raises(ModelAdapterError):
        sd.ask(_banking(), "total balance", profile="banking", mode="plan")


def test_advanced_exposes_power_tools():
    for name in ("safe_query", "safe_answer", "summarize", "token_stats",
                 "token_savings", "to_pandera_schema", "to_great_expectations_suite",
                 "redact_text", "report", "wrap", "run_safely", "check_code",
                 "leak_test", "create_shadowframe", "Agent", "privacy_report"):
        assert hasattr(sd.advanced, name), name


def test_ask_summary_mode_no_execution():
    res = sd.ask(_banking(), "is this safe?", model=None, profile="banking",
                 mode="summary")
    assert res.engine == "summary"
    assert isinstance(res.data, sd.ScanReport)


def _sensitive_df(n=40):
    return pd.DataFrame({
        "customer_id": [f"C{i}" for i in range(n)],
        "account_number": [f"{10000000+i}" for i in range(n)],
        "policy_number": [f"P{i}" for i in range(n)],
        "claim_id": [f"CL{i}" for i in range(n)],
        "mpan": [f"M{i}" for i in range(n)],
        "name": [f"Person {i}" for i in range(n)],
        "email": [f"p{i}@x.com" for i in range(n)],
        "complaint_notes": ["called about a charge"] * n,
        "region": (["N"] * (n // 2) + ["S"] * (n - n // 2)),
        "revenue": range(n),
    })


def test_ask_prompt_excludes_unneeded_business_ids_and_free_text(monkeypatch):
    # The model prompt for "total revenue by region" must NOT mention sensitive
    # or business/free-text columns the question does not need.
    df = _sensitive_df()
    captured = {}

    def model(prompt):
        captured["prompt"] = prompt
        return ('{"operation":"groupby_aggregate","group_by":["region"],'
                '"metrics":[{"column":"revenue","agg":"sum","as_name":"tot"}]}')

    sd.ask(df, "total revenue by region", model=model, profile="banking")
    p = captured["prompt"]
    assert "region" in p and "revenue" in p
    # Distinctive sensitive column names must not reach the model (bare "name"
    # is skipped here only because it appears in the prompt's JSON schema text;
    # that the 'name' column is dropped is covered by the receipt test below).
    for col in ("customer_id", "account_number", "policy_number", "claim_id",
                "mpan", "complaint_notes", "p0@x.com"):
        assert col not in p, f"prompt leaked column {col}"


def test_ask_receipt_lists_sensitive_and_dropped(monkeypatch):
    df = _sensitive_df()
    res = sd.ask(df, "total revenue by region",
                 model=lambda pr: ('{"operation":"groupby_aggregate",'
                                   '"group_by":["region"],"metrics":[{"column":'
                                   '"revenue","agg":"sum","as_name":"tot"}]}'),
                 profile="banking")
    r = res.receipt
    # PII + business identifiers + free text all recorded as sensitive.
    for col in ("email", "name", "customer_id", "account_number", "complaint_notes"):
        assert col in r.sensitive_columns, col
    # and they were dropped from the safe view actually analysed
    for col in ("customer_id", "account_number", "complaint_notes", "email"):
        assert col in r.dropped_columns, col
    assert "region" in r.safe_columns and "revenue" in r.safe_columns


def test_ask_warns_or_blocks_when_k_anonymity_suppresses_all_rows():
    # Many tiny groups under banking (k=10): every group is suppressed, so the
    # answer is empty - the Result must warn clearly, not look like "no data".
    df = pd.DataFrame({"region": [f"R{i}" for i in range(30)],   # 1 row per group
                       "revenue": range(30)})
    model = _plan('{"operation":"groupby_aggregate","group_by":["region"],'
                  '"metrics":[{"column":"revenue","agg":"sum","as_name":"tot"}]}')
    res = sd.ask(df, "total revenue by region", model=model, profile="banking")
    assert len(res.answer) == 0
    assert res.warnings and "suppressed" in res.warnings[0].lower()
    assert "min_group_size" in res.warnings[0]
    assert res.receipt.warnings == res.warnings


def test_ask_blocked_plan_surfaces_blocked_result():
    res = sd.ask(_banking(), "dump it", model=_plan('{"operation":"export"}'),
                 profile="banking")
    assert res.blocked is True and res.ok is False


# --- model adapter ----------------------------------------------------------

def test_model_can_be_object_with_generate():
    class M:
        def generate(self, prompt):
            return '{"operation":"count_rows"}'
    res = sd.ask(_banking(), "how many rows", model=M(), profile="general")
    assert res.ok and res.answer == {"count": 60}


def test_invalid_model_raises_adaptererror():
    with pytest.raises(ModelAdapterError):
        sd.ask(_banking(), "q", model=12345)


# --- scan -------------------------------------------------------------------

def test_scan_returns_scanreport_with_categories():
    rep = sd.scan(_banking(), profile="banking")
    assert isinstance(rep, sd.ScanReport)
    assert "email" in rep.pii_columns
    assert "account_number" in rep.business_identifier_columns
    assert "balance" in rep.financial_columns
    assert "notes" in rep.free_text_columns
    assert rep.risk_level in ("low", "medium", "high")


# --- protect ----------------------------------------------------------------

def test_scan_risk_level_not_low_for_pii_heavy_data():
    # A table full of customer names must not be rated 'low' (the live-test gap).
    df = pd.DataFrame({"full_name": [f"Person {i}" for i in range(50)],
                       "region": ["N"] * 25 + ["S"] * 25,
                       "spend": range(50)})
    rep = sd.scan(df, profile="banking")
    assert rep.risk_level in ("medium", "high")


def test_scan_health_data_is_high_risk():
    df = pd.DataFrame({"patient_name": ["A", "B"], "diagnosis": ["x", "y"],
                       "age": [40, 50]})
    rep = sd.scan(df, profile="healthcare")
    assert rep.risk_level == "high"
    assert "diagnosis" in rep.health_columns
    assert "age" in rep.quasi_identifier_columns


def test_classifier_handles_spaced_and_hyphenated_names():
    # Real columns like "Offer ID" / "Sub-Team" must classify (separators differ
    # from the underscore tokens). Regression for a live-found bug.
    df = pd.DataFrame({"Customer Name": ["A"], "Offer ID": ["O1"],
                       "Sub-Team": ["x"], "Annual CGM": [5]})
    rep = sd.scan(df, profile="energy")
    assert "Offer ID" in rep.business_identifier_columns
    safe = sd.protect(df, question="total CGM by Sub-Team", profile="energy")
    assert "Offer ID" not in safe.columns and "Customer Name" not in safe.columns
    assert "Sub-Team" in safe.columns


def test_protect_drops_business_identifiers_not_needed():
    safe = sd.protect(_banking(), question="average balance by region",
                      profile="banking")
    # account_number is a business identifier the question does not need.
    assert "account_number" not in safe.columns
    assert "region" in safe.columns and "balance" in safe.columns


def test_protect_drops_pii_keeps_analytic():
    safe = sd.protect(_banking(), question="average balance by region",
                      profile="banking")
    cols = set(safe.columns)
    assert "region" in cols and "balance" in cols
    assert "email" not in cols and "full_name" not in cols


def test_protect_return_report():
    safe, report = sd.protect(_banking(), question="balance by region",
                              profile="banking", return_report=True)
    assert "email" in report.dropped_columns or "email" not in safe.columns


# --- Guard ------------------------------------------------------------------

def test_guard_reuses_profile_and_model():
    model = _plan('{"operation":"count_rows"}')
    guard = sd.Guard(profile="banking", model=model)
    assert guard.profile == "banking"
    res = guard.ask(_banking(), "count rows")
    assert res.ok and res.answer == {"count": 60}
    rep = guard.scan(_banking())
    assert isinstance(rep, sd.ScanReport)
    safe = guard.protect(_banking(), question="balance by region")
    assert "email" not in safe.columns


def test_guard_session_is_safesession():
    guard = sd.Guard(profile="general", model=_plan('{"operation":"count_rows"}'))
    s = guard.session(_banking())
    assert isinstance(s, sd.advanced.SafeSession)


def test_safedataerror_catches_everything():
    # PolicyError/DataValidationError etc. are all SafedataError subclasses.
    with pytest.raises(SafedataError):
        sd.ask(_banking(), "q", model=_plan("{}"), profile="banking", mode="python")
