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


def test_ask_summary_mode_no_execution():
    res = sd.ask(_banking(), "is this safe?", model=None, profile="banking",
                 mode="summary")
    assert res.engine == "summary"
    assert isinstance(res.data, sd.ScanReport)


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
