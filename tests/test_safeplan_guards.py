"""Guard-rail tests for SafePlan hardening (limits, types, aliases, dtypes,
count suppression, and the prepare/execute split)."""

import pandas as pd
import pytest

import safedata
from safedata import Policy, SafetyError
from safedata.safeplan import (SafePlan, MetricSpec, execute_safeplan,
                               validate_safeplan, parse_safeplan,
                               prepare_safeplan, execute_prepared)


def _df():
    return pd.DataFrame({
        "region": ["N"] * 30 + ["S"] * 30,
        "revenue": range(60),
        "label": [f"L{i}" for i in range(60)],
    })


# --- limit hardening (negative / zero / non-int) ---------------------------

@pytest.mark.parametrize("bad_limit", [-1, 0, -1000])
def test_limit_below_one_blocked(bad_limit):
    with pytest.raises(SafetyError):
        execute_safeplan(SafePlan(operation="value_counts", group_by=["region"],
                                  limit=bad_limit), _df(), Policy.basic())


def test_negative_limit_does_not_bypass_max_rows():
    # df.head(-1) would otherwise return almost everything.
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="count_rows", limit=-1),
                          _df(), Policy.basic())


def test_bool_limit_rejected():
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="count_rows", limit=True),
                          _df(), Policy.basic())


# --- bad model JSON should raise SafetyError, never a raw ValueError --------

def test_parse_bad_limit_raises_safetyerror():
    with pytest.raises(SafetyError):
        parse_safeplan({"operation": "count_rows", "limit": "abc"})


def test_parse_non_string_operation():
    with pytest.raises(SafetyError):
        parse_safeplan({"operation": 123})


@pytest.mark.parametrize("key", ["group_by", "metrics", "filters"])
def test_parse_non_list_fields(key):
    with pytest.raises(SafetyError):
        parse_safeplan({"operation": "count_rows", key: "notalist"})


def test_safe_query_survives_bad_json_limit():
    # End to end: a model emitting a bad limit must come back blocked, not crash.
    res = safedata.safe_query(_df(), "q",
                              model=lambda p: '{"operation":"count_rows","limit":"abc"}',
                              policy=Policy.basic(), max_retries=1)
    assert res.blocked is True and res.answer is None


# --- alias safety ----------------------------------------------------------

def test_alias_count_reserved():
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="aggregate",
                                   metrics=[MetricSpec("revenue", "sum", "count")]),
                          _df(), Policy.basic())


@pytest.mark.parametrize("alias", ["bad name", "1bad", "drop;", "x" * 70])
def test_alias_must_be_simple_name(alias):
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="aggregate",
                                   metrics=[MetricSpec("revenue", "sum", alias)]),
                          _df(), Policy.basic())


# --- numeric aggregation requires numeric column ---------------------------

@pytest.mark.parametrize("agg", ["sum", "mean", "median", "std"])
def test_numeric_agg_on_text_blocked(agg):
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="aggregate",
                                   metrics=[MetricSpec("label", agg)]),
                          _df(), Policy.basic())


def test_count_nunique_allowed_on_text():
    res = execute_safeplan(SafePlan(operation="aggregate",
                                    metrics=[MetricSpec("label", "nunique", "u")]),
                           _df(), Policy.basic())
    assert res["u"] == 60


# --- sort_by must reference a real output column ----------------------------

def test_sort_by_unknown_blocked():
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="groupby_aggregate", group_by=["region"],
                                   metrics=[MetricSpec("revenue", "sum", "tot")],
                                   sort_by="nope"), _df(), Policy.basic())


def test_sort_by_alias_allowed():
    res = execute_safeplan(SafePlan(operation="groupby_aggregate", group_by=["region"],
                                    metrics=[MetricSpec("revenue", "sum", "tot")],
                                    sort_by="tot", ascending=False), _df(), Policy.basic())
    assert list(res["tot"]) == sorted(res["tot"], reverse=True)


# --- count_rows small-filtered suppression ----------------------------------

def test_count_rows_small_filtered_blocked_regulated():
    df = pd.DataFrame({"city": ["X"] + ["Y"] * 50, "v": range(51)})
    with pytest.raises(SafetyError):
        execute_safeplan(SafePlan(operation="count_rows",
                                  filters=[{"column": "city", "op": "==", "value": "X"}]),
                         df, Policy.regulated())


def test_count_rows_unfiltered_allowed_regulated():
    df = pd.DataFrame({"city": ["X"] + ["Y"] * 50, "v": range(51)})
    res = execute_safeplan(SafePlan(operation="count_rows"), df, Policy.regulated())
    assert res["count"] == 51


# --- prepare / execute split ------------------------------------------------

def test_prepare_validates_without_executing():
    df = _df()
    model = lambda p: '{"operation":"groupby_aggregate","group_by":["region"],"metrics":[{"column":"revenue","agg":"sum","as_name":"tot"}]}'
    prepared = prepare_safeplan(df, "totals", model=model, policy=Policy.basic())
    assert prepared.blocked is False
    assert prepared.plan is not None and prepared.plan.operation == "groupby_aggregate"
    # Executing the prepared plan yields the answer.
    res = execute_prepared(prepared)
    assert res.blocked is False and "tot" in res.answer.columns


def test_prepare_blocks_invalid_plan():
    prepared = prepare_safeplan(_df(), "q", model=lambda p: '{"operation":"export"}',
                                policy=Policy.regulated(), max_retries=1)
    assert prepared.blocked is True and prepared.plan is None
