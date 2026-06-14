"""Guard-rail tests for SafePlan hardening (limits, types, aliases, dtypes,
count suppression, and the prepare/execute split)."""

import pandas as pd
import pytest

import safedata
from safedata import Policy
from safedata.bodyguard import SafetyError
from safedata.safeplan import (SafePlan, MetricSpec, execute_safeplan,
                               validate_safeplan, parse_safeplan,
                               prepare_safeplan, execute_prepared, safe_query)


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
    res = safe_query(_df(), "q",
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


# --- untrusted JSON: non-string fields must not crash with TypeError --------

@pytest.mark.parametrize("payload", [
    '{"operation":"value_counts","group_by":[{"bad":"region"}],"limit":5}',
    '{"operation":"count_rows","filters":[{"column":["region"],"op":"==","value":"N"}]}',
    '{"operation":"aggregate","metrics":[{"column":["revenue"],"agg":"sum"}]}',
    '{"operation":"aggregate","metrics":[{"column":"revenue","agg":["sum"]}]}',
    '{"operation":"count_rows","filters":[{"column":"region","op":["=="],"value":"N"}]}',
    '{"operation":"count_rows","filters":["notadict"]}',
    '{"operation":"count_rows","filters":[{"column":"region","op":"==","value":{"x":1}}]}',
    '{"operation":"count_rows","filters":[{"column":"region","op":"in","value":"N"}]}',
])
def test_untrusted_json_returns_blocked_not_crash(payload):
    res = safe_query(_df(), "q", model=lambda p, pl=payload: pl,
                              policy=Policy.basic(), max_retries=1)
    assert res.blocked is True and res.answer is None


# --- booleans must be real booleans, not truthy strings ---------------------

@pytest.mark.parametrize("key", ["include_count", "ascending"])
def test_string_boolean_rejected(key):
    with pytest.raises(SafetyError):
        parse_safeplan({"operation": "count_rows", key: "false"})


def test_real_boolean_accepted():
    p = parse_safeplan({"operation": "count_rows", "include_count": False,
                        "ascending": True})
    assert p.include_count is False and p.ascending is True


# --- output-name collisions -------------------------------------------------

def test_duplicate_alias_blocked():
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="groupby_aggregate", group_by=["region"],
                                   metrics=[MetricSpec("revenue", "sum", "x"),
                                            MetricSpec("revenue", "mean", "x")]),
                          _df(), Policy.basic())


def test_alias_colliding_with_group_by_blocked():
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="groupby_aggregate", group_by=["region"],
                                   metrics=[MetricSpec("revenue", "sum", "region")]),
                          _df(), Policy.basic())


# --- filter value / column dtype compatibility ------------------------------

@pytest.mark.parametrize("op", [">", ">=", "<", "<="])
def test_ordering_numeric_column_with_string_blocked(op):
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="count_rows",
                                   filters=[{"column": "revenue", "op": op, "value": "5"}]),
                          _df(), Policy.basic())


def test_ordering_text_column_with_number_blocked():
    with pytest.raises(SafetyError):
        validate_safeplan(SafePlan(operation="count_rows",
                                   filters=[{"column": "label", "op": "<", "value": 5}]),
                          _df(), Policy.basic())


def test_equality_dtype_mismatch_allowed_and_safe():
    # == between a numeric column and a string does not crash in pandas; allowed.
    res = execute_safeplan(SafePlan(operation="count_rows",
                                    filters=[{"column": "revenue", "op": "==", "value": "5"}]),
                           _df(), Policy.basic())
    assert res["count"] == 0


def test_valid_numeric_filter_still_works():
    res = execute_safeplan(SafePlan(operation="count_rows",
                                    filters=[{"column": "revenue", "op": ">", "value": 5}]),
                           _df(), Policy.basic())
    assert res["count"] == 54


def test_safe_query_dtype_mismatch_blocks_not_crash():
    df = _df()
    payload = ('{"operation":"aggregate","filters":[{"column":"revenue","op":">",'
               '"value":"5"}],"metrics":[{"column":"revenue","agg":"sum"}]}')
    res = safe_query(df, "q", model=lambda p: payload,
                              policy=Policy.basic(), max_retries=1)
    assert res.blocked is True and res.answer is None


def test_execute_prepared_fails_closed_on_unexpected_error():
    # A backstop: even if a value slips past validation, execution fails closed.
    from safedata.safeplan import prepare_safeplan, execute_prepared
    df = _df()
    prepared = prepare_safeplan(df, "q",
                                model=lambda p: '{"operation":"count_rows"}',
                                policy=Policy.basic())
    # Corrupt the validated plan post-validation to force an execution error.
    prepared.plan.filters = [{"column": "revenue", "op": ">", "value": "oops"}]
    res = execute_prepared(prepared)
    assert res.blocked is True and res.answer is None


# --- limit must be a real integer (no coercion) -----------------------------

@pytest.mark.parametrize("payload", [
    '{"operation":"count_rows","limit":true}',
    '{"operation":"count_rows","limit":1.9}',
    '{"operation":"count_rows","limit":"5"}',
])
def test_limit_non_integer_rejected(payload):
    import json
    with pytest.raises(SafetyError):
        parse_safeplan(json.loads(payload))


def test_limit_real_integer_accepted():
    import json
    assert parse_safeplan(json.loads('{"operation":"count_rows","limit":5}')).limit == 5
