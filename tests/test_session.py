import json
import pandas as pd
import pytest

import safedata
from safedata.session import SafeSession, estimate_question_cost


def _df():
    return pd.DataFrame({
        "name": [f"Person {i}" for i in range(60)],
        "city": (["London"] * 30 + ["Leeds"] * 30),
        "order_value": list(range(60)),
    })


def _plan_model(operation, group_by=None, metrics=None, filters=None):
    """A stub model that always returns the given JSON SafePlan."""
    plan = {"operation": operation}
    if group_by:
        plan["group_by"] = group_by
    if metrics:
        plan["metrics"] = metrics
    if filters:
        plan["filters"] = filters
    return lambda prompt: json.dumps(plan)


def test_cost_increases_for_raw_and_pii_words():
    base = estimate_question_cost("average order value", ["name"])
    raw = estimate_question_cost("show all names", ["name"])
    assert raw > base


def test_session_blocks_when_budget_exceeded():
    df = _df()
    model = _plan_model("count_rows")
    s = SafeSession(df, model=model, policy=safedata.Policy.basic(), budget=2)
    s.ask("how many rows")                       # cost 1, used=1
    out = s.ask("show all customer names raw export")  # high cost -> over budget
    assert out["blocked"] is True
    assert "budget" in out["reason"].lower()


def test_session_allows_distinct_safe_questions():
    df = _df()
    # two different aggregates, no narrowing -> both allowed
    s = SafeSession(df, model=_plan_model("count_rows"),
                    policy=safedata.Policy.basic(), budget=20)
    a = s.ask("how many rows")
    assert a["blocked"] is False and a["answer"] == {"count": 60}


def test_session_blocks_differencing_narrowing():
    df = _df()
    metrics = [{"column": "order_value", "agg": "mean", "as_name": "avg"}]
    s = SafeSession(df, model=None, policy=safedata.Policy.basic(), budget=50)

    # First: mean order_value where city == London (non-PII columns survive the
    # safe view, so the plan actually executes).
    s.model = _plan_model("aggregate", metrics=metrics,
                          filters=[{"column": "city", "op": "==", "value": "London"}])
    first = s.ask("average order value in London")
    assert first["blocked"] is False

    # Then: same aggregate but with a tightened filter -> differencing attack.
    s.model = _plan_model("aggregate", metrics=metrics, filters=[
        {"column": "city", "op": "==", "value": "London"},
        {"column": "order_value", "op": "!=", "value": 5}])
    second = s.ask("average order value in London excluding one record")
    assert second["blocked"] is True
    assert "differencing" in second["reason"].lower()


def test_session_allows_disjoint_sibling_query():
    # Same aggregate, different equality value (London vs Leeds) is NOT a
    # differencing attack - disjoint populations, no individual isolated.
    df = _df()
    metrics = [{"column": "order_value", "agg": "mean", "as_name": "avg"}]
    s = SafeSession(df, model=None, policy=safedata.Policy.basic(), budget=50)
    s.model = _plan_model("aggregate", metrics=metrics,
                          filters=[{"column": "city", "op": "==", "value": "London"}])
    assert s.ask("avg in London")["blocked"] is False
    s.model = _plan_model("aggregate", metrics=metrics,
                          filters=[{"column": "city", "op": "==", "value": "Leeds"}])
    assert s.ask("avg in Leeds")["blocked"] is False


def test_session_blocks_threshold_shift():
    # Same equality base, a shifted range threshold = differencing.
    df = _df()
    metrics = [{"column": "order_value", "agg": "mean", "as_name": "avg"}]
    s = SafeSession(df, model=None, policy=safedata.Policy.basic(), budget=50)
    s.model = _plan_model("aggregate", metrics=metrics, filters=[
        {"column": "city", "op": "==", "value": "London"},
        {"column": "order_value", "op": ">", "value": 5}])
    assert s.ask("avg London over 5")["blocked"] is False
    s.model = _plan_model("aggregate", metrics=metrics, filters=[
        {"column": "city", "op": "==", "value": "London"},
        {"column": "order_value", "op": ">", "value": 6}])
    assert s.ask("avg London over 6")["blocked"] is True


def test_session_does_not_block_identical_repeat():
    # Asking the exact same query twice is not a differencing attack.
    df = _df()
    metrics = [{"column": "order_value", "agg": "mean", "as_name": "avg"}]
    model = _plan_model("aggregate", metrics=metrics,
                        filters=[{"column": "city", "op": "==", "value": "London"}])
    s = SafeSession(df, model=model, policy=safedata.Policy.basic(), budget=50)
    s.ask("average order value in London")
    out = s.ask("average order value in London again")
    assert out["blocked"] is False
