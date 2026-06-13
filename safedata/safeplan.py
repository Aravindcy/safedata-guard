"""
SafePlan engine: the LLM returns a restricted JSON analysis plan, and safedata
executes it locally. No generated Python runs for these operations, so the whole
class of code-injection/exfiltration risk does not apply - there is no arbitrary
code, only a validated plan run by a fixed interpreter.

This is the safest path and covers common analysis (aggregate, group-by, counts,
value_counts, describe). For richer/custom analysis, fall back to the guarded
Python path (safe_answer / Agent), which screens generated code instead.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

from .analysis import _as_pandas
from .firewall import create_privacy_plan, make_safe_view
from .policy import Policy
from .bodyguard import SafetyError, _redact_result
from .translator import summarize
from .receipt import create_receipt


ALLOWED_OPERATIONS = {"aggregate", "groupby_aggregate", "count_rows",
                      "value_counts", "describe"}
BLOCKED_OPERATIONS = {"show_rows", "raw_lookup", "export", "list_customers",
                      "head", "sample", "to_csv"}
ALLOWED_AGGS = {"sum", "mean", "median", "min", "max", "count", "nunique", "std"}
ALLOWED_FILTER_OPS = {"==", "!=", ">", ">=", "<", "<=", "in"}


@dataclass
class MetricSpec:
    column: str
    agg: str
    as_name: Optional[str] = None


@dataclass
class SafePlan:
    operation: str
    group_by: List[str] = field(default_factory=list)
    metrics: List[MetricSpec] = field(default_factory=list)
    filters: List[dict] = field(default_factory=list)
    include_count: bool = True
    limit: int = 50
    sort_by: Optional[str] = None
    ascending: bool = False


@dataclass
class SafePlanResult:
    answer: Any
    plan: Optional[SafePlan]
    blocked: bool
    reason: Optional[str]
    receipt: dict
    attempts: List[dict] = field(default_factory=list)


# --- JSON parsing (never trust the model) -----------------------------------

def extract_json_plan(model_output) -> dict:
    """Pull a JSON object out of the model reply, tolerating fences/chatter."""
    text = str(model_output).strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            text = text[start:end + 1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise SafetyError(f"Model did not return valid JSON: {e}")
    if not isinstance(obj, dict):
        raise SafetyError("Model output must be a single JSON object.")
    return obj


def parse_safeplan(obj: dict) -> SafePlan:
    if "operation" not in obj:
        raise SafetyError("Plan is missing the required 'operation' field.")
    metrics = []
    for m in obj.get("metrics", []) or []:
        if not isinstance(m, dict) or "column" not in m or "agg" not in m:
            raise SafetyError("Each metric needs 'column' and 'agg'.")
        metrics.append(MetricSpec(column=m["column"], agg=m["agg"],
                                  as_name=m.get("as_name")))
    return SafePlan(
        operation=obj["operation"],
        group_by=list(obj.get("group_by", []) or []),
        metrics=metrics,
        filters=list(obj.get("filters", []) or []),
        include_count=bool(obj.get("include_count", True)),
        limit=int(obj.get("limit", 50)),
        sort_by=obj.get("sort_by"),
        ascending=bool(obj.get("ascending", False)),
    )


# --- validation (before any execution) --------------------------------------

def validate_safeplan(plan: SafePlan, df, policy: Policy) -> None:
    df = _as_pandas(df)
    cols = set(df.columns)

    if plan.operation in BLOCKED_OPERATIONS:
        raise SafetyError(
            f"Blocked: operation '{plan.operation}' (raw row access/export) is "
            f"not allowed in SafePlan mode.")
    if plan.operation not in ALLOWED_OPERATIONS:
        raise SafetyError(
            f"Blocked: operation '{plan.operation}' is not allowed. Use one of "
            f"{sorted(ALLOWED_OPERATIONS)}.")
    if plan.limit > policy.max_result_rows:
        raise SafetyError(
            f"Blocked: limit {plan.limit} exceeds max_result_rows "
            f"{policy.max_result_rows}.")
    for col in plan.group_by:
        if col not in cols:
            raise SafetyError(f"Blocked: group_by column '{col}' does not exist.")
    for m in plan.metrics:
        if m.column not in cols:
            raise SafetyError(f"Blocked: metric column '{m.column}' does not exist.")
        if m.agg not in ALLOWED_AGGS:
            raise SafetyError(f"Blocked: aggregation '{m.agg}' is not allowed.")
    for f in plan.filters:
        if not isinstance(f, dict) or set(f.keys()) - {"column", "op", "value"}:
            raise SafetyError("Blocked: each filter must have only column/op/value.")
        if f.get("column") not in cols:
            raise SafetyError(f"Blocked: filter column '{f.get('column')}' does not exist.")
        if f.get("op") not in ALLOWED_FILTER_OPS:
            raise SafetyError(f"Blocked: filter operator '{f.get('op')}' is not allowed.")


# --- execution (boring and controlled - no eval/exec/generated code) --------

def _enforce_min_rows(df, policy, operation):
    """k-anonymity for whole-frame results (aggregate/describe). The groupby and
    value_counts paths enforce min_group_size per group via a count column, but a
    plain aggregate or describe runs over the filtered subset as a single group,
    so a narrow filter could otherwise expose one individual's exact value."""
    k = getattr(policy, "min_group_size", 0) or 0
    if k and len(df) < k:
        raise SafetyError(
            f"Blocked: '{operation}' covers only {len(df)} record(s), below the "
            f"min_group_size of {k}. Broaden the filters or group the result.")


def _apply_filters(df, filters):
    out = df
    ops = {"==": lambda s, v: s == v, "!=": lambda s, v: s != v,
           ">": lambda s, v: s > v, ">=": lambda s, v: s >= v,
           "<": lambda s, v: s < v, "<=": lambda s, v: s <= v}
    for f in filters:
        col, op, value = f["column"], f["op"], f["value"]
        if op == "in":
            if not isinstance(value, list):
                raise SafetyError("Blocked: 'in' filter value must be a list.")
            out = out[out[col].isin(value)]
        else:
            out = out[ops[op](out[col], value)]
    return out


def execute_safeplan(plan: SafePlan, df, policy: Policy):
    """Validate then run the plan on `df` with our own engine. Returns the
    answer (privacy rules applied). Raises SafetyError if the plan is unsafe."""
    df = _as_pandas(df)
    validate_safeplan(plan, df, policy)
    df = _apply_filters(df, plan.filters)
    limit = min(plan.limit, policy.max_result_rows)

    if plan.operation == "count_rows":
        result = {"count": int(len(df))}
        return _post(result, policy)

    if plan.operation == "aggregate":
        if not plan.metrics:
            raise SafetyError("Blocked: aggregate requires at least one metric.")
        _enforce_min_rows(df, policy, plan.operation)
        result = {}
        for m in plan.metrics:
            name = m.as_name or f"{m.agg}_{m.column}"
            result[name] = getattr(df[m.column], m.agg)()
        return _post(result, policy)

    if plan.operation == "value_counts":
        if len(plan.group_by) != 1:
            raise SafetyError("value_counts requires exactly one group_by column.")
        col = plan.group_by[0]
        result = df[col].value_counts(dropna=False).reset_index()
        result.columns = [col, "count"]
        if policy.min_group_size:
            result = result[result["count"] >= policy.min_group_size]
        return _post(result.head(limit), policy)

    if plan.operation == "describe":
        _enforce_min_rows(df, policy, plan.operation)
        numeric = df.select_dtypes(include="number")
        return _post(numeric.describe().T.head(limit).reset_index(), policy)

    if plan.operation == "groupby_aggregate":
        if not plan.group_by:
            raise SafetyError("Blocked: groupby_aggregate requires group_by.")
        if not plan.metrics:
            raise SafetyError("Blocked: groupby_aggregate requires at least one metric.")
        agg_spec = {}
        for m in plan.metrics:
            out_name = m.as_name or f"{m.agg}_{m.column}"
            agg_spec[out_name] = (m.column, m.agg)
        # Always include a per-group count so k-anonymity can be enforced.
        agg_spec["count"] = (plan.metrics[0].column, "size")
        result = df.groupby(plan.group_by, dropna=False).agg(**agg_spec).reset_index()
        if policy.min_group_size:
            result = result[result["count"] >= policy.min_group_size]
        if not plan.include_count:
            result = result.drop(columns=["count"])
        if plan.sort_by and plan.sort_by in result.columns:
            result = result.sort_values(plan.sort_by, ascending=plan.ascending)
        return _post(result.head(limit), policy)

    raise SafetyError(f"Unsupported operation: {plan.operation}")


def _post(result, policy):
    """Apply result-level privacy (redaction) after execution."""
    if policy.redact_result_pii:
        return _redact_result(result)
    return result


# --- prompt + public entry point --------------------------------------------

def _shadow_summary(safe_df, rows=8):
    """Schema + a synthetic sample (no real cell values) for the prompt."""
    from .shadowframe import create_shadowframe
    shadow = create_shadowframe(safe_df, rows=rows)
    cols = ", ".join(f"{c} ({t['dtype']}, {t['kind']})"
                     for c, t in shadow.profile["columns"].items())
    sample = shadow.shadow_df.to_string(index=False, max_rows=rows)
    return (f"COLUMNS: {cols}\n"
            f"ROWS (real): {shadow.profile['rows']}\n"
            f"SYNTHETIC SAMPLE (fake values, real values withheld):\n{sample}")


def build_safeplan_prompt(safe_df, question, policy, previous_error=None,
                          use_shadow=True):
    if use_shadow:
        summary = _shadow_summary(safe_df)
    else:
        summary = summarize(safe_df, mask_pii=True)
    parts = [
        "You convert a question into a STRICT JSON analysis plan. You do NOT "
        "write Python. Return ONLY a single JSON object, no prose, no code "
        "fences.",
        "Schema:",
        '{ "operation": one of '
        '["aggregate","groupby_aggregate","count_rows","value_counts","describe"],',
        '  "group_by": [column names],',
        '  "metrics": [{"column": name, "agg": one of '
        '["sum","mean","median","min","max","count","nunique","std"], '
        '"as_name": optional}],',
        '  "filters": [{"column": name, "op": one of '
        '["==","!=",">",">=","<","<=","in"], "value": literal}],',
        f'  "include_count": true, "limit": <= {policy.max_result_rows}, '
        '"sort_by": optional column, "ascending": true/false }',
        "Rules: use only the columns in the summary; do not request raw rows or "
        "exports; prefer an aggregate. For a 'top N' / 'highest' / 'largest' "
        "(or 'bottom' / 'lowest') question, set sort_by to the metric's as_name, "
        "ascending=false (true for bottom/lowest), and limit=N.",
        "",
        f"QUESTION: {question}",
        "",
        f"DATA SUMMARY:\n{summary}",
    ]
    if previous_error:
        parts += ["", "YOUR LAST PLAN WAS REJECTED:", previous_error,
                  "Return a corrected JSON plan."]
    return "\n".join(parts)


def safe_query(df, question, model=None, policy=None, max_retries: int = 3,
               use_shadow: bool = True):
    """Answer `question` by having the model emit a JSON SafePlan that safedata
    executes locally (no generated Python). Returns a SafePlanResult with the
    answer, the plan, and a Data Safety Receipt.

    If `model` is None, returns the privacy plan/receipt without executing (a
    dry run). A bad/unsafe plan is fed back to the model and retried; it never
    raises a SafetyError out of this function (the result carries blocked/reason).
    """
    policy = policy or Policy.regulated()
    privacy_plan = create_privacy_plan(
        df, question, safe_mode=policy.safe_mode, scan_rows=policy.pii_scan_rows,
        max_result_rows=policy.max_result_rows, use_presidio=policy.use_presidio)
    safe_df = make_safe_view(df, privacy_plan)

    def _receipt(answer, plan):
        return create_receipt(question, "safeplan", privacy_plan, policy,
                              answer=answer, safeplan=plan,
                              generated_python_executed=False)

    if model is None:
        return SafePlanResult(
            answer=None, plan=None, blocked=False, reason=None,
            receipt=_receipt(None, None))

    error, attempts = None, []
    for _ in range(max(1, max_retries)):
        prompt = build_safeplan_prompt(safe_df, question, policy,
                                       previous_error=error, use_shadow=use_shadow)
        raw = model(prompt)
        attempts.append(str(raw)[:500])
        try:
            plan = parse_safeplan(extract_json_plan(raw))
            answer = execute_safeplan(plan, safe_df, policy)
            return SafePlanResult(answer=answer, plan=plan, blocked=False,
                                  reason=None, receipt=_receipt(answer, plan),
                                  attempts=attempts)
        except SafetyError as e:
            error = str(e)
    return SafePlanResult(answer=None, plan=None, blocked=True, reason=error,
                          receipt=_receipt(None, None), attempts=attempts)
