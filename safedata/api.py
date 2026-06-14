"""
The public front door: ask / scan / protect.

    import safedata as sd
    result = sd.ask(df, "total revenue by region", model=my_model, profile="banking")
    report = sd.scan(df, profile="banking")
    safe_df = sd.protect(df, question="total revenue by region", profile="banking")

These wrap the internal engine (SafePlan, the privacy firewall, the guarded
Python runner) so a caller never has to choose between them. SafePlan is the
default engine; guarded Python is only used when the policy allows it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Tuple, Union

from .policy import Policy
from .results import Result, ScanReport, Receipt, ProtectReport
from .exceptions import (DataValidationError, ModelAdapterError,
                         UnsafeRequestError, PolicyError)
from .analysis import (_as_pandas, privacy_report, ai_risk_score, validate)


# --- shared helpers ---------------------------------------------------------

def _resolve_policy(profile: str, policy: Optional[Policy]) -> Policy:
    if policy is not None:
        return policy
    return Policy.from_profile(profile)


def _as_prompt_fn(model):
    """Accept a plain callable OR an object exposing .generate(prompt)."""
    if model is None:
        return None
    if callable(model):
        return model
    gen = getattr(model, "generate", None)
    if callable(gen):
        return gen
    raise ModelAdapterError(
        "model must be a callable (prompt -> text) or expose a .generate(prompt) "
        "method.")


def _require_df(df):
    pdf = _as_pandas(df)
    if pdf is None or len(pdf.columns) == 0:
        raise DataValidationError("A non-empty DataFrame is required.")
    return pdf


# Light keyword classifier for scan/protect. Phase 3 deepens this; it is honest
# about being best-effort, keyword-based detection.
_BUSINESS_ID = ("customer_id", "account_id", "account_number", "policy_number",
                "policy_id", "claim_id", "claim_number", "sort_code", "iban",
                "mpan", "mprn", "meter_id", "meter_number", "contract_id",
                "case_id", "invoice_id", "txn_id", "order_id", "nhs_number")
_FINANCIAL = ("balance", "salary", "income", "credit_score", "debt", "arrears",
              "amount", "revenue", "arr", "sort_code", "iban", "loan",
              "payment", "price")
_HEALTH = ("diagnosis", "condition", "medication", "treatment", "nhs_number",
           "department", "icd", "symptom")
_LOCATION = ("postcode", "post_code", "zip", "zipcode", "city", "address",
             "region", "country", "lat", "lon", "longitude", "latitude")
_FREE_TEXT = ("notes", "note", "comment", "comments", "complaint", "description",
              "feedback", "message", "remarks", "case_description")


def _is_stringlike(series) -> bool:
    import pandas as pd
    dt = series.dtype
    return (pd.api.types.is_string_dtype(series)
            or pd.api.types.is_object_dtype(series)) and not \
        pd.api.types.is_numeric_dtype(dt)


def _classify_columns(df, pii_cols) -> dict:
    cats = {"business_identifier": [], "financial": [], "health": [],
            "location": [], "free_text": []}
    pii = set(pii_cols)
    for col in df.columns:
        name = str(col).lower()
        if any(tok in name for tok in _BUSINESS_ID):
            cats["business_identifier"].append(col)
        if any(tok in name for tok in _FINANCIAL):
            cats["financial"].append(col)
        if any(tok in name for tok in _HEALTH):
            cats["health"].append(col)
        if any(tok in name for tok in _LOCATION):
            cats["location"].append(col)
        # free text: string-like column named like prose, not already PII
        if (col not in pii and any(tok in name for tok in _FREE_TEXT)
                and _is_stringlike(df[col])):
            cats["free_text"].append(col)
    return cats


# --- scan -------------------------------------------------------------------

def scan(df, profile: str = "general", policy: Optional[Policy] = None,
         deep: bool = True) -> ScanReport:
    """Assess a DataFrame's privacy risk, sensitive-column categories, data
    quality, and AI-readiness. Read-only; returns a ScanReport."""
    pdf = _require_df(df)
    policy = _resolve_policy(profile, policy)
    scan_rows = "all" if deep else policy.pii_scan_rows

    risk = ai_risk_score(pdf, scan_rows=scan_rows, use_presidio=policy.use_presidio)
    pii_cols = list(risk["pii_columns"])
    cats = _classify_columns(pdf, pii_cols)

    issues = [{"rule_id": i.rule_id, "severity": i.severity,
               "column": i.column, "message": i.message} for i in validate(pdf)]
    sensitive = sorted(set(cats["business_identifier"] + cats["financial"]
                           + cats["health"] + cats["free_text"]))
    readiness = max(0, 100 - int(risk["score"]))

    return ScanReport(
        rows=int(len(pdf)), columns=int(len(pdf.columns)),
        risk_level=risk["risk_level"],
        pii_columns=pii_cols,
        sensitive_columns=sensitive,
        business_identifier_columns=cats["business_identifier"],
        financial_columns=cats["financial"],
        health_columns=cats["health"],
        location_columns=cats["location"],
        free_text_columns=cats["free_text"],
        quality_issues=issues,
        ai_readiness_score=readiness,
        recommendations=list(risk["reasons"]))


# --- protect ----------------------------------------------------------------

def protect(df, question: Optional[str] = None, profile: str = "general",
            policy: Optional[Policy] = None, return_report: bool = False
            ) -> Union[Any, Tuple[Any, ProtectReport]]:
    """Return a privacy-filtered view of `df`: unneeded PII / sensitive columns
    dropped, retained sensitive fields masked, analytical columns kept. If
    `question` is given, columns it needs are preserved."""
    from .firewall import create_privacy_plan, make_safe_view
    pdf = _require_df(df)
    policy = _resolve_policy(profile, policy)
    plan = create_privacy_plan(
        pdf, question or "", safe_mode=policy.safe_mode,
        scan_rows=policy.pii_scan_rows, max_result_rows=policy.max_result_rows,
        use_presidio=policy.use_presidio)
    safe_df = make_safe_view(pdf, plan)

    if not return_report:
        return safe_df
    report = ProtectReport(
        kept_columns=list(getattr(plan, "allowed_columns", list(safe_df.columns))),
        dropped_columns=list(getattr(plan, "dropped_columns", [])),
        masked_columns=list(getattr(plan, "retained_pii_columns", [])))
    return safe_df, report


# --- ask --------------------------------------------------------------------

def _receipt_from(sp_receipt: dict, profile: str, engine: str, mode: str, pdf,
                  python_used: bool, blocked_ops, warnings) -> Receipt:
    return Receipt(
        audit_id=sp_receipt.get("audit_id") or _new_audit_id(),
        timestamp=sp_receipt.get("timestamp_utc") or _now(),
        profile=profile, engine=engine, mode=mode,
        row_count=int(len(pdf)), column_count=int(len(pdf.columns)),
        safe_columns=list(sp_receipt.get("columns_allowed", [])),
        dropped_columns=list(sp_receipt.get("pii_columns_dropped", [])),
        masked_columns=[],
        pii_columns=list(sp_receipt.get("pii_columns_detected", [])),
        sensitive_columns=[],
        min_group_size=sp_receipt.get("min_group_size"),
        max_result_rows=sp_receipt.get("max_result_rows", 50),
        python_fallback_used=python_used,
        raw_rows_exposed=bool(python_used),
        blocked_operations=list(blocked_ops or []),
        warnings=list(warnings or []))


def _suppression_warning(answer, policy):
    """If a k-anonymity policy suppressed every group (empty DataFrame result),
    say so explicitly - an empty answer should never look like 'no data'."""
    try:
        import pandas as pd
        k = getattr(policy, "min_group_size", None)
        if k and isinstance(answer, pd.DataFrame) and len(answer) == 0:
            return [f"All result groups were suppressed by the k-anonymity rule "
                    f"(min_group_size={k}): no group had at least {k} records. "
                    f"Broaden the grouping or lower min_group_size."]
    except Exception:
        pass
    return []


def _now():
    return datetime.now(timezone.utc).isoformat()


def _new_audit_id():
    import uuid
    return f"SDG-{uuid.uuid4().hex[:10].upper()}"


def ask(df, question: str, model=None, profile: str = "general",
        policy: Optional[Policy] = None, mode: str = "auto",
        explain: bool = True) -> Result:
    """Answer `question` over `df` safely and return a Result with an audit
    Receipt. SafePlan is used by default; guarded Python only if the policy
    allows it (mode='python' or an 'auto' fallback)."""
    if not isinstance(question, str) or not question.strip():
        raise DataValidationError("question must be a non-empty string.")
    pdf = _require_df(df)
    policy = _resolve_policy(profile, policy)
    fn = _as_prompt_fn(model)
    if mode not in ("auto", "plan", "summary", "python"):
        raise PolicyError(f"Unknown mode '{mode}'. Use auto/plan/summary/python.")

    # summary mode: explain risk, no data execution.
    if mode == "summary":
        report = scan(pdf, policy=policy)
        rec = Receipt(audit_id=_new_audit_id(), timestamp=_now(),
                      profile=policy.profile, engine="summary", mode="summary",
                      row_count=report.rows, column_count=report.columns,
                      pii_columns=report.pii_columns,
                      sensitive_columns=report.sensitive_columns,
                      min_group_size=policy.min_group_size,
                      max_result_rows=policy.max_result_rows)
        return Result(answer=report.recommendations, data=report, receipt=rec,
                      engine="summary")

    if mode == "python" and not policy.allow_python_fallback:
        raise UnsafeRequestError(
            f"Guarded-Python mode is disabled for profile '{policy.profile}'. "
            f"Set allow_python_fallback=True on the policy to enable it.")

    # SafePlan first (the default, safest engine).
    if mode in ("auto", "plan"):
        from .safeplan import safe_query
        sp = safe_query(pdf, question, model=fn, policy=policy)
        if not sp.blocked or mode == "plan" or not policy.allow_python_fallback:
            warnings = _suppression_warning(sp.answer, policy)
            rec = _receipt_from(sp.receipt, policy.profile, "safeplan", mode,
                                pdf, python_used=False,
                                blocked_ops=([sp.reason] if sp.blocked else []),
                                warnings=warnings)
            return Result(answer=sp.answer, data=sp.answer, receipt=rec,
                          engine="safeplan", blocked=sp.blocked, reason=sp.reason,
                          warnings=warnings)
        # auto + fallback allowed + SafePlan blocked -> guarded Python.

    # Guarded Python engine.
    from .firewall import safe_answer
    out = safe_answer(pdf, question, model=fn, policy=policy)
    base_receipt = {"min_group_size": policy.min_group_size,
                    "max_result_rows": policy.max_result_rows}
    rec = _receipt_from(base_receipt, policy.profile, "guarded_python", mode,
                        pdf, python_used=not out.get("blocked"),
                        blocked_ops=([out.get("reason")] if out.get("blocked") else []),
                        warnings=[])
    return Result(answer=out.get("answer"), data=out.get("answer"), receipt=rec,
                  engine="guarded_python", blocked=bool(out.get("blocked")),
                  reason=out.get("reason"))
