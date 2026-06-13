"""
Data Safety Receipt: a per-answer record of what the analysis exposed.

Every safe_query/safe_answer can produce a receipt: a question id, the execution
mode, whether any generated Python ran, which PII was detected/dropped, the
columns used, the policy in force, and the shape of the answer. It is the audit
trail a regulated team needs to show "this AI answer did not touch raw PII".
"""

from datetime import datetime, timezone
import uuid


def _answer_shape(answer):
    try:
        import pandas as pd
        if isinstance(answer, pd.DataFrame):
            return {"type": "dataframe", "rows": int(len(answer)),
                    "columns": [str(c) for c in answer.columns]}
        if isinstance(answer, pd.Series):
            return {"type": "series", "length": int(len(answer))}
    except Exception:
        pass
    if isinstance(answer, dict):
        return {"type": "dict", "keys": [str(k) for k in answer.keys()]}
    if isinstance(answer, (list, tuple)):
        return {"type": type(answer).__name__, "length": len(answer)}
    return {"type": type(answer).__name__}


def create_receipt(question, mode, privacy_plan, policy, answer=None,
                   safeplan=None, generated_python_executed=False):
    """Build a Data Safety Receipt dict for one answered question."""
    receipt = {
        "audit_id": f"SDG-{uuid.uuid4().hex[:10].upper()}",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "mode": mode,
        "raw_rows_exposed_to_llm": 0 if mode == "safeplan" else "summary_only",
        "generated_python_executed": bool(generated_python_executed),
        "original_risk_level": getattr(privacy_plan, "original_risk_level", None),
        "safe_view_risk_level": getattr(privacy_plan, "safe_view_risk_level", None),
        "pii_columns_detected": list(getattr(privacy_plan, "pii_columns", [])),
        "pii_columns_dropped": list(getattr(privacy_plan, "dropped_pii_columns", [])),
        "columns_allowed": list(getattr(privacy_plan, "allowed_columns", [])),
        "policy": policy.to_dict() if hasattr(policy, "to_dict") else {},
        "min_group_size": getattr(policy, "min_group_size", None),
        "max_result_rows": getattr(policy, "max_result_rows", None),
        "answer_shape": _answer_shape(answer),
    }
    if safeplan is not None:
        receipt["safeplan"] = {
            "operation": safeplan.operation,
            "group_by": list(safeplan.group_by),
            "metrics": [{"column": m.column, "agg": m.agg, "as_name": m.as_name}
                        for m in safeplan.metrics],
            "limit": safeplan.limit,
        }
    return receipt


def format_receipt(receipt: dict) -> str:
    """Human-readable rendering of a receipt."""
    lines = [
        "Data Safety Receipt",
        "-" * 19,
        f"Audit ID: {receipt.get('audit_id')}",
        f"Question: {receipt.get('question')}",
        f"Mode: {receipt.get('mode')}",
        f"Raw rows exposed to LLM: {receipt.get('raw_rows_exposed_to_llm')}",
        f"Generated Python executed: {receipt.get('generated_python_executed')}",
        f"PII detected: {receipt.get('pii_columns_detected')}",
        f"PII dropped: {receipt.get('pii_columns_dropped')}",
        f"Allowed columns: {receipt.get('columns_allowed')}",
        f"Min group size: {receipt.get('min_group_size')}",
        f"Answer shape: {receipt.get('answer_shape')}",
    ]
    return "\n".join(lines)
