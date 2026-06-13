"""
QUERY-AWARE PRIVACY FIREWALL.

Instead of asking "does this DataFrame contain PII?", this asks the stronger
question: "what is the minimum safe data needed to answer THIS question?" - then
builds a privacy-filtered view of the data, runs the analysis only on that view,
and returns an audit explaining what was dropped and why.

It is a thin orchestration layer over the existing pieces (privacy_report,
infer_columns, create_contract, run_safely), not a rewrite.

SAFE BY DESIGN - the default never drops analytical columns:
  - safe_mode="drop_unneeded_pii" (DEFAULT): remove the PII columns the question
    doesn't need; KEEP every non-PII column. This can't cause a wrong answer,
    because the columns analysis needs are always present - only unneeded
    sensitive data is removed.
  - safe_mode="minimal" (OPT-IN, ADVANCED): also drop non-PII columns the
    question doesn't appear to reference. Stronger minimisation, but column
    relevance is a heuristic, so it CAN drop a column the analysis needed and
    produce a wrong/failed answer. Use only when you know your data.

Deliberately NOT included yet (they need careful design + tests before they can
be trusted): private surrogate filters (customer_name -> match flag) and
k-anonymity / minimum-group-size suppression.
"""

from dataclasses import dataclass, field, asdict

from .analysis import (privacy_report, infer_columns, ai_risk_score,
                       _question_mentions_column, _as_pandas)
from .bodyguard import run_safely, SafetyError
from .translator import summarize
from .wrap import extract_code, ModelError


_AGGREGATE_WORDS = ("total", "sum", "average", "avg", "mean", "count", "median",
                    "min", "max", "minimum", "maximum", "by", "per")
_RANKING_WORDS = ("top", "bottom", "highest", "lowest", "largest", "smallest",
                  "rank")
_TREND_WORDS = ("trend", "over time", "monthly", "weekly", "daily", "yearly",
                "quarterly", "year over year")
_RAW_WORDS = ("show all", "list all", "give me all", "every row", "all records",
              "all customers", "export", "download", "raw data", "full data")


def detect_operation(question: str) -> str:
    """Coarse intent of a question: raw_lookup | ranking | trend | aggregate |
    general_analysis. Heuristic; used to shape the result policy and audit."""
    q = str(question).lower()
    if any(w in q for w in _RAW_WORDS):
        return "raw_lookup"
    if any(w in q for w in _RANKING_WORDS):
        return "ranking"
    if any(w in q for w in _TREND_WORDS):
        return "trend"
    if any(w in q for w in _AGGREGATE_WORDS):
        return "aggregate"
    return "general_analysis"


@dataclass
class PrivacyPlan:
    """A declarative plan for answering `question` over `df` with least data."""
    question: str
    safe_mode: str
    operation: str
    allowed_columns: list
    dropped_columns: list          # columns removed from the view
    pii_columns: list
    dropped_pii_columns: list      # the subset of dropped that were PII
    retained_pii_columns: list     # PII the question needs (kept, but redacted)
    original_risk_level: str       # risk of the RAW dataframe
    safe_view_risk_level: str      # risk of the privacy-filtered view (what's exposed)
    risk_level: str                # == original_risk_level (kept for clarity)
    result_policy: dict
    audit: str
    reason: str
    warnings: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def create_privacy_plan(df, question: str,
                        safe_mode: str = "drop_unneeded_pii",
                        scan_rows=20, max_result_rows: int = 50) -> PrivacyPlan:
    """Decide the minimum safe set of columns to answer `question`.

    safe_mode:
      "drop_unneeded_pii" (default) - drop PII columns the question doesn't
          mention; keep ALL non-PII columns. No correctness risk.
      "minimal" - also drop non-PII columns not mentioned by the question.
          Stronger, but relevance is heuristic and can drop a needed column.
    """
    if safe_mode not in ("drop_unneeded_pii", "minimal"):
        raise ValueError(
            f"safe_mode must be 'drop_unneeded_pii' or 'minimal', got "
            f"{safe_mode!r}.")

    pdf = _as_pandas(df)
    cols = list(pdf.columns)
    pii_cols = list(privacy_report(pdf, scan_rows=scan_rows)["pii_columns"])
    operation = detect_operation(question)
    warnings = []

    mentioned = {c for c in cols if _question_mentions_column(question, c)}
    pii_set = set(pii_cols)
    retained_pii = sorted(c for c in pii_cols if c in mentioned)
    dropped_pii = sorted(c for c in pii_cols if c not in mentioned)

    if safe_mode == "drop_unneeded_pii":
        # Keep every non-PII column; drop only the unneeded PII. Safe.
        allowed = [c for c in cols if c not in set(dropped_pii)]
        reason = ("Dropped PII columns the question doesn't need; kept all "
                  "non-PII (analytical) columns so the answer stays correct.")
    else:  # "minimal"
        needed = set(mentioned)
        # Always keep non-PII columns the question names; if nothing matched,
        # fall back to all non-PII so we never ship an empty/over-stripped view.
        if not (needed - pii_set):
            needed |= {c for c in cols if c not in pii_set}
            warnings.append(
                "minimal mode: no analytical columns matched the question by "
                "name; kept all non-PII columns as a safe fallback.")
        allowed = [c for c in cols if c in needed]
        warnings.append(
            "minimal mode drops non-PII columns by heuristic name-matching; if a "
            "needed column was missed the answer may be wrong. Verify, or use "
            "the default safe_mode='drop_unneeded_pii'.")
        reason = ("Kept only columns the question appears to reference (advanced "
                  "minimal mode); all others dropped.")

    dropped = [c for c in cols if c not in set(allowed)]

    # Risk of the RAW frame vs the privacy-filtered view actually exposed. The
    # raw risk can read "high" while the safe view is "low" because the PII was
    # dropped before anything reaches the model; surface both so that isn't
    # mistaken for the firewall not working.
    original_risk = ai_risk_score(pdf, question, scan_rows=scan_rows)["risk_level"]
    try:
        safe_view_risk = ai_risk_score(
            pdf[allowed], question, scan_rows=scan_rows)["risk_level"]
    except Exception:
        safe_view_risk = original_risk
    result_policy = {
        "max_result_rows": max_result_rows,
        "max_result_bytes": 1_000_000,
        "redact_result_pii": True,
        # aggregate/ranking/trend questions should not return every row
        "enforce_minimal_result": operation in ("aggregate", "ranking", "trend"),
    }

    audit = _build_audit(question, operation, allowed, dropped_pii,
                         retained_pii, [c for c in dropped if c not in pii_set])

    return PrivacyPlan(
        question=question, safe_mode=safe_mode, operation=operation,
        allowed_columns=allowed, dropped_columns=dropped, pii_columns=pii_cols,
        dropped_pii_columns=dropped_pii, retained_pii_columns=retained_pii,
        original_risk_level=original_risk, safe_view_risk_level=safe_view_risk,
        risk_level=original_risk, result_policy=result_policy,
        audit=audit, reason=reason, warnings=warnings)


def _build_audit(question, operation, allowed, dropped_pii, retained_pii,
                 dropped_nonpii):
    parts = [f"Question classified as '{operation}'."]
    if dropped_pii:
        parts.append(f"Dropped {len(dropped_pii)} unneeded PII column(s) "
                     f"({', '.join(dropped_pii)}) - never sent to the model.")
    else:
        parts.append("No unneeded PII columns to drop.")
    if retained_pii:
        parts.append(f"Kept {len(retained_pii)} PII column(s) the question "
                     f"needs ({', '.join(retained_pii)}); masked in the prompt "
                     f"and redacted from the result.")
    if dropped_nonpii:
        parts.append(f"Also dropped {len(dropped_nonpii)} non-PII column(s) "
                     f"({', '.join(dropped_nonpii)}) - advanced 'minimal' mode; "
                     f"verify the answer didn't need them.")
    parts.append(f"Retained {len(allowed)} column(s) for analysis: "
                 f"{', '.join(allowed)}.")
    return " ".join(parts)


def make_safe_view(df, plan: PrivacyPlan):
    """Return a copy of `df` with only the plan's allowed columns.

    The values the analysis doesn't need are simply not present - stronger than
    masking, since no access path (positional, .values, .to_numpy()) can reach
    them. Retained PII columns are kept usable for computation; they are masked
    in the prompt (summarize(mask_pii=True)) and scrubbed from the result by
    run_safely(redact_result_pii=True) in safe_answer.
    """
    pdf = _as_pandas(df)
    keep = [c for c in plan.allowed_columns if c in pdf.columns]
    return pdf[keep].copy()


def _build_firewall_prompt(safe_df, question, plan, previous_error=None,
                           min_group_size=None):
    summary = summarize(safe_df, mask_pii=True)
    parts = [
        "You are analysing a privacy-filtered DataFrame named df. It is a safe "
        "view of the original: unneeded PII columns were removed; non-PII "
        "analytical columns may be retained to keep the answer correct.",
        "Rules:",
        "- Use only the columns shown in the summary.",
        "- Prefer an aggregated answer; don't return raw rows unless required.",
        f"- Keep the result small (at most {plan.result_policy['max_result_rows']} "
        "rows); return an aggregate or top-N, not every row.",
        "- Assign the final answer to a variable named `result`. Return ONLY "
        "Python code.",
    ]
    if min_group_size:
        parts.append(
            "- For any grouped/aggregated result, INCLUDE a per-group row count "
            "in a column named 'count' (e.g. df.groupby(k).agg("
            "value=('x','mean'), count=('x','size')).reset_index()). Do NOT "
            "filter or drop groups yourself and do NOT use .query()/.eval(); "
            "return ALL groups with their counts. Small groups are removed "
            "automatically afterwards.")
    parts += [
        "",
        f"QUESTION: {question}",
        "",
        f"DATA SUMMARY:\n{summary}",
    ]
    if previous_error:
        parts += ["", "YOUR LAST ATTEMPT WAS BLOCKED:", previous_error,
                  "Rewrite the code to fix this."]
    return "\n".join(parts)


def safe_answer(df, question, model=None, code=None,
                safe_mode: str = "drop_unneeded_pii", scan_rows=20,
                isolation: str = "process", timeout: float = 10.0,
                max_retries: int = 3, min_group_size=None):
    """Answer `question` over `df` using the minimum safe data.

    Builds a privacy plan, creates the safe view, has `model` write code against
    that view (or runs the `code` you pass), executes it under the guardrails,
    and returns the answer plus the plan/audit. If neither `model` nor `code` is
    given, returns the plan only (a dry run).

    Self-correcting: if generated code is blocked by a guardrail (e.g. too many
    rows), the error is fed back to the model and it retries up to `max_retries`
    times - like Agent.ask. A guardrail block NEVER raises out of this function;
    instead the result has ``blocked=True`` and a ``reason``. (A model failure
    still raises ModelError.)

    model : callable (prompt:str) -> code/text. Output is run through
        extract_code, so a raw LLM reply with ```fences``` is fine.
    """
    plan = create_privacy_plan(df, question, safe_mode=safe_mode,
                               scan_rows=scan_rows)
    safe_df = make_safe_view(df, plan)
    pol = plan.result_policy

    out = {
        "question": question,
        "plan": plan.to_dict(),
        "audit": plan.audit,
        "safe_dataframe_columns": list(safe_df.columns),
        "answer": None,
        "code": code,
        "blocked": False,
        "reason": None,
        "attempts": [],
    }

    if code is None and model is None:
        out["message"] = ("Privacy plan created (dry run). Pass model= or code= "
                          "to execute on the safe view.")
        return out

    def _run(c):
        return run_safely(
            c, safe_df, isolation=isolation, timeout=timeout,
            max_result_rows=pol["max_result_rows"],
            max_result_bytes=pol["max_result_bytes"],
            redact_result_pii=pol["redact_result_pii"],
            enforce_minimal_result=pol["enforce_minimal_result"],
            min_group_size=min_group_size)

    # Code supplied directly: run once, but return a structured block (don't raise).
    if model is None:
        out["attempts"].append(code)
        try:
            out["answer"] = _run(code)
        except SafetyError as e:
            out["blocked"], out["reason"] = True, str(e)
        return out

    # Model present: generate, run, and self-correct on a guardrail block.
    error = None
    for _ in range(max(1, max_retries)):
        prompt = _build_firewall_prompt(safe_df, question, plan,
                                        previous_error=error,
                                        min_group_size=min_group_size)
        try:
            code = extract_code(model(prompt))
        except ModelError:
            raise
        except Exception as e:
            raise ModelError(f"The model call failed: {type(e).__name__}: {e}.")
        out["attempts"].append(code)
        out["code"] = code
        try:
            out["answer"] = _run(code)
            return out
        except SafetyError as e:
            error = str(e)
    out["blocked"], out["reason"] = True, error
    return out
