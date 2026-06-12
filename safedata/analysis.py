"""
STRUCTURED DATA-QUALITY ANALYSIS (additive, read-only layer).

The translator and the HTML report produce human-readable warnings; this module
exposes the SAME findings as structured objects you can act on programmatically:
a rule id, a severity, a confidence, the offending column, a few evidence
values, and a suggested fix (often as ready-to-run code).

Everything here is additive and read-only. It never mutates your DataFrame and
never executes code. It reuses the translator's detection helpers so its verdicts
stay consistent with summarize()/report().

Public surface
--------------
    validate(df)            -> list[Issue]
    suggest_fixes(df)       -> list[dict]   (issues that carry runnable code)
    explain_issue(issue)    -> str
    quality_score(df)       -> dict
    ai_readiness(df)        -> dict
    privacy_report(df)      -> dict
    infer_columns(df)       -> dict
    build_safe_prompt(df, question, privacy="mask") -> str
"""

import pandas as pd

from . import pii as _pii
from .translator import (
    summarize, dedupe_columns, _looks_numeric, _looks_like_date,
    _normalize_cat, _name_hints_date, _name_hints_nonnegative, _name_tokens,
    EXCEL_DATE_RANGE, HIGH_MISSING_THRESHOLD, NEG_TOLERANCE, _fmt_missing,
)

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
# A high-cardinality object column carries little signal for an AI summary.
HIGH_CARDINALITY_RATIO = 0.9


class Issue:
    """One structured data-quality finding.

    Attributes
    ----------
    rule_id : str        stable identifier, e.g. "TEXT_NUMERIC"
    severity : str        "low" | "medium" | "high"
    confidence : float    0..1, how sure the heuristic is
    column : str          the column the issue is about (or None / a name list)
    message : str         human-readable description
    evidence : list       a few sample values that triggered it
    suggestion : str      plain-language recommended action
    suggested_code : str  ready-to-run pandas fix, or None if not auto-fixable

    Supports both attribute access (issue.severity) and dict-style access
    (issue["severity"]) so it is convenient from either style of code.
    """

    __slots__ = ("rule_id", "severity", "confidence", "column", "message",
                 "evidence", "suggestion", "suggested_code")

    def __init__(self, rule_id, severity, confidence, column, message,
                 evidence=None, suggestion=None, suggested_code=None):
        self.rule_id = rule_id
        self.severity = severity
        self.confidence = round(float(confidence), 2)
        self.column = column
        self.message = message
        self.evidence = list(evidence) if evidence else []
        self.suggestion = suggestion
        self.suggested_code = suggested_code

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "suggestion": self.suggestion,
            "suggested_code": self.suggested_code,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __repr__(self):
        return (f"Issue({self.rule_id}, severity={self.severity!r}, "
                f"column={self.column!r}, confidence={self.confidence})")


def _as_pandas(df):
    """Return a pandas view of df (convert polars if needed).

    Uses a pyarrow-free conversion (via dict) so it works even when pyarrow,
    which polars' own to_pandas() requires, is not installed.
    """
    if isinstance(df, pd.DataFrame):
        return df
    try:
        import polars as pl
    except Exception:
        pl = None
    if pl is not None and isinstance(df, pl.DataFrame):
        try:
            return df.to_pandas()
        except Exception:
            # to_pandas() needs pyarrow; fall back to a dict round-trip
            return pd.DataFrame(df.to_dict(as_series=False))
    raise TypeError(
        f"expected a pandas or polars DataFrame, got {type(df).__name__}")


def _samples(series, k=3):
    return [str(v) for v in series.dropna().astype(str).unique()[:k]]


# --- explanations for explain_issue() ---------------------------------------
_EXPLANATIONS = {
    "TEXT_NUMERIC": (
        "This column looks numeric but is stored as text (e.g. '$1,200'). Maths, "
        "sorting and aggregation will be wrong or fail until it is converted."),
    "DATE_AS_TEXT": (
        "These look like dates stored as plain text. String comparison will not "
        "order them correctly; convert to a real datetime first."),
    "EXCEL_SERIAL_DATE": (
        "This is an Excel serial date (a number like 45292) rather than a real "
        "date. Convert it before doing any date maths."),
    "MESSY_CATEGORY": (
        "The same category is written several ways (e.g. 'North' vs 'north '). "
        "Grouping will split what should be one category."),
    "CONSTANT_COLUMN": (
        "Every row holds the same value, so this column carries no information "
        "for grouping, filtering or comparison."),
    "NON_UNIQUE_ID": (
        "This column looks like an identifier but repeats, so you cannot assume "
        "one row per value."),
    "EMPTY_COLUMN": (
        "This column is entirely empty and carries no data; exclude it."),
    "HIGH_MISSING": (
        "Most of this column is missing, so averages and counts reflect only a "
        "small minority of rows."),
    "UNEXPECTED_NEGATIVE": (
        "This column contains negative values though its name implies it should "
        "not. Verify they are real and not data-entry errors."),
    "DUPLICATE_COLUMNS": (
        "Two or more columns share a name. This breaks per-column access and is "
        "usually a messy import; give each column a unique name."),
    "HIGH_CARDINALITY": (
        "Almost every value is unique (e.g. free text or an id). It adds little "
        "signal to an AI summary and inflates token cost."),
    "PII": (
        "This column contains personal data (emails, phones, etc.). Mask or drop "
        "it before sending anything to a third-party model."),
}


def explain_issue(issue) -> str:
    """Return a plain-language explanation for an Issue (or issue dict / rule id)."""
    if isinstance(issue, Issue):
        rule_id, suggestion = issue.rule_id, issue.suggestion
    elif isinstance(issue, dict):
        rule_id, suggestion = issue.get("rule_id"), issue.get("suggestion")
    else:
        rule_id, suggestion = str(issue), None
    base = _EXPLANATIONS.get(rule_id, "No explanation available for this issue.")
    if suggestion:
        return f"{base} Suggested fix: {suggestion}"
    return base


# --- the core: validate() ----------------------------------------------------

def validate(df) -> list:
    """Return a list of structured Issue objects for `df`.

    Read-only. Reuses the same heuristics as the text summary, so findings agree
    with summarize()/report(), but returns them in a machine-usable shape.
    """
    df = _as_pandas(df)
    df, dup_names = dedupe_columns(df)
    n = len(df)
    issues = []

    if dup_names:
        for name in dup_names:
            issues.append(Issue(
                "DUPLICATE_COLUMNS", "high", 1.0, name,
                f"Column name '{name}' is duplicated.",
                suggestion="Rename so each column has a unique name."))

    obj_cols = df.select_dtypes(include=["object", "string"]).columns
    for col in obj_cols:
        nn = df[col].dropna().astype(str)
        if not len(nn):
            continue
        num_frac = nn.map(_looks_numeric).mean()
        if num_frac >= 0.7:
            issues.append(Issue(
                "TEXT_NUMERIC", "high", num_frac, col,
                f"Column '{col}' holds numbers stored as text.",
                evidence=_samples(df[col]),
                suggestion="Strip symbols ($ , %) then cast to a numeric type.",
                suggested_code=(
                    f"df[{col!r}] = pd.to_numeric("
                    f"df[{col!r}].astype('string')"
                    f".str.replace(r'[^0-9.\\-]', '', regex=True), "
                    f"errors='coerce')")))
        else:
            date_frac = nn.map(_looks_like_date).mean()
            if date_frac >= 0.9:
                issues.append(Issue(
                    "DATE_AS_TEXT", "medium", date_frac, col,
                    f"Column '{col}' holds dates stored as text.",
                    evidence=_samples(df[col]),
                    suggestion="Convert to datetime before sorting or maths.",
                    suggested_code=(
                        f"df[{col!r}] = pd.to_datetime(df[{col!r}], "
                        f"errors='coerce')")))
        # messy categories
        keys = {}
        for v in nn.unique():
            keys.setdefault(_normalize_cat(v), []).append(v)
        merged = [grp for grp in keys.values() if len(grp) > 1]
        if merged:
            issues.append(Issue(
                "MESSY_CATEGORY", "medium", 0.8, col,
                f"Column '{col}' has the same category written several ways.",
                evidence=list(merged[0])[:4],
                suggestion="Normalize (trim/case) before grouping.",
                suggested_code=(
                    # astype('string'), not str: keeps NaN as <NA> instead of
                    # turning None/NaN into the literal 'none'/'nan'
                    f"df[{col!r}] = df[{col!r}].astype('string').str.strip()"
                    f".str.lower()")))
        # high cardinality
        if n and df[col].nunique(dropna=True) / n >= HIGH_CARDINALITY_RATIO and n > 5:
            issues.append(Issue(
                "HIGH_CARDINALITY", "low", 0.6, col,
                f"Column '{col}' is almost all unique values.",
                evidence=_samples(df[col]),
                suggestion="Consider excluding from an AI summary."))

    # constant columns
    for col in df.columns:
        nn = df[col].dropna()
        if len(nn) > 1 and nn.nunique() == 1:
            issues.append(Issue(
                "CONSTANT_COLUMN", "low", 1.0, col,
                f"Column '{col}' holds the same value in every row.",
                evidence=_samples(df[col], 1),
                suggestion="Drop it; it carries no information."))

    # non-unique IDs
    for col in df.columns:
        name = str(col).lower()
        if name == "id" or name.endswith("_id") or name.endswith("id"):
            nn = df[col].dropna()
            if len(nn) and nn.nunique() < len(nn):
                dup_rate = 1 - nn.nunique() / len(nn)
                issues.append(Issue(
                    "NON_UNIQUE_ID", "medium", min(1.0, 0.5 + dup_rate), col,
                    f"Column '{col}' looks like an ID but is not unique.",
                    suggestion="Do not assume one row per value."))

    # empty / high-missing
    for col in df.columns:
        frac = df[col].isna().mean() if n else 0.0
        if frac >= 1.0 and n > 0:
            issues.append(Issue(
                "EMPTY_COLUMN", "medium", 1.0, col,
                f"Column '{col}' is completely empty.",
                suggestion="Exclude it.",
                suggested_code=f"df = df.drop(columns=[{col!r}])"))
        elif frac >= HIGH_MISSING_THRESHOLD:
            issues.append(Issue(
                "HIGH_MISSING", "medium", frac, col,
                f"Column '{col}' is {_fmt_missing(frac)} missing.",
                suggestion="Consider dropna() before relying on it."))

    # Excel serial dates
    for col in df.select_dtypes(include=["int64", "float64", "int32"]).columns:
        if not _name_hints_date(col):
            continue
        nn = df[col].dropna()
        if len(nn) and nn.between(*EXCEL_DATE_RANGE).mean() >= 0.9:
            issues.append(Issue(
                "EXCEL_SERIAL_DATE", "medium", 0.85, col,
                f"Column '{col}' looks like an Excel serial date stored as a "
                f"number.",
                evidence=[str(int(nn.iloc[0]))],
                suggestion="Convert with origin='1899-12-30'.",
                suggested_code=(
                    f"df[{col!r}] = pd.to_datetime(df[{col!r}], unit='D', "
                    f"origin='1899-12-30')")))

    # unexpected negatives
    for col in df.select_dtypes(include=["int64", "float64"]).columns:
        nn = df[col].dropna()
        if len(nn) < 2 or not _name_hints_nonnegative(col):
            continue
        scale = max(abs(nn.max()), abs(nn.min()))
        threshold = max(scale * 1e-3, NEG_TOLERANCE)
        if (nn < -threshold).any():
            issues.append(Issue(
                "UNEXPECTED_NEGATIVE", "medium", 0.7, col,
                f"Column '{col}' contains negative values though its name "
                f"implies it should not (min={nn.min():.2f}).",
                suggestion="Verify these are real, not data errors."))

    # PII: value matches are high confidence; name-only hints are a softer
    # "review this" signal (medium), so we don't over-flag e.g. 'Customer Name'
    # as strongly as a column whose cells actually contain emails.
    for col, info in _all_pii(df).items():
        kinds = ", ".join(info["kinds"])
        if info["by"] == "value":
            issues.append(Issue(
                "PII", "high", 0.9, col,
                f"Column '{col}' contains likely PII ({kinds}).",
                suggestion="Mask or drop before sending to a model."))
        else:
            issues.append(Issue(
                "PII", "medium", 0.55, col,
                f"Column '{col}' name suggests personal data ({kinds}); review.",
                suggestion="Confirm contents; mask or drop if personal."))

    return issues


def suggest_fixes(df) -> list:
    """Return just the issues that carry runnable fix code, as plain dicts.

        [{"issue": ..., "column": ..., "suggested_code": ...}, ...]
    """
    out = []
    for iss in validate(df):
        if iss.suggested_code:
            out.append({
                "issue": iss.message,
                "rule_id": iss.rule_id,
                "column": iss.column,
                "suggested_code": iss.suggested_code,
            })
    return out


# --- PII / privacy -----------------------------------------------------------

# Person-context tokens. The bare token "name" is ambiguous ("Product Name",
# "Team Name" are NOT personal data), so we only treat "name" as PII when one of
# these also appears, or when the column is literally "name"/"names".
_PERSON_CONTEXT = {
    "first", "last", "sur", "surname", "full", "fore", "middle", "maiden",
    "given", "family", "contact", "person", "people", "customer", "client",
    "employee", "user", "holder", "patient", "member", "applicant",
    "policyholder", "driver",
}
# "high sensitivity" kinds escalate to high risk even when only the NAME hints it
_HIGH_RISK_KINDS = {"email", "phone", "national_id", "date_of_birth", "address"}


def _pii_name_hints(df) -> dict:
    """Return {column: kind} for columns whose NAME (token-matched) implies PII.

    Token matching, not substring: 'cover_noofnameddrivers' tokenises without a
    'name' token, so it is not flagged; 'Product Name' has 'name' but no
    person-context token, so it is not flagged either.
    """
    out = {}
    for col in df.columns:
        toks = _name_tokens(col)
        if not toks:
            continue
        if "email" in toks:
            kind = "email"
        elif toks & {"phone", "mobile", "telephone", "msisdn"}:
            kind = "phone"
        elif toks & {"ssn", "nino", "sin"}:
            kind = "national_id"
        elif "dob" in toks or "birth" in toks:
            kind = "date_of_birth"
        elif toks & {"postcode", "zipcode", "zip"}:
            kind = "postcode"
        elif "address" in toks:
            kind = "address"
        elif "surname" in toks:
            kind = "name"
        elif "name" in toks and (toks & _PERSON_CONTEXT):
            kind = "name"
        elif toks in ({"name"}, {"names"}):
            kind = "name"
        else:
            continue
        out[col] = kind
    return out


# How many unique values per column the value-based PII scan inspects by
# default. Small = fast; a rare PII value past this window can be missed, so
# privacy_report(scan_rows=...) / "all" let callers scan deeper.
_DEFAULT_PII_SCAN = 20


def _all_pii(df, scan_rows=_DEFAULT_PII_SCAN):
    """Merge value-detected PII (high confidence) with name-hinted PII.

    Returns {column: {"kinds": [...], "by": "value"|"name"}}. Value evidence wins
    when a column is detected both ways. `scan_rows` controls how many unique
    values the value scan inspects ("all" or None = every value).
    """
    df = _as_pandas(df)
    merged = {}
    for col, kind in _pii_name_hints(df).items():
        merged[col] = {"kinds": [kind], "by": "name"}
    for col, kinds in _detect_pii_columns(df, scan_rows=scan_rows).items():
        merged[col] = {"kinds": kinds, "by": "value"}
    return merged


def _detect_pii_columns(df, scan_rows=_DEFAULT_PII_SCAN):
    """Return {column: [kinds]} for columns whose VALUES match a PII pattern.

    Each sample value is tested on its own. We must NOT join samples and search
    the blob: consecutive values (e.g. dates '2024-01-15 2024-02-20') can form a
    digit run that spuriously matches the card/phone patterns across the join.
    `scan_rows` is the number of unique values inspected per column ("all"/None
    scans every value, slower but catches rare PII).
    """
    df = _as_pandas(df)
    unlimited = scan_rows in (None, "all")
    hits = {}
    for col in df.select_dtypes(include=["object", "string"]).columns:
        uniques = df[col].dropna().astype(str).unique()
        samples = uniques if unlimited else uniques[:int(scan_rows)]
        kinds = set()
        for label, pattern in _pii._PATTERNS:
            for s in samples:
                if not pattern.search(s):
                    continue
                if label == "PHONE" and not _pii._looks_like_phone(s):
                    continue  # date/time guard: timestamps aren't phones
                kinds.add(label.lower())
                break
        if kinds:
            hits[col] = sorted(kinds)
    return hits


def privacy_report(df, scan_rows=_DEFAULT_PII_SCAN) -> dict:
    """A privacy view: which columns hold PII (by value or by name) and what to do.

    `scan_rows` controls how many unique values per column the value scan checks
    ("all"/None for an exhaustive but slower scan that catches rare PII).
    """
    df = _as_pandas(df)
    high, medium, actions = [], [], []

    for col, info in _all_pii(df, scan_rows=scan_rows).items():
        kinds = info["kinds"]
        if info["by"] == "value":
            high.append({"column": col, "kinds": kinds, "by": "value"})
            actions.append(f"mask or drop '{col}' (contains {', '.join(kinds)})")
        else:
            # name-only hint: high risk only for the sensitive kinds
            bucket = high if set(kinds) & _HIGH_RISK_KINDS else medium
            bucket.append({"column": col, "kinds": kinds, "by": "name"})
            actions.append(f"review '{col}' (name suggests {', '.join(kinds)})")

    pii_columns = sorted({h["column"] for h in high} |
                         {m["column"] for m in medium})
    return {
        "pii_columns": pii_columns,
        "high_risk": high,
        "medium_risk": medium,
        "recommended_action": actions,
        "note": ("best-effort, regex/name heuristics only; not a compliance "
                 "guarantee. See safedata.pii."),
    }


# --- scoring -----------------------------------------------------------------

def _label(score):
    if score >= 85:
        return "Good"
    if score >= 60:
        return "Fair"
    return "Poor"


def _risk_label(score):
    # higher score = lower risk; invert for a risk word
    if score >= 85:
        return "Low"
    if score >= 60:
        return "Medium"
    return "High"


def quality_score(df) -> dict:
    """A 0..100 data-quality score with a per-dimension breakdown."""
    df = _as_pandas(df)
    n, ncols = len(df), df.shape[1]
    issues = validate(df)
    by_rule = {}
    for iss in issues:
        by_rule.setdefault(iss.rule_id, []).append(iss)

    # completeness: 100 - average missing fraction
    completeness = round(100 * (1 - df.isna().mean().mean())) if (n and ncols) else 100

    def _pct_cols_without(rule_ids):
        bad = {iss.column for iss in issues if iss.rule_id in rule_ids}
        return round(100 * (1 - len(bad) / ncols)) if ncols else 100

    type_consistency = _pct_cols_without(
        {"TEXT_NUMERIC", "DATE_AS_TEXT", "EXCEL_SERIAL_DATE"})
    duplicate_risk = _pct_cols_without({"DUPLICATE_COLUMNS", "NON_UNIQUE_ID"})
    pii_risk = _pct_cols_without({"PII"})
    outlier_risk = _pct_cols_without({"UNEXPECTED_NEGATIVE"})

    breakdown = {
        "completeness": int(completeness),
        "type_consistency": int(type_consistency),
        "duplicate_risk": int(duplicate_risk),
        "pii_risk": int(pii_risk),
        "outlier_risk": int(outlier_risk),
    }
    # weighted overall (completeness and type matter most for AI use)
    weights = {"completeness": 0.3, "type_consistency": 0.3,
               "duplicate_risk": 0.15, "pii_risk": 0.15, "outlier_risk": 0.1}
    overall = round(sum(breakdown[k] * w for k, w in weights.items()))

    # Privacy risk is NOT a proportion of columns: a single email column makes
    # raw sharing unsafe even among 100 clean ones. Derive it from the kind of
    # PII found, kept separate from the data-quality score.
    rep = privacy_report(df)
    if rep["high_risk"]:
        privacy_risk = "High"
    elif rep["medium_risk"]:
        privacy_risk = "Medium"
    else:
        privacy_risk = "Low"

    return {
        "score": overall,
        "label": _label(overall),
        "breakdown": breakdown,
        "privacy_risk": privacy_risk,
        "ai_readiness": _label(overall),
        "issue_count": len(issues),
    }


# --- AI readiness ------------------------------------------------------------

def ai_readiness(df) -> dict:
    """Is this dataset ready to hand to an LLM? Returns checks + a verdict."""
    from .tokens import token_stats
    df = _as_pandas(df)
    issues = validate(df)
    rules = {iss.rule_id for iss in issues}
    pii_cols = sorted({iss.column for iss in issues if iss.rule_id == "PII"})

    checks = []

    def add(name, ok, detail):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    tk = token_stats(df)
    too_big = tk["summary_tokens"] > 6000
    add("fits_in_prompt", not too_big,
        f"summary ~{tk['summary_tokens']} tokens (raw ~{tk['raw_tokens']})")
    add("no_duplicate_columns", "DUPLICATE_COLUMNS" not in rules,
        "duplicate column names break per-column access")
    add("types_consistent",
        not (rules & {"TEXT_NUMERIC", "DATE_AS_TEXT", "EXCEL_SERIAL_DATE"}),
        "numbers/dates should be stored as proper types")
    add("no_pii", not pii_cols,
        f"PII columns: {pii_cols}" if pii_cols else "no obvious PII detected")
    add("low_cardinality_ok", "HIGH_CARDINALITY" not in rules,
        "very-high-cardinality columns add little signal")

    safe_to_summarize = "DUPLICATE_COLUMNS" not in rules
    safe_to_send_raw = not pii_cols

    if pii_cols:
        summary = (f"This dataset is safe to summarize for AI, but not safe to "
                   f"send raw because it contains PII columns: "
                   f"{', '.join(pii_cols)}. Use the masked summary "
                   f"(safedata.summarize) or build_safe_prompt().")
    elif too_big:
        summary = ("This dataset is large; send the summary, not the raw rows. "
                   "No PII was detected.")
    else:
        summary = ("This dataset looks ready for AI use. Prefer the summary over "
                   "raw rows to save tokens.")

    needs_review = bool(pii_cols) or "DUPLICATE_COLUMNS" in rules
    return {
        # clear, intent-revealing keys
        "ready_for_summary": safe_to_summarize,
        "safe_to_send_raw": safe_to_send_raw,
        "needs_review": needs_review,
        # back-compat aliases (deprecated; prefer the keys above)
        "ready": safe_to_summarize,
        "safe_to_summarize": safe_to_summarize,
        "checks": checks,
        "summary": summary,
    }


# --- column meaning ----------------------------------------------------------

def infer_columns(df) -> dict:
    """Best-effort semantic type for each column (identifier/date/money/...)."""
    df = _as_pandas(df)
    pii_cols = _all_pii(df)
    out = {}
    for col in df.columns:
        name = str(col).lower()
        s = df[col]
        if col in pii_cols:
            kinds = pii_cols[col]["kinds"]
            out[col] = "pii_" + (kinds[0] if kinds else "sensitive")
            continue
        if name == "id" or name.endswith("_id") or name.endswith("id"):
            out[col] = "identifier"
            continue
        if pd.api.types.is_datetime64_any_dtype(s) or _name_hints_date(col):
            out[col] = "date"
            continue
        if any(t in name for t in ("price", "amount", "revenue", "cost",
                                   "salary", "value", "$", "usd", "gbp")):
            out[col] = "money"
            continue
        if _name_hints_nonnegative(col):
            out[col] = "quantity"
            continue
        if pd.api.types.is_numeric_dtype(s):
            out[col] = "numeric"
            continue
        nun = s.nunique(dropna=True)
        if len(s) and nun / max(1, len(s)) >= HIGH_CARDINALITY_RATIO:
            out[col] = "text"
        else:
            out[col] = "category"
    return out


# --- safe prompt builder -----------------------------------------------------

def build_safe_prompt(df, question: str, privacy: str = "mask") -> str:
    """Build a ready-to-send prompt: a privacy-aware summary plus the question.

    privacy : "mask" (default) redacts PII in the summary; "raw" leaves samples
    as-is. Any other value is treated as "mask".
    """
    df = _as_pandas(df)
    redact = privacy != "raw"
    # All PII columns, value- AND name-detected. Regex masking alone misses
    # names/addresses, so when masking we FULLY withhold these columns' values.
    pii_cols = sorted(_all_pii(df))
    mask_columns = set(pii_cols) if redact else set()
    summary = summarize(df, redact_pii=redact, mask_columns=mask_columns)
    header = "DATA SUMMARY (raw rows withheld; safe to send to a model):"
    privacy_line = ""
    if pii_cols:
        verb = "masked/withheld" if redact else "PRESENT and NOT masked"
        privacy_line = f"\nPII columns {verb}: {', '.join(pii_cols)}"
    return (f"{header}{privacy_line}\n{summary}\n\n"
            f"USER QUESTION:\n{question}")


# --- data safety contract ----------------------------------------------------

# The trap rule-ids that describe a data hazard the model must account for
# (as opposed to privacy or structural findings).
_TRAP_RULES = {"TEXT_NUMERIC", "DATE_AS_TEXT", "EXCEL_SERIAL_DATE",
               "MESSY_CATEGORY", "CONSTANT_COLUMN", "NON_UNIQUE_ID",
               "EMPTY_COLUMN", "HIGH_MISSING", "UNEXPECTED_NEGATIVE",
               "DUPLICATE_COLUMNS", "HIGH_CARDINALITY"}

# Operations the guardrail allows (in-memory analysis) vs always refuses. These
# mirror what the bodyguard's static screen enforces, surfaced as a declarative
# policy so a caller (or the Agent) can reason about access before running code.
_ALLOWED_OPERATIONS = ["filter", "groupby", "aggregate", "sort",
                       "derive_column", "join_in_memory", "describe"]
_BLOCKED_OPERATIONS = ["file_read", "file_write", "network", "shell",
                       "code_eval", "raw_row_return"]


def _token_in_question(tok: str, q_tokens) -> bool:
    """A column token is present if a question token equals it or differs only by
    a trailing 's' (so 'email' matches 'emails'), avoiding false blocks of a
    column the question explicitly names."""
    return any(q == tok or q == tok + "s" or tok == q + "s" for q in q_tokens)


def _question_mentions_column(question: str, col) -> bool:
    """True if a column's name tokens all appear in the question text.

    Token-based (not substring) so 'region' matches "...by region" but 'name' in
    'customer_name' doesn't match the word 'rename'. Requiring ALL of a column's
    tokens avoids matching 'customer_name' on the bare word 'customer'. Used only
    to decide which PII columns a question legitimately needs.
    """
    if not question:
        return False
    q_tokens = _name_tokens(question)
    c_tokens = _name_tokens(col)
    return bool(c_tokens) and all(_token_in_question(t, q_tokens)
                                  for t in c_tokens)


def create_contract(df, question: str = None) -> dict:
    """Build a machine-readable Data Safety Contract for `df`.

    A declarative policy derived from the same read-only heuristics as the rest
    of the library: which columns are safe to expose, which hold PII and should
    be withheld, the data traps the model must account for, the operations the
    guardrail permits/refuses, and an overall privacy level. It runs no code and
    mutates nothing.

    question : optional. When given, enables a LEAST-PRIVILEGE firewall: PII
        columns the question doesn't reference are added to `blocked_columns`, so
        `run_safely(..., blocked_columns=contract["blocked_columns"])` refuses
        code that touches sensitive columns the question never needed. Only PII
        columns are firewalled this way — non-PII columns stay allowed, so the
        firewall never blocks a legitimate aggregate just because the question
        didn't name every column.

    This is a POLICY VIEW, not a guarantee: it is built from best-effort PII and
    data-quality heuristics (see safedata.pii / privacy_report). Use it to gate
    or document AI access to a dataset.
    """
    df = _as_pandas(df)
    rep = privacy_report(df)
    pii_cols = rep["pii_columns"]

    if question:
        # Block the PII columns the question does not mention; keep the rest.
        blocked_cols = [c for c in pii_cols
                        if not _question_mentions_column(question, c)]
        reason = (f"Question references "
                  f"{[c for c in df.columns if _question_mentions_column(question, c)] or 'no columns by name'}; "
                  f"PII columns not needed are blocked.")
    else:
        blocked_cols = list(pii_cols)
        reason = "All detected PII columns are blocked (no question supplied)."

    allowed_cols = [c for c in df.columns if c not in set(blocked_cols)]

    traps = []
    for iss in validate(df):
        if iss.rule_id in _TRAP_RULES:
            traps.append({"column": iss.column, "rule_id": iss.rule_id,
                          "issue": iss.message})

    if rep["high_risk"]:
        privacy_level = "strict"
    elif rep["medium_risk"]:
        privacy_level = "review"
    else:
        privacy_level = "low"

    return {
        "question": question,
        "allowed_columns": allowed_cols,
        "blocked_columns": blocked_cols,
        "allowed_operations": list(_ALLOWED_OPERATIONS),
        "blocked_operations": list(_BLOCKED_OPERATIONS),
        "data_traps": traps,
        "privacy_level": privacy_level,
        "max_result_rows": 50,
        "column_types": infer_columns(df),
        "reason": reason,
        "note": ("declarative policy from best-effort heuristics; not a "
                 "compliance guarantee. See safedata.pii / privacy_report."),
    }


def ai_risk_score(df, question: str = None) -> dict:
    """Score how risky it is to hand `df` (and `question`) to an AI: 0..100.

    Composes the existing privacy and data-quality signals into a single risk
    view with human-readable reasons and a recommended Agent mode. Read-only.
    Higher score = higher risk.
    """
    df = _as_pandas(df)
    rep = privacy_report(df)
    issues = validate(df)
    rules = {i.rule_id for i in issues}
    pii_cols = rep["pii_columns"]

    score = 0
    reasons = []
    if rep["high_risk"]:
        score += 50
        hi = [h["column"] for h in rep["high_risk"]]
        reasons.append(f"High-sensitivity PII columns: {', '.join(hi)}")
    elif rep["medium_risk"]:
        score += 25
        md = [m["column"] for m in rep["medium_risk"]]
        reasons.append(f"Possible PII columns (review): {', '.join(md)}")

    if question and pii_cols:
        unneeded = [c for c in pii_cols
                    if not _question_mentions_column(question, c)]
        if unneeded:
            score += 15
            reasons.append(
                f"Question doesn't need PII column(s) {', '.join(unneeded)}; "
                f"raw access is unnecessary.")

    trap_rules = rules & {"TEXT_NUMERIC", "DATE_AS_TEXT", "EXCEL_SERIAL_DATE",
                          "MESSY_CATEGORY", "DUPLICATE_COLUMNS"}
    if trap_rules:
        score += min(20, 5 * len(trap_rules))
        reasons.append(
            "Data traps that can cause wrong answers: "
            + ", ".join(sorted(trap_rules)))

    score = min(100, score)
    if score >= 60:
        level, mode = "high", "strict"
    elif score >= 30:
        level, mode = "medium", "safe"
    else:
        level, mode = "low", "safe"
    if not reasons:
        reasons.append("No PII or major data traps detected.")

    return {
        "risk_level": level,
        "score": score,
        "reasons": reasons,
        "pii_columns": pii_cols,
        "recommended_mode": mode,
    }


def detect_ai_traps(df) -> list:
    """The data traps that make an AI write a WRONG answer, AI-framed.

    A focused view of validate(): only the hazards that cause incorrect analysis
    (text-numeric, dates-as-text, Excel serials, messy categories, duplicate
    names, non-unique ids, unexpected negatives), each with a short instruction
    to give the model. Read-only.
    """
    out = []
    for iss in validate(df):
        if iss.rule_id in _TRAP_RULES and iss.rule_id not in (
                "CONSTANT_COLUMN", "HIGH_CARDINALITY"):
            out.append({
                "column": iss.column,
                "trap": iss.rule_id,
                "warning": iss.message,
                "tell_the_model": iss.suggestion,
            })
    return out


def shadow(df, rows: int = None, seed: int = 0):
    """Return a SYNTHETIC DataFrame with the same columns/types as `df` but no
    real values. Useful to test generated code (does it run?) without exposing
    real data, and to share a dataset's shape safely.

    Per column: numerics get random values in the observed range; datetimes get
    random dates in range; PII columns get typed fakes (user001@example.com,
    NAME_001); other text columns get cardinality-preserving synthetic labels.
    Missingness is approximately preserved. Deterministic for a given seed.
    """
    import numpy as np
    df = _as_pandas(df)
    n_src = len(df)
    n = rows if rows is not None else min(max(n_src, 1), 20)
    rng = np.random.default_rng(seed)
    pii = _all_pii(df)
    out = {}

    for col in df.columns:
        s = df[col]
        nn = s.dropna()
        null_frac = (s.isna().mean() if n_src else 0.0)

        if pd.api.types.is_datetime64_any_dtype(s):
            if len(nn):
                lo, hi = nn.min().value, nn.max().value
                vals = pd.to_datetime(rng.integers(lo, max(hi, lo + 1), n))
            else:
                vals = pd.to_datetime(rng.integers(0, 10**9, n))
            col_vals = list(vals)
        elif pd.api.types.is_numeric_dtype(s):
            if len(nn):
                lo, hi = float(nn.min()), float(nn.max())
            else:
                lo, hi = 0.0, 100.0
            raw = rng.uniform(lo, hi if hi > lo else lo + 1.0, n)
            if pd.api.types.is_integer_dtype(s):
                raw = np.round(raw).astype("int64")
            col_vals = list(raw)
        elif col in pii:
            kind = (pii[col]["kinds"] or ["sensitive"])[0]
            if kind == "email":
                col_vals = [f"user{i:03d}@example.com" for i in range(n)]
            elif kind == "phone":
                col_vals = [f"+10000{i:06d}" for i in range(n)]
            elif kind in ("name", "address", "national_id", "postcode",
                          "date_of_birth"):
                col_vals = [f"{kind.upper()}_{i:03d}" for i in range(n)]
            else:
                col_vals = [f"REDACTED_{i:03d}" for i in range(n)]
        else:
            # cardinality-preserving synthetic labels for categorical/text
            uniques = list(pd.unique(nn))[:max(1, len(pd.unique(nn)))]
            k = max(1, len(uniques))
            labels = [f"{col}_{j}" for j in range(k)]
            col_vals = [labels[int(rng.integers(0, k))] for _ in range(n)]

        # reapply approximate missingness
        if null_frac > 0 and n:
            mask = rng.random(n) < null_frac
            col_vals = [None if m else v for v, m in zip(col_vals, mask)]
        out[col] = col_vals

    shadow_df = pd.DataFrame(out, columns=list(df.columns))
    # preserve datetime dtype where the source was datetime
    for col in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            shadow_df[col] = pd.to_datetime(shadow_df[col])
    return shadow_df
