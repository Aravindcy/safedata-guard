"""
THE TRANSLATOR.

Turns a huge DataFrame into a tiny, quality-aware summary safe to send to an
AI. This is NOT just df.describe(), it also warns the AI about the data traps
(text-numeric columns, messy categories, fake-unique IDs) that would otherwise
make the AI write broken code. That quality-awareness is what plain summaries
lack.
"""

import re
import pandas as pd

from . import pii as _pii

try:
    import polars as pl
    _HAS_POLARS = True
except Exception:  # pragma: no cover
    pl = None
    _HAS_POLARS = False


_NUMERIC_LIKE = re.compile(r"^\s*[-+]?[$£€]?\s*[\d,]+(\.\d+)?\s*%?\s*$")

# date-shaped strings: 2024-01-15, 2024/1/5, optional time, or 15-01-2024
_DATE_LIKE = re.compile(
    r"^\s*\d{4}[-/]\d{1,2}[-/]\d{1,2}([ T]\d{1,2}:\d{2}(:\d{2})?)?\s*$"
    r"|^\s*\d{1,2}[-/]\d{1,2}[-/]\d{4}\s*$")


def _looks_numeric(val) -> bool:
    return bool(_NUMERIC_LIKE.match(str(val)))


def _looks_like_date(val) -> bool:
    return bool(_DATE_LIKE.match(str(val)))


def _normalize_cat(val: str) -> str:
    s = str(val).strip().lower()
    return re.sub(r"[\s._\-]+", "", s)


def summarize(df, max_samples: int = 3, redact_pii: bool = True,
              mask_columns=None, mask_pii: bool = False) -> str:
    """
    Build a compact text summary of `df` for an AI prompt.
    Includes shape, per-column type/samples/stats, and DATA-TRAP WARNINGS.
    Accepts a pandas or polars DataFrame.

    PRIVACY NOTE: by default this masks only REGEX-detectable PII in the sample
    values (emails, cards, phones, SSNs, IPs). It does NOT hide names or
    addresses, which regex cannot reliably detect — so the raw summary can still
    contain values like "Alice Smith". If you will send the summary to a model,
    use `mask_pii=True` (below), or the higher-level `build_safe_prompt()` /
    `Agent.ask()`, which withhold detected PII columns automatically.

    redact_pii : bool
        If True (default), obvious PII in the sample values (emails, card-like
        numbers, phones, SSNs, IPs) is masked before the summary is built, so
        it isn't sent to the LLM. Best-effort only, see safedata.pii. Set
        False if you are sure the data is non-sensitive and want raw samples.
    mask_columns : set or None
        Columns whose values must be FULLY withheld (samples and stats replaced
        with [REDACTED]). Use this for PII that regex can't catch, e.g. name or
        address columns. safedata.build_safe_prompt() passes the detected PII
        columns here so names don't leak even though redact_pii alone can't spot
        them.
    mask_pii : bool
        If True, auto-detect PII columns (by value AND by name, so name/address
        columns are caught) and fully withhold them — i.e. populate
        `mask_columns` for you. Off by default to keep `summarize` a low-level,
        no-surprises view and avoid the detection cost; turn it on for a
        privacy-safe summary in one flag.
    """
    mask_columns = set(mask_columns) if mask_columns else set()
    if mask_pii:
        try:
            from .analysis import privacy_report
            mask_columns |= set(privacy_report(df)["pii_columns"])
        except Exception:
            pass
    if _HAS_POLARS and isinstance(df, pl.DataFrame):
        return _summarize_polars(df, max_samples=max_samples,
                                 redact_pii=redact_pii,
                                 mask_columns=mask_columns)
    return _summarize_pandas(df, max_samples=max_samples,
                             redact_pii=redact_pii,
                             mask_columns=mask_columns)


def _summarize_polars(df, max_samples: int = 3, redact_pii: bool = True,
                      mask_columns=None) -> str:
    """Native polars summary, mirrors the pandas one without converting."""
    mask_columns = set(mask_columns) if mask_columns else set()
    n = df.height
    lines = [f"Dataset: {n} rows, {df.width} columns.", "", "Columns:"]
    pii_cols = []

    for col in df.columns:
        s = df[col]
        dtype = str(s.dtype)
        missing = (s.null_count() / n) if n else 0.0
        info = f"- '{col}' (type={dtype}, missing={_fmt_missing(missing)})"
        if col in mask_columns:
            info += ", samples=['[REDACTED]']"
            pii_cols.append(col)
            lines.append(info)
            continue
        if s.dtype.is_numeric() and s.drop_nulls().len():
            nn = s.drop_nulls()
            info += (f", min={float(nn.min()):.2f}, max={float(nn.max()):.2f}, "
                     f"mean={float(nn.mean()):.2f}")
        else:
            samples = s.drop_nulls().unique().head(max_samples).to_list()
            samples = [str(x) for x in samples]
            if redact_pii:
                redacted = _pii.redact_samples(samples)
                if redacted != samples:
                    pii_cols.append(col)
                samples = redacted
            info += f", samples={samples}"
        lines.append(info)

    if pii_cols:
        shown = ", ".join(f"'{c}'" for c in pii_cols[:6])
        more = f" (+{len(pii_cols) - 6} more)" if len(pii_cols) > 6 else ""
        lines += ["", (f"NOTE: possible PII was detected and masked in the "
                       f"samples for {shown}{more} (best-effort redaction).")]

    warnings = _trap_warnings_polars(df)
    if warnings:
        lines += ["", "DATA TRAPS (account for these when writing code):"]
        lines += [f"- {w}" for w in warnings]
    return "\n".join(lines)


def _trap_warnings_polars(df):
    """Polars version of the trap detector. Same checks as pandas."""
    n = df.height
    warnings = []

    for col in df.columns:
        s = df[col]
        if not (s.dtype == pl.Utf8):
            continue
        non_null = s.drop_nulls()
        if not non_null.len():
            continue
        vals = non_null.to_list()
        if sum(_looks_numeric(v) for v in vals) / len(vals) >= 0.7:
            warnings.append(
                f"Column '{col}' is stored as TEXT but holds numbers "
                f"(e.g. '$', ','). Clean and cast to float before math.")
        elif sum(_looks_like_date(v) for v in vals) / len(vals) >= 0.9:
            warnings.append(
                f"Column '{col}' looks like DATES stored as text. Convert it "
                f"to a date type before sorting or doing date maths; string "
                f"comparison will not order them correctly.")
        keys = {}
        for v in set(vals):
            keys.setdefault(_normalize_cat(v), []).append(v)
        merged = [grp for grp in keys.values() if len(grp) > 1]
        if merged:
            warnings.append(
                f"Column '{col}' has the same category written several ways "
                f"(e.g. {merged[0]}). Normalize before grouping.")

    # constant-column trap (fact, not a guess)
    const_cols = []
    for col in df.columns:
        nn = df[col].drop_nulls()
        if nn.len() > 1 and nn.n_unique() == 1:
            const_cols.append(col)
    if const_cols:
        shown = ", ".join(f"'{c}'" for c in const_cols[:6])
        more = f" (+{len(const_cols) - 6} more)" if len(const_cols) > 6 else ""
        warnings.append(
            f"{len(const_cols)} column(s) hold the SAME value in every row "
            f"({shown}{more}); they carry no information for grouping or "
            f"comparison.")

    for col in df.columns:
        name = col.lower()
        if name == "id" or name.endswith("_id") or name.endswith("id"):
            nn = df[col].drop_nulls()
            if nn.len() and nn.n_unique() < nn.len():
                warnings.append(
                    f"Column '{col}' looks like an ID but is NOT unique. "
                    f"Do not assume one row per value.")

    empty_cols = [c for c in df.columns if df[c].null_count() == n and n > 0]
    if empty_cols:
        shown = ", ".join(f"'{c}'" for c in empty_cols[:6])
        more = f" (+{len(empty_cols) - 6} more)" if len(empty_cols) > 6 else ""
        warnings.append(
            f"{len(empty_cols)} column(s) are COMPLETELY EMPTY and carry no "
            f"data; exclude them: {shown}{more}.")

    high_missing = []
    for col in df.columns:
        if col in empty_cols:
            continue
        frac = (df[col].null_count() / n) if n else 0.0
        if frac >= HIGH_MISSING_THRESHOLD:
            high_missing.append((col, frac))
    if high_missing:
        high_missing.sort(key=lambda x: -x[1])
        shown = ", ".join(f"'{c}' ({_fmt_missing(f)})"
                          for c, f in high_missing[:6])
        more = (f" (+{len(high_missing) - 6} more)"
                if len(high_missing) > 6 else "")
        warnings.append(
            f"{len(high_missing)} column(s) are mostly empty "
            f"(>= {int(HIGH_MISSING_THRESHOLD*100)}% missing); averages/counts "
            f"reflect a small minority of rows; consider dropna(): "
            f"{shown}{more}.")

    for col in df.columns:
        s = df[col]
        if not s.dtype.is_numeric() or not _name_hints_date(col):
            continue
        nn = s.drop_nulls()
        if not nn.len():
            continue
        in_range = nn.is_between(*EXCEL_DATE_RANGE).sum() / nn.len()
        if in_range >= 0.9:
            warnings.append(
                f"Column '{col}' looks like an Excel SERIAL DATE stored as a "
                f"number (e.g. {int(nn[0])} ~ a real date). Convert it before "
                f"treating it as a date.")

    for col in df.columns:
        s = df[col]
        if not s.dtype.is_numeric() or not _name_hints_nonnegative(col):
            continue
        nn = s.drop_nulls()
        if nn.len() < 2:
            continue
        scale = max(abs(float(nn.max())), abs(float(nn.min())))
        threshold = max(scale * 1e-3, NEG_TOLERANCE)
        if (nn < -threshold).sum() > 0:
            warnings.append(
                f"Column '{col}' contains NEGATIVE values "
                f"(min={float(nn.min()):.2f}) though its name suggests it "
                f"should not. Verify these are real, not data errors.")

    return warnings


def dedupe_columns(df: pd.DataFrame):
    """Return (df_view, dup_names) with any duplicate column names made unique.

    Duplicate column names are a real data-quality problem (common in messy
    CSV/Excel imports) and they also break per-column access (df[name] returns
    a DataFrame, not a Series), which crashes anything that does df[col].isna().
    Repeated names get a numeric suffix (`a`, `a.1`, ...). If there are no
    duplicates the original df is returned untouched. Shared by the summary and
    the HTML report so both handle this the same way.
    """
    dup_names = list(dict.fromkeys(
        c for c in df.columns if list(df.columns).count(c) > 1))
    if not dup_names:
        return df, dup_names
    seen = {}
    new_cols = []
    for c in df.columns:
        seen[c] = seen.get(c, 0) + 1
        new_cols.append(c if seen[c] == 1 else f"{c}.{seen[c]-1}")
    df = df.copy()
    df.columns = new_cols
    return df, dup_names


def _summarize_pandas(df: pd.DataFrame, max_samples: int = 3,
                      redact_pii: bool = True, mask_columns=None) -> str:
    # Analyse a de-duplicated view so the rest of the summary is reliable.
    df, dup_names = dedupe_columns(df)
    mask_columns = set(mask_columns) if mask_columns else set()

    lines = [f"Dataset: {len(df)} rows, {df.shape[1]} columns.", "", "Columns:"]
    pii_cols = []

    for i, col in enumerate(df.columns):
        # iterate by position so any odd indexing still gives a Series
        s = df.iloc[:, i]
        non_null = s.dropna()
        dtype = str(s.dtype)
        null_str = _fmt_missing(s.isna().mean())
        info = f"- '{col}' (type={dtype}, missing={null_str})"

        if col in mask_columns:
            # fully withhold values (PII that regex can't catch, e.g. names)
            info += ", samples=['[REDACTED]']"
            pii_cols.append(col)
        elif pd.api.types.is_numeric_dtype(s) and len(non_null):
            info += f", min={non_null.min():.2f}, max={non_null.max():.2f}, mean={non_null.mean():.2f}"
        else:
            samples = list(non_null.astype(str).unique()[:max_samples])
            if redact_pii:
                redacted = _pii.redact_samples(samples)
                if redacted != [str(v) for v in samples]:
                    pii_cols.append(col)
                samples = redacted
            info += f", samples={list(samples)}"
        lines.append(info)

    if pii_cols:
        shown = ", ".join(f"'{c}'" for c in pii_cols[:6])
        more = f" (+{len(pii_cols) - 6} more)" if len(pii_cols) > 6 else ""
        lines += ["", (f"NOTE: possible PII was detected and masked in the "
                       f"samples for {shown}{more} (best-effort redaction).")]

    warnings = _trap_warnings(df)
    if dup_names:
        shown = ", ".join(f"'{c}'" for c in dup_names[:6])
        more = f" (+{len(dup_names) - 6} more)" if len(dup_names) > 6 else ""
        warnings.insert(0,
            f"{len(dup_names)} column name(s) are DUPLICATED ({shown}{more}); "
            f"they were renamed with a numeric suffix for analysis. Fix the "
            f"source so each column has a unique name.")
    if warnings:
        lines += ["", "DATA TRAPS (account for these when writing code):"]
        lines += [f"- {w}" for w in warnings]

    return "\n".join(lines)


def _trap_warnings(df: pd.DataFrame):
    """The quality-aware part: flag traps that make AIs write wrong code."""
    warnings = []
    obj_cols = df.select_dtypes(include=["object", "string"]).columns

    for col in obj_cols:
        non_null = df[col].dropna().astype(str)
        if not len(non_null):
            continue
        # text-numeric trap
        if non_null.map(_looks_numeric).mean() >= 0.7:
            warnings.append(
                f"Column '{col}' is stored as TEXT but holds numbers "
                f"(e.g. '$', ','). Clean and cast to float before math.")
        # date-as-text trap: date-shaped strings that aren't a real date type
        elif non_null.map(_looks_like_date).mean() >= 0.9:
            warnings.append(
                f"Column '{col}' looks like DATES stored as text. Convert with "
                f"pd.to_datetime(col) before sorting or doing date maths; string "
                f"comparison will not order them correctly.")
        # messy-category trap
        keys = {}
        for v in non_null.unique():
            keys.setdefault(_normalize_cat(v), []).append(v)
        merged = [grp for grp in keys.values() if len(grp) > 1]
        if merged:
            warnings.append(
                f"Column '{col}' has the same category written several ways "
                f"(e.g. {merged[0]}). Normalize before grouping.")

    # constant-column trap: one value in every row. An AI may group by it or
    # filter on it pointlessly; it carries no information. (Fact, not a guess.)
    const_cols = []
    for col in df.columns:
        nn = df[col].dropna()
        if len(nn) > 1 and nn.nunique() == 1:
            const_cols.append(col)
    if const_cols:
        shown = ", ".join(f"'{c}'" for c in const_cols[:6])
        more = f" (+{len(const_cols) - 6} more)" if len(const_cols) > 6 else ""
        warnings.append(
            f"{len(const_cols)} column(s) hold the SAME value in every row "
            f"({shown}{more}); they carry no information for grouping or "
            f"comparison.")

    # non-unique ID trap
    for col in df.columns:
        name = col.lower()
        if (name == "id" or name.endswith("_id") or name.endswith("id")):
            nn = df[col].dropna()
            if len(nn) and nn.nunique() < len(nn):
                warnings.append(
                    f"Column '{col}' looks like an ID but is NOT unique. "
                    f"Do not assume one row per value.")

    # empty-column trap: truly all-missing columns (group them into one line)
    empty_cols = [c for c in df.columns if df[c].isna().all()]
    if empty_cols:
        shown = ", ".join(f"'{c}'" for c in empty_cols[:6])
        more = f" (+{len(empty_cols) - 6} more)" if len(empty_cols) > 6 else ""
        warnings.append(
            f"{len(empty_cols)} column(s) are COMPLETELY EMPTY and carry no "
            f"data; exclude them: {shown}{more}.")

    # high-missingness trap: a lot (but not all) missing. Group into ONE line
    # so 20 similar columns don't produce 20 near-identical warnings.
    high_missing = []
    for col in df.columns:
        if col in empty_cols:
            continue
        frac = df[col].isna().mean()
        if frac >= HIGH_MISSING_THRESHOLD:
            high_missing.append((col, frac))
    if high_missing:
        high_missing.sort(key=lambda x: -x[1])
        shown = ", ".join(f"'{c}' ({_fmt_missing(f)})" for c, f in high_missing[:6])
        more = (f" (+{len(high_missing) - 6} more)"
                if len(high_missing) > 6 else "")
        warnings.append(
            f"{len(high_missing)} column(s) are mostly empty "
            f"(>= {int(HIGH_MISSING_THRESHOLD*100)}% missing); averages/counts "
            f"reflect a small minority of rows; consider dropna(): "
            f"{shown}{more}.")

    # Excel-serial-date trap (integers in the typical serial-date range,
    # in a column whose name hints at a date)
    for col in df.select_dtypes(include=["int64", "float64", "int32"]).columns:
        if not _name_hints_date(col):
            continue
        nn = df[col].dropna()
        if len(nn) and nn.between(*EXCEL_DATE_RANGE).mean() >= 0.9:
            warnings.append(
                f"Column '{col}' looks like an Excel SERIAL DATE stored as a "
                f"number (e.g. {int(nn.iloc[0])} ~ a real date). Convert with "
                f"pd.to_datetime(col, unit='D', origin='1899-12-30') before "
                f"treating it as a date.")

    # unexpected-negatives note. Only flag negatives that are MATERIAL relative
    # to the column's scale, tiny values near zero (e.g. -0.00, -0.01 in a
    # column that ranges to hundreds) are rounding noise, not real negatives.
    for col in df.select_dtypes(include=["int64", "float64"]).columns:
        nn = df[col].dropna()
        if len(nn) < 2 or not _name_hints_nonnegative(col):
            continue
        scale = max(abs(nn.max()), abs(nn.min()))
        # "material" = more negative than 0.1% of the column's scale (and not
        # just floating-point dust)
        threshold = max(scale * 1e-3, NEG_TOLERANCE)
        if (nn < -threshold).any():
            warnings.append(
                f"Column '{col}' contains NEGATIVE values "
                f"(min={nn.min():.2f}) though its name suggests it should not. "
                f"Verify these are real, not data errors.")

    return warnings


# thresholds / ranges, kept as named constants so they're easy to tune
HIGH_MISSING_THRESHOLD = 0.6
NEG_TOLERANCE = 1e-6  # values within this of zero are treated as zero


def _fmt_missing(frac: float) -> str:
    """Format a missing fraction consistently everywhere.
    Avoids rounding a non-empty column up to a misleading '100%'."""
    pct = frac * 100
    if frac >= 1.0:
        return "100%"
    if pct > 99:
        return ">99%"
    return f"{pct:.0f}%"
# Excel serial dates: ~ year 2000 (36526) to ~ year 2040 (51500)
EXCEL_DATE_RANGE = (36526, 51500)


# Name-based hints for two heuristics. Kept as generic, editable module
# constants (not domain-specific jargon) so the library is useful out of the box
# for any dataset; extend them in place if your domain has its own conventions.
#   safedata.translator.DATE_NAME_HINTS.add("renewal")
#
# DATE hints use word-boundary matching so "start"/"end" only fire on a real
# token (e.g. "start_date"), not as a substring of unrelated names ("restart").
DATE_NAME_HINTS = {"date", "dt", "datetime", "timestamp", "day"}
NONNEGATIVE_NAME_HINTS = {"count", "qty", "quantity", "amount", "total",
                          "volume", "price", "age", "num"}

_WORD = re.compile(r"[a-z0-9]+")


def _name_tokens(col: str):
    return set(_WORD.findall(str(col).lower()))


def _name_hints_date(col: str) -> bool:
    tokens = _name_tokens(col)
    name = str(col).lower()
    # token match (start_date) OR substring for the unambiguous roots
    return bool(tokens & DATE_NAME_HINTS) or "date" in name or "time" in name


def _name_hints_nonnegative(col: str) -> bool:
    return bool(_name_tokens(col) & NONNEGATIVE_NAME_HINTS)
