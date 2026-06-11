"""
THE TOKEN COUNTER.

A big reason to use safedata is cost: instead of sending a whole DataFrame to a
model (which can be millions of tokens), it sends a short summary (a few hundred
tokens). This module estimates how many tokens that saves, so the benefit is
visible.

Important: these are ESTIMATES. Each model provider counts tokens with its own
tokenizer, so exact numbers vary. The estimate uses the widely used rule of
about 4 characters per token, which is close enough to show the scale of the
saving honestly.

    import safedata
    print(safedata.token_savings(df))
    # Sending the summary uses about 380 tokens instead of about 2,100,000
    # for the raw data. Estimated saving: 99.98%.
"""

import pandas as pd
from .translator import summarize

try:
    import polars as pl
    _HAS_POLARS = True
except Exception:  # pragma: no cover
    pl = None
    _HAS_POLARS = False


CHARS_PER_TOKEN = 4  # common rough rule used across providers


def estimate_tokens(text: str) -> int:
    """Estimate the number of tokens in a piece of text (rough, provider-agnostic)."""
    if not text:
        return 0
    return max(1, round(len(str(text)) / CHARS_PER_TOKEN))


# Sampling the whole frame to size it would defeat the purpose (the library
# exists precisely so you never materialise the full table). Estimate the raw
# size from a small head sample instead: serialise a few hundred rows, measure
# the average characters per row, and scale to the full row count.
_RAW_SAMPLE_ROWS = 200


def _estimate_raw_tokens(df) -> int:
    """Estimate the tokens of the full table-as-CSV WITHOUT serialising it all.

    Serialise a small sample, get an average row width, and scale up. For tiny
    frames the sample is the whole frame, so the estimate is exact.
    """
    is_polars = _HAS_POLARS and isinstance(df, pl.DataFrame)
    n = df.height if is_polars else len(df)
    if n == 0:
        # header-only: a single line of column names
        header = ",".join(str(c) for c in df.columns)
        return estimate_tokens(header)

    sample_n = min(n, _RAW_SAMPLE_ROWS)
    if is_polars:
        sample_csv = df.head(sample_n).write_csv()
    else:
        sample_csv = df.head(sample_n).to_csv(index=False)

    # Split header (sent once) from the per-row body so the scale-up is fair.
    newline = sample_csv.find("\n")
    header_len = newline + 1 if newline != -1 else len(sample_csv)
    body_len = len(sample_csv) - header_len
    avg_row_chars = body_len / sample_n if sample_n else 0.0

    total_chars = header_len + avg_row_chars * n
    return max(1, round(total_chars / CHARS_PER_TOKEN))


def token_stats(df: pd.DataFrame) -> dict:
    """
    Return a dictionary of token estimates:
      summary_tokens : tokens for safedata's summary
      raw_tokens     : tokens if you sent the whole DataFrame as text
      saved_tokens   : the difference
      saved_percent  : percentage saved (0..100)

    `raw_tokens` is estimated from a row sample (never serialises the whole
    frame), so this stays cheap even on tables with millions of rows.
    """
    summary_text = summarize(df)

    summary_tokens = estimate_tokens(summary_text)
    raw_tokens = _estimate_raw_tokens(df)
    saved = max(0, raw_tokens - summary_tokens)
    pct = (saved / raw_tokens * 100) if raw_tokens else 0.0
    # never display a misleading 100% when some tokens were actually sent
    if 99.995 <= pct < 100 or (pct >= 100 and summary_tokens > 0):
        pct = 99.99

    return {
        "summary_tokens": summary_tokens,
        "raw_tokens": raw_tokens,
        "saved_tokens": saved,
        "saved_percent": round(pct, 2),
    }


def token_savings(df: pd.DataFrame) -> str:
    """
    A human-readable sentence describing the estimated token saving.
    """
    r = token_stats(df)
    # For very small inputs the fixed-size summary (column list, stats, trap
    # warnings) can be larger than dumping the raw data, so there is nothing to
    # save. Say that plainly instead of reporting an odd "0.0% saving".
    if r["saved_tokens"] <= 0:
        return (
            f"For very small inputs the summary (~{r['summary_tokens']:,} "
            f"tokens) may be larger than the raw data (~{r['raw_tokens']:,} "
            f"tokens), so there is no token saving here. The summary pays off "
            f"on larger tables. These are estimates; exact counts vary by model."
        )
    return (
        f"Sending the summary uses about {r['summary_tokens']:,} tokens "
        f"instead of about {r['raw_tokens']:,} for the raw data. "
        f"Estimated saving: {r['saved_percent']}% "
        f"(about {r['saved_tokens']:,} tokens). "
        f"These are estimates; exact counts vary by model."
    )
