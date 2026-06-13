"""
ShadowFrame: a fully synthetic, same-shape stand-in for a real DataFrame.

The point is uniqueness in the SafePlan flow: instead of sending the model real
sample values (even masked ones), we send a schema profile plus rows of
synthetic data that match each column's type, range, and category cardinality.
The model sees the SHAPE of the data and can write a correct JSON plan, but no
real cell value ever reaches it.

This is best-effort de-identification of the prompt, not a guarantee: aggregate
statistics in the profile (numeric min/max/mean) are real summary values, and a
synthetic frame can still echo the real schema. It removes raw row exposure; it
does not make the schema itself secret.
"""

from __future__ import annotations

from dataclasses import dataclass
import pandas as pd
import numpy as np

from .analysis import _as_pandas, privacy_report


@dataclass
class ShadowFrameResult:
    shadow_df: pd.DataFrame
    profile: dict


def profile_dataframe(df, scan_rows="all") -> dict:
    """Describe `df` structurally: per-column dtype, missingness, cardinality,
    numeric/datetime range, and which columns look like PII."""
    df = _as_pandas(df)
    pii_set = set(privacy_report(df, scan_rows=scan_rows)["pii_columns"])

    profile = {"rows": int(len(df)), "columns": {}, "pii_columns": list(pii_set)}

    for col in df.columns:
        s = df[col]
        nn = s.dropna()
        info = {
            "dtype": str(s.dtype),
            "missing_rate": float(s.isna().mean()) if len(s) else 0.0,
            "unique_count": int(s.nunique(dropna=True)),
            "is_pii": col in pii_set,
        }

        if col in pii_set:
            # PII takes priority: never profile its value range, even if numeric.
            info["kind"] = "pii"
        elif pd.api.types.is_numeric_dtype(s):
            info["kind"] = "numeric"
            info["min"] = float(nn.min()) if len(nn) else 0.0
            info["max"] = float(nn.max()) if len(nn) else 1.0
            info["mean"] = float(nn.mean()) if len(nn) else 0.0
        elif pd.api.types.is_datetime64_any_dtype(s):
            info["kind"] = "datetime"
            info["min"] = str(nn.min()) if len(nn) else None
            info["max"] = str(nn.max()) if len(nn) else None
        else:
            info["kind"] = "categorical"
            info["category_count"] = int(s.nunique(dropna=True))

        profile["columns"][col] = info

    return profile


def _fake_pii_value(col: str, i: int) -> str:
    name = col.lower()
    if "email" in name:
        return f"user{i:04d}@example.com"
    if "phone" in name or "mobile" in name:
        return f"+440000{i:06d}"
    if "postcode" in name or "zip" in name or "postal" in name:
        return f"PC{i:04d}"
    if "surname" in name or "last" in name:
        return f"SURNAME_{i:04d}"
    if "name" in name:
        return f"PERSON_{i:04d}"
    if "address" in name:
        return f"ADDRESS_{i:04d}"
    if "id" in name:
        return f"ID_{i:04d}"
    return f"REDACTED_{i:04d}"


def create_shadowframe(df, rows: int = 20, seed: int = 0,
                       scan_rows="all") -> ShadowFrameResult:
    """Return a synthetic same-shape DataFrame (no real values) plus the schema
    profile it was built from. Column names, order, dtypes, approximate ranges,
    category cardinality and missingness are preserved; cell values are fake."""
    df = _as_pandas(df)
    rng = np.random.default_rng(seed)
    profile = profile_dataframe(df, scan_rows=scan_rows)

    out = {}
    n = rows
    for col, info in profile["columns"].items():
        kind = info["kind"]

        if kind == "numeric":
            lo = info.get("min", 0.0)
            hi = info.get("max", 1.0)
            vals = rng.uniform(lo, hi if hi > lo else lo + 1.0, n)
            if "int" in info["dtype"]:
                vals = vals.round().astype("int64")
            col_vals = list(vals)

        elif kind == "datetime":
            start = pd.to_datetime(info["min"]) if info["min"] else pd.Timestamp("2024-01-01")
            end = pd.to_datetime(info["max"]) if info["max"] else pd.Timestamp("2024-12-31")
            delta_days = max((end - start).days, 1)
            col_vals = [start + pd.Timedelta(days=int(rng.integers(0, delta_days)))
                        for _ in range(n)]

        elif kind == "pii":
            col_vals = [_fake_pii_value(col, i) for i in range(n)]

        else:  # categorical
            k = max(1, min(info.get("category_count", 3), 20))
            labels = [f"{col}_CATEGORY_{j}" for j in range(k)]
            col_vals = [labels[int(rng.integers(0, k))] for _ in range(n)]

        # Approximate the original missingness so the model sees nullable columns.
        missing_rate = info["missing_rate"]
        if missing_rate > 0:
            mask = rng.random(n) < missing_rate
            col_vals = [None if m else v for v, m in zip(col_vals, mask)]

        out[col] = col_vals

    shadow_df = pd.DataFrame(out, columns=list(df.columns))
    return ShadowFrameResult(shadow_df=shadow_df, profile=profile)
