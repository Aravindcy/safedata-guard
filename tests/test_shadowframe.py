import pandas as pd
import numpy as np
import pytest

import safedata
from safedata.shadowframe import create_shadowframe, profile_dataframe
from safedata.safeplan import safe_query


def _df():
    return pd.DataFrame({
        "email": [f"real{i}@corp.com" for i in range(30)],
        "name": [f"Real Name {i}" for i in range(30)],
        "revenue": np.arange(30) * 10.0,
        "region": (["North", "South", "East"] * 10),
        "qty": np.arange(30),
    })


def test_shadow_same_shape_and_columns():
    df = _df()
    res = create_shadowframe(df, rows=12)
    assert list(res.shadow_df.columns) == list(df.columns)
    assert len(res.shadow_df) == 12


def test_shadow_does_not_copy_real_pii_values():
    df = _df()
    shadow = create_shadowframe(df, rows=25).shadow_df
    real_emails = set(df["email"].astype(str))
    real_names = set(df["name"].astype(str))
    assert real_emails.isdisjoint(set(shadow["email"].astype(str)))
    assert real_names.isdisjoint(set(shadow["name"].astype(str)))


def test_shadow_numeric_stays_in_range():
    df = _df()
    res = create_shadowframe(df, rows=50, seed=1)
    lo, hi = df["revenue"].min(), df["revenue"].max()
    assert res.shadow_df["revenue"].min() >= lo
    assert res.shadow_df["revenue"].max() <= hi


def test_profile_marks_pii_and_kinds():
    prof = profile_dataframe(_df())
    assert "email" in prof["pii_columns"]
    assert prof["columns"]["revenue"]["kind"] == "numeric"
    assert prof["columns"]["region"]["kind"] == "categorical"
    # PII columns are never profiled as numeric, even if they look numeric.
    assert prof["columns"]["email"]["kind"] == "pii"


def test_shadow_preserves_missingness_roughly():
    df = _df()
    df.loc[:14, "region"] = None        # ~50% missing
    shadow = create_shadowframe(df, rows=200, seed=3).shadow_df
    miss = shadow["region"].isna().mean()
    assert 0.3 < miss < 0.7


def test_safe_query_shadow_prompt_excludes_real_values(monkeypatch):
    # The prompt the model receives must not contain real cell values.
    df = _df()
    captured = {}

    def model(prompt):
        captured["prompt"] = prompt
        return '{"operation":"count_rows"}'

    safe_query(df, "how many rows", model=model,
                        policy=safedata.Policy.regulated(), use_shadow=True)
    p = captured["prompt"]
    assert "real0@corp.com" not in p
    assert "Real Name 0" not in p
