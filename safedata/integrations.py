"""
Export the inferred schema and data-quality checks to other validation tools.

safedata's role is the AI-safety layer; these helpers let it plug into the
schema/quality tools teams already use rather than compete with them:

    to_pandera_schema(df)            -> a pandera DataFrameSchema (needs pandera)
    to_great_expectations_suite(df)  -> a portable expectation-suite dict that
        Great Expectations can import (no GX dependency required here, since GX
        is heavy and its API changes between major versions)

The checks come from the same read-only heuristics as validate()/privacy_report,
so they agree with the rest of the library.
"""

import pandas as pd

from .analysis import _as_pandas, _all_pii
from .translator import _name_hints_nonnegative


def _is_unique_id(col, series) -> bool:
    name = str(col).lower()
    id_like = name == "id" or name.endswith("_id") or name.endswith("id")
    nn = series.dropna()
    return bool(id_like and len(nn) and nn.nunique() == len(nn))


def _column_facts(df):
    """Per-column facts both exporters share."""
    df = _as_pandas(df)
    pii = set(_all_pii(df))
    facts = {}
    for col in df.columns:
        s = df[col]
        facts[col] = {
            "dtype": str(s.dtype),
            "nullable": bool(s.isna().any()),
            "non_negative": (_name_hints_nonnegative(col)
                             and pd.api.types.is_numeric_dtype(s)),
            "unique": _is_unique_id(col, s),
            "is_pii": col in pii,
        }
    return df, facts


def to_pandera_schema(df, coerce: bool = True):
    """Return a pandera DataFrameSchema inferred from `df`.

    Columns get their dtype, nullability and (where applicable) a non-negative
    check or a uniqueness constraint. Requires pandera (pip install pandera).
    """
    try:
        import pandera.pandas as pa   # pandera >= 0.20 (avoids deprecation)
    except ImportError:
        try:
            import pandera as pa
        except ImportError as e:
            raise ImportError(
                "to_pandera_schema needs pandera: pip install pandera") from e

    _df, facts = _column_facts(df)
    columns = {}
    for col, f in facts.items():
        checks = [pa.Check.ge(0)] if f["non_negative"] else None
        columns[col] = pa.Column(
            f["dtype"], nullable=f["nullable"], unique=f["unique"],
            checks=checks, required=True,
            description="PII (safedata)" if f["is_pii"] else None)
    return pa.DataFrameSchema(columns, coerce=coerce)


def to_great_expectations_suite(df, suite_name: str = "safedata_suite") -> dict:
    """Return a Great Expectations expectation suite as a portable dict.

    The shape (expectation_suite_name + a list of {expectation_type, kwargs}) is
    what GX consumes, so you can load it with GX of your choice without safedata
    depending on a specific GX version. Detected PII columns are listed in the
    suite meta so a pipeline can act on them.
    """
    _df, facts = _column_facts(df)
    expectations = [{
        "expectation_type": "expect_table_columns_to_match_set",
        "kwargs": {"column_set": list(facts.keys())},
    }]
    for col, f in facts.items():
        expectations.append({
            "expectation_type": "expect_column_to_exist",
            "kwargs": {"column": col},
        })
        if not f["nullable"]:
            expectations.append({
                "expectation_type": "expect_column_values_to_not_be_null",
                "kwargs": {"column": col},
            })
        if f["unique"]:
            expectations.append({
                "expectation_type": "expect_column_values_to_be_unique",
                "kwargs": {"column": col},
            })
        if f["non_negative"]:
            expectations.append({
                "expectation_type": "expect_column_values_to_be_between",
                "kwargs": {"column": col, "min_value": 0},
            })
    return {
        "expectation_suite_name": suite_name,
        "expectations": expectations,
        "meta": {
            "generated_by": "safedata-guard",
            "pii_columns": sorted(c for c, f in facts.items() if f["is_pii"]),
        },
    }
