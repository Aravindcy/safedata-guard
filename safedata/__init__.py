"""
safedata-guard: a safety layer for asking AI questions over sensitive data.

It scans your dataframe, removes unnecessary sensitive fields, executes the
analysis through a safe engine (SafePlan - the model returns a validated JSON
plan, not raw Python), and returns an answer with an audit receipt.

Quick start (the one front door):

    import safedata as sd

    result = sd.ask(df, "What is total revenue by region?",
                    model=my_model, profile="banking")
    print(result.answer)
    print(result.receipt.summary())

The four verbs:
    sd.ask(df, question, model, profile)  - answer a question safely
    sd.scan(df, profile)                  - assess privacy/quality risk
    sd.protect(df, question, profile)     - get a privacy-filtered safe view
    sd.Guard(profile, model)              - a reusable, configured object

Policy controls everything (industry profiles: general/energy/banking/insurance/
healthcare/strict). Advanced/power-user tools live under `sd.advanced`.

This is a safety layer, not a compliance guarantee. See SECURITY.md.
"""

from .api import ask, scan, protect
from .guard import Guard
from .policy import Policy
from .results import Result, ScanReport, Receipt
from .exceptions import SafedataError
from . import advanced

__version__ = "2.0.0"

__all__ = [
    "ask",
    "scan",
    "protect",
    "Guard",
    "Policy",
    "Result",
    "ScanReport",
    "Receipt",
    "SafedataError",
]
