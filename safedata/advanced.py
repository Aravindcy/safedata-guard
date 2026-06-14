"""
Advanced tools - reachable via `safedata.advanced.*`.

The top-level package exposes only the nine everyday names (ask, scan, protect,
Guard, Policy, Result, ScanReport, Receipt, SafedataError). The power-user tools
live here so the front door stays small but nothing is lost:

    import safedata as sd
    report = sd.advanced.leak_test(df, model=my_model)
    shadow = sd.advanced.create_shadowframe(df)
    sd.advanced.run_safely(code, df)          # guarded Python on a copy

These are stable, supported entry points - just intentionally one level deeper
than the everyday API.
"""

from .leaktest import (leak_test, LeakTestResult, LeakAttempt, detect_leak,
                       collect_sensitive_values)
from .shadowframe import create_shadowframe, profile_dataframe, ShadowFrameResult
from .session import SafeSession, SessionEvent, estimate_question_cost
from .bodyguard import run_safely, check_code, CodeCheck, k_anonymize, SafetyError

__all__ = [
    "leak_test", "LeakTestResult", "LeakAttempt", "detect_leak",
    "collect_sensitive_values",
    "create_shadowframe", "profile_dataframe", "ShadowFrameResult",
    "SafeSession", "SessionEvent", "estimate_question_cost",
    "run_safely", "check_code", "CodeCheck", "k_anonymize", "SafetyError",
]
