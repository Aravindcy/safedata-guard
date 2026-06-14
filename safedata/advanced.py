"""
Advanced tools - reachable via `safedata.advanced.*`.

The top-level package exposes only the nine everyday names (ask, scan, protect,
Guard, Policy, Result, ScanReport, Receipt, SafedataError). Every power-user
feature from earlier versions is still here, one level deeper, so the front door
stays small but nothing is lost:

    import safedata as sd

    sd.advanced.safe_query(df, q, model=m)        # low-level SafePlan call
    sd.advanced.safe_answer(df, q, model=m)       # guarded-Python answer
    sd.advanced.leak_test(df, model=m)            # privacy red-team score
    sd.advanced.create_shadowframe(df)            # synthetic same-shape data
    sd.advanced.summarize(df)                     # quality-aware text summary
    sd.advanced.token_stats(df)                   # token-saving estimate
    sd.advanced.to_pandera_schema(df)             # Pandera / GX export
    sd.advanced.run_safely(code, df)              # guarded Python on a copy
"""

# Privacy red-team + synthetic data + sessions
from .leaktest import (leak_test, LeakTestResult, LeakAttempt, detect_leak,
                       collect_sensitive_values)
from .shadowframe import create_shadowframe, profile_dataframe, ShadowFrameResult
from .session import SafeSession, SessionEvent, estimate_question_cost

# Guarded-execution internals
from .bodyguard import (run_safely, check_code, CodeCheck, k_anonymize,
                        SafetyError)

# Low-level engines (SafePlan + the question-aware firewall)
from .safeplan import (safe_query, SafePlan, SafePlanResult, MetricSpec,
                       validate_safeplan, execute_safeplan, prepare_safeplan,
                       execute_prepared)
from .firewall import (safe_answer, create_privacy_plan, make_safe_view,
                       PrivacyPlan, detect_operation)
from .agent import Agent, AgentResult, build_prompt

# Translator / tokens / reporting / model wrapping / PII utilities
from .translator import summarize
from .tokens import token_savings, token_stats, estimate_tokens
from .report import report
from .wrap import wrap, extract_code, ModelError
from .pii import redact_text
from .receipt import create_receipt, format_receipt
from .integrations import to_pandera_schema, to_great_expectations_suite

# Read-only analysis helpers
from .analysis import (privacy_report, ai_readiness, ai_risk_score,
                       quality_score, validate, Issue, infer_columns,
                       detect_ai_traps, create_contract, build_safe_prompt,
                       enable_presidio, shadow, suggest_fixes, explain_issue)

__all__ = [
    # red-team / synthetic / sessions
    "leak_test", "LeakTestResult", "LeakAttempt", "detect_leak",
    "collect_sensitive_values",
    "create_shadowframe", "profile_dataframe", "ShadowFrameResult",
    "SafeSession", "SessionEvent", "estimate_question_cost",
    # guarded execution
    "run_safely", "check_code", "CodeCheck", "k_anonymize", "SafetyError",
    # low-level engines
    "safe_query", "SafePlan", "SafePlanResult", "MetricSpec",
    "validate_safeplan", "execute_safeplan", "prepare_safeplan",
    "execute_prepared",
    "safe_answer", "create_privacy_plan", "make_safe_view", "PrivacyPlan",
    "detect_operation", "Agent", "AgentResult", "build_prompt",
    # translator / tokens / report / wrap / pii / integrations
    "summarize", "token_savings", "token_stats", "estimate_tokens", "report",
    "wrap", "extract_code", "ModelError", "redact_text",
    "create_receipt", "format_receipt",
    "to_pandera_schema", "to_great_expectations_suite",
    # analysis
    "privacy_report", "ai_readiness", "ai_risk_score", "quality_score",
    "validate", "Issue", "infer_columns", "detect_ai_traps", "create_contract",
    "build_safe_prompt", "enable_presidio", "shadow", "suggest_fixes",
    "explain_issue",
]
