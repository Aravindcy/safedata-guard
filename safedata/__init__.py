"""
safedata, a safety layer and translator between an AI and your data.

It does two things existing AI-data tools don't combine:
  - TRANSLATOR: sends the AI a tiny, quality-aware summary (not 100k rows),
    making analysis far cheaper and warning the AI about data traps upfront.
  - BODYGUARD: runs the AI's code on a copy, blocks destructive operations,
    checks invariants, and feeds errors back so the AI fixes itself,
    before anything touches your real data.

Quick start:

    import safedata

    def my_model(prompt):       # plug in any LLM here
        return "result = df['amount'].sum()"

    agent = safedata.Agent(model=my_model)
    print(agent.ask(df, "What is total amount?").answer)
"""

from .translator import summarize
from .bodyguard import (run_safely, SafetyError, check_code, CodeCheck,
                        k_anonymize)
from .agent import Agent, AgentResult, build_prompt
from .report import report
from .wrap import wrap, extract_code, ModelError
from .tokens import token_savings, token_stats, estimate_tokens
from .pii import redact_text
from .analysis import (validate, Issue, suggest_fixes, explain_issue,
                       quality_score, ai_readiness, privacy_report,
                       infer_columns, build_safe_prompt, create_contract,
                       ai_risk_score, detect_ai_traps, shadow, enable_presidio)
from .firewall import (create_privacy_plan, make_safe_view, safe_answer,
                       PrivacyPlan, detect_operation)
from .policy import Policy
from .integrations import to_pandera_schema, to_great_expectations_suite

__version__ = "1.0.9"
__all__ = ["Agent", "AgentResult", "summarize", "run_safely",
           "SafetyError", "check_code", "CodeCheck", "k_anonymize",
           "build_prompt", "report",
           "wrap", "extract_code", "ModelError",
           "token_savings", "token_stats", "estimate_tokens",
           "redact_text",
           # structured analysis layer
           "validate", "Issue", "suggest_fixes", "explain_issue",
           "quality_score", "ai_readiness", "privacy_report",
           "infer_columns", "build_safe_prompt", "create_contract",
           "ai_risk_score", "detect_ai_traps", "shadow", "enable_presidio",
           # query-aware privacy firewall
           "create_privacy_plan", "make_safe_view", "safe_answer",
           "PrivacyPlan", "detect_operation", "Policy",
           "to_pandera_schema", "to_great_expectations_suite"]
