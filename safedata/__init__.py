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
from .bodyguard import run_safely, SafetyError, check_code, CodeCheck
from .agent import Agent, AgentResult, build_prompt
from .report import report
from .wrap import wrap, extract_code, ModelError
from .tokens import token_savings, token_stats, estimate_tokens
from .pii import redact_text
from .analysis import (validate, Issue, suggest_fixes, explain_issue,
                       quality_score, ai_readiness, privacy_report,
                       infer_columns, build_safe_prompt, create_contract,
                       ai_risk_score, detect_ai_traps, shadow)

__version__ = "1.0.8"
__all__ = ["Agent", "AgentResult", "summarize", "run_safely",
           "SafetyError", "check_code", "CodeCheck", "build_prompt", "report",
           "wrap", "extract_code", "ModelError",
           "token_savings", "token_stats", "estimate_tokens",
           "redact_text",
           # structured analysis layer
           "validate", "Issue", "suggest_fixes", "explain_issue",
           "quality_score", "ai_readiness", "privacy_report",
           "infer_columns", "build_safe_prompt", "create_contract",
           "ai_risk_score", "detect_ai_traps", "shadow"]
