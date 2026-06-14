"""
Guard: a reusable, configured front door.

    guard = sd.Guard(profile="banking", model=my_model)
    report = guard.scan(df)
    result = guard.ask(df, "average balance by region")
    safe_df = guard.protect(df, question="average balance by region")
    session = guard.session(df)            # multi-turn, privacy-budgeted

Guard holds the profile/policy and model once, so you do not repeat them on
every call. It delegates to the same ask/scan/protect functions.
"""

from __future__ import annotations

from typing import Optional

from .policy import Policy
from .results import Result, ScanReport
from . import api


class Guard:
    def __init__(self, profile: str = "general", policy: Optional[Policy] = None,
                 model=None, config: Optional[dict] = None):
        self.policy = policy or Policy.from_profile(profile)
        self.profile = self.policy.profile
        self.model = model
        self.config = dict(config or {})

    def ask(self, df, question: str, mode: str = "auto") -> Result:
        return api.ask(df, question, model=self.model, policy=self.policy,
                       mode=mode)

    def scan(self, df, deep: bool = True) -> ScanReport:
        return api.scan(df, policy=self.policy, deep=deep)

    def protect(self, df, question: Optional[str] = None,
                return_report: bool = False):
        return api.protect(df, question=question, policy=self.policy,
                           return_report=return_report)

    def session(self, df, budget: int = 10):
        """A multi-turn conversation with a privacy budget and differencing
        guard. Returns a SafeSession; call `.ask(question)` on it."""
        from .session import SafeSession
        fn = api._as_prompt_fn(self.model)
        return SafeSession(df, model=fn, policy=self.policy, budget=budget)

    def __repr__(self) -> str:
        return f"Guard(profile={self.profile!r})"
