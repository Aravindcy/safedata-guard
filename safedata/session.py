"""
SafeSession: a per-conversation privacy guard on top of safe_query.

Most privacy tools protect one answer at a time. A sequence of individually-safe
answers can still leak: "average order value in London" (n=100) followed by
"average order value in London excluding customer X" (n=99) lets you recover X,
even though each query passes k-anonymity on its own. SafeSession adds two coarse
guards across the whole conversation:

  1. A structural DIFFERENCING check: it blocks a query that reuses the same
     operation + group_by + metrics as an earlier one but tightens the filter
     set (the shape of a difference attack). This is exact for that pattern.
  2. A keyword PRIVACY BUDGET: each question is assigned a heuristic cost (raw/
     narrow/high-risk wording, naming a PII column); when the running total
     exceeds the budget, further questions are blocked.

Honest scope: this is a practical heuristic, NOT differential privacy. The
budget costs are word-based and approximate; the differencing check only catches
same-shape narrowing, not every correlation across differently-shaped queries.
For formal guarantees use a differential-privacy library (e.g. OpenDP). Budget
and per-category costs are configurable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Any

from .analysis import _as_pandas, privacy_report
from .policy import Policy
from .safeplan import prepare_safeplan, execute_prepared


DEFAULT_COSTS = {
    "base": 1,
    "raw": 4,        # show/list/all rows/raw/export/email/name
    "narrow": 2,     # where/excluding/except/only/specific/customer
    "high_risk": 2,  # highest/lowest/top/bottom/exact
    "pii_column": 3, # the question names a detected PII column
}

_RAW_WORDS = ["show", "list", "all rows", "raw", "export", "email", "name"]
_NARROW_WORDS = ["where", "excluding", "except", "only", "specific", "customer",
                 "without", "remove", "not including"]
_HIGH_RISK_WORDS = ["highest", "lowest", "top", "bottom", "exact"]


@dataclass
class SessionEvent:
    question: str
    cost: int
    operation: Optional[str]
    columns_used: List[str]
    blocked: bool
    reason: Optional[str]
    plan_signature: Optional[tuple] = None
    plan_signature_filters: Optional[set] = None


def estimate_question_cost(question: str, pii_columns, costs=None) -> int:
    costs = costs or DEFAULT_COSTS
    q = question.lower()
    cost = costs["base"]
    if any(w in q for w in _RAW_WORDS):
        cost += costs["raw"]
    if any(w in q for w in _NARROW_WORDS):
        cost += costs["narrow"]
    if any(w in q for w in _HIGH_RISK_WORDS):
        cost += costs["high_risk"]
    for col in pii_columns:
        if col.lower() in q:
            cost += costs["pii_column"]
    return cost


def _plan_signature(plan):
    """Shape of a plan, ignoring filter VALUES, for differencing comparison."""
    metrics = frozenset((m.column, m.agg) for m in plan.metrics)
    group_by = frozenset(plan.group_by)
    filter_cols = frozenset((f.get("column"), f.get("op")) for f in plan.filters)
    return (plan.operation, group_by, metrics, filter_cols, len(plan.filters))


_RANGE_OPS = {">", ">=", "<", "<=", "!="}


def _filter_set(filters):
    return {(f.get("column"), f.get("op"), repr(f.get("value"))) for f in filters}


def _differencing_pair(new_set, old_set):
    """Decide whether two filter sets over the SAME aggregate form a differencing
    pair. We flag genuine narrowing/threshold-shifts, NOT disjoint siblings.

      - identical sets        -> not a differencing pair (same question twice)
      - one a strict subset   -> a constraint was added/removed (narrow/widen)
      - same equality context
        but a range/exclusion
        constraint differs    -> threshold shift / added exclusion on same base
      - otherwise (e.g. city==London vs city==Dublin, disjoint equality) -> no
    """
    if new_set == old_set:
        return False
    if new_set < old_set or old_set < new_set:
        return True
    new_eq = {(c, v) for (c, op, v) in new_set if op == "=="}
    old_eq = {(c, v) for (c, op, v) in old_set if op == "=="}
    new_range = {(c, op, v) for (c, op, v) in new_set if op in _RANGE_OPS}
    old_range = {(c, op, v) for (c, op, v) in old_set if op in _RANGE_OPS}
    if new_eq == old_eq and new_range != old_range:
        return True
    return False


def _is_differencing(new_plan, history):
    """True if `new_plan` reuses the same operation/group_by/metrics as a prior
    plan and narrows or shifts the filtered population (a difference attack).
    Disjoint sibling queries (same shape, different equality value) are allowed."""
    new_op, new_g, new_m, _, _ = _plan_signature(new_plan)
    new_set = _filter_set(new_plan.filters)
    for ev in history:
        if ev.blocked or ev.plan_signature is None:
            continue
        op, g, m, _, _ = ev.plan_signature
        if op == new_op and g == new_g and m == new_m:
            if _differencing_pair(new_set, ev.plan_signature_filters):
                return True
    return False


@dataclass
class SafeSession:
    df: Any
    model: Any
    policy: Optional[Policy] = None
    budget: int = 10
    costs: dict = field(default_factory=lambda: dict(DEFAULT_COSTS))
    used: int = 0
    events: List[SessionEvent] = field(default_factory=list)

    def __post_init__(self):
        self.policy = self.policy or Policy.regulated()
        self.pii_columns = privacy_report(
            _as_pandas(self.df), scan_rows=self.policy.pii_scan_rows)["pii_columns"]

    def _record(self, event):
        self.events.append(event)

    def ask(self, question: str) -> dict:
        cost = estimate_question_cost(question, self.pii_columns, self.costs)

        # 1. Budget check (before spending a model call).
        if self.used + cost > self.budget:
            ev = SessionEvent(question, cost, None, [], True,
                              "Blocked: session privacy budget exceeded.")
            self._record(ev)
            return {"blocked": True, "reason": ev.reason, "answer": None,
                    "used_budget": self.used,
                    "remaining_budget": max(self.budget - self.used, 0)}

        # 2. Get a validated plan WITHOUT executing it, so the differencing
        #    check can block before any data is read/filtered.
        prepared = prepare_safeplan(self.df, question, model=self.model,
                                    policy=self.policy)

        # 3. Structural differencing check on the (not-yet-executed) plan.
        if prepared.plan is not None and _is_differencing(prepared.plan, self.events):
            ev = SessionEvent(
                question, cost, prepared.plan.operation, [], True,
                "Blocked: repeated narrowing of the same aggregate may reveal "
                "individual-level information (differencing attack).")
            ev.plan_signature = _plan_signature(prepared.plan)
            ev.plan_signature_filters = _filter_set(prepared.plan.filters)
            self._record(ev)
            return {"blocked": True, "reason": ev.reason, "answer": None,
                    "used_budget": self.used,
                    "remaining_budget": max(self.budget - self.used, 0)}

        # 4. Only now execute the validated plan.
        result = execute_prepared(prepared)

        self.used += cost
        cols = []
        sig = None
        if result.plan is not None:
            cols = list(result.plan.group_by) + [m.column for m in result.plan.metrics]
            sig = _plan_signature(result.plan)
        ev = SessionEvent(question, cost,
                          result.plan.operation if result.plan else None,
                          cols, result.blocked, result.reason)
        ev.plan_signature = sig
        ev.plan_signature_filters = _filter_set(
            result.plan.filters if result.plan else [])
        self._record(ev)
        return {"answer": result.answer, "receipt": result.receipt,
                "blocked": result.blocked, "reason": result.reason,
                "used_budget": self.used,
                "remaining_budget": self.budget - self.used}
