"""
Typed return objects for the public API.

Every public function returns a predictable dataclass instead of a loose dict:

    sd.ask(...)     -> Result   (has .answer, .receipt, .ok, .blocked)
    sd.scan(...)    -> ScanReport
    sd.protect(..., return_report=True) -> (DataFrame, ProtectReport)

Receipt is the audit trail attached to every ask().
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional


@dataclass
class Receipt:
    """A per-answer audit record. Attached to every Result from sd.ask()."""
    audit_id: str
    timestamp: str
    profile: str
    engine: str
    mode: str
    row_count: int
    column_count: int
    safe_columns: List[str] = field(default_factory=list)
    dropped_columns: List[str] = field(default_factory=list)
    masked_columns: List[str] = field(default_factory=list)
    pii_columns: List[str] = field(default_factory=list)
    sensitive_columns: List[str] = field(default_factory=list)
    min_group_size: Optional[int] = None
    max_result_rows: int = 50
    python_fallback_used: bool = False
    raw_rows_exposed: bool = False
    blocked_operations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        """Human-readable one-screen rendering of the receipt."""
        lines = [
            "Data Safety Receipt",
            "-" * 19,
            f"Audit ID:            {self.audit_id}",
            f"Profile / engine:    {self.profile} / {self.engine} (mode={self.mode})",
            f"Data:                {self.row_count} rows x {self.column_count} cols",
            f"PII detected:        {self.pii_columns}",
            f"Sensitive detected:  {self.sensitive_columns}",
            f"Dropped columns:     {self.dropped_columns}",
            f"Masked columns:      {self.masked_columns}",
            f"Min group size:      {self.min_group_size}",
            f"Python fallback:     {self.python_fallback_used}",
            f"Raw rows exposed:    {self.raw_rows_exposed}",
        ]
        if self.warnings:
            lines.append(f"Warnings:            {self.warnings}")
        return "\n".join(lines)


@dataclass
class Result:
    """What sd.ask() returns. `.answer` is the analysis output, `.receipt` the
    audit trail. `.ok` is True when an answer was produced and not blocked."""
    answer: Any
    data: Any
    receipt: Receipt
    engine: str
    blocked: bool = False
    reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (not self.blocked) and self.answer is not None

    def __repr__(self) -> str:
        head = "blocked" if self.blocked else "ok"
        return (f"Result({head}, engine={self.engine!r}, "
                f"audit_id={self.receipt.audit_id!r})")


@dataclass
class ScanReport:
    """What sd.scan() returns: privacy categories, quality, and AI-readiness."""
    rows: int
    columns: int
    risk_level: str
    pii_columns: List[str] = field(default_factory=list)
    sensitive_columns: List[str] = field(default_factory=list)
    business_identifier_columns: List[str] = field(default_factory=list)
    financial_columns: List[str] = field(default_factory=list)
    health_columns: List[str] = field(default_factory=list)
    location_columns: List[str] = field(default_factory=list)
    free_text_columns: List[str] = field(default_factory=list)
    quality_issues: List[dict] = field(default_factory=list)
    ai_readiness_score: int = 0
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProtectReport:
    """Returned by sd.protect(..., return_report=True) alongside the safe frame."""
    kept_columns: List[str] = field(default_factory=list)
    dropped_columns: List[str] = field(default_factory=list)
    masked_columns: List[str] = field(default_factory=list)
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
