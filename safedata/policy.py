"""
Policy profiles: one object that bundles the privacy/safety settings.

The library has many individual knobs (safe_mode, isolation, max_result_rows,
min_group_size, redact_result_pii, ...). A Policy packages them into a named
profile so callers pick an intent instead of remembering flags:

    import safedata as sd

    policy = sd.Policy.regulated()
    out = sd.safe_answer(df, "total revenue by region", model=my_llm, policy=policy)

Profiles:
    Policy.basic()      - sensible defaults for non-sensitive data
    Policy.regulated()  - for customer/PII data (k-anonymity, deep PII scan)
    Policy.strict()     - maximum lockdown (container isolation, Presidio)
    Policy.audit_only()  - permissive run + full audit, for trying things out

Any field can be overridden: Policy.regulated(min_group_size=10).
"""

from __future__ import annotations

from dataclasses import dataclass, replace, asdict


@dataclass(frozen=True)
class Policy:
    safe_mode: str = "drop_unneeded_pii"
    isolation: str = "process"
    max_result_rows: int = 50
    max_result_bytes: int = 1_000_000
    redact_result_pii: bool = True
    enforce_minimal_result: bool = False
    block_1d_row_results: bool = False
    min_group_size: "int | None" = None
    pii_scan_rows: "int | str" = 20
    use_presidio: bool = False

    def with_(self, **overrides) -> "Policy":
        """Return a copy with some fields replaced."""
        return replace(self, **overrides)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def basic(cls, **overrides) -> "Policy":
        """Sensible guardrails for non-sensitive data."""
        return cls(
            max_result_rows=100,
            redact_result_pii=True,
            enforce_minimal_result=False,
            block_1d_row_results=False,
            min_group_size=None,
        ).with_(**overrides)

    @classmethod
    def regulated(cls, **overrides) -> "Policy":
        """For customer/PII data: deep PII scan, result caps, k-anonymity."""
        return cls(
            max_result_rows=50,
            redact_result_pii=True,
            enforce_minimal_result=True,
            block_1d_row_results=True,
            min_group_size=5,
            pii_scan_rows="all",
        ).with_(**overrides)

    @classmethod
    def strict(cls, **overrides) -> "Policy":
        """Maximum lockdown: container isolation, deep scan, Presidio, k>=10.

        Requires Docker (isolation='docker') and the optional Presidio install;
        both degrade gracefully if absent (Presidio is skipped, Docker raises a
        clear error telling you to set it up or drop to isolation='process')."""
        return cls(
            isolation="docker",
            max_result_rows=25,
            redact_result_pii=True,
            enforce_minimal_result=True,
            block_1d_row_results=True,
            min_group_size=10,
            pii_scan_rows="all",
            use_presidio=True,
        ).with_(**overrides)

    @classmethod
    def audit_only(cls, **overrides) -> "Policy":
        """Permissive execution with redaction on, for exploration + audit."""
        return cls(
            max_result_rows=50,
            redact_result_pii=True,
            enforce_minimal_result=False,
            block_1d_row_results=False,
            min_group_size=None,
        ).with_(**overrides)

    def agent(self, model, **overrides):
        """Build an Agent configured from this policy (a convenience bridge)."""
        from .agent import Agent
        opts = dict(
            isolation=self.isolation,
            max_result_rows=self.max_result_rows,
            max_result_bytes=self.max_result_bytes,
            redact_result_pii=self.redact_result_pii,
            enforce_minimal_result=self.enforce_minimal_result,
            block_1d_row_results=self.block_1d_row_results,
            min_group_size=self.min_group_size,
            pii_scan_rows=self.pii_scan_rows,
            column_firewall=True,
        )
        opts.update(overrides)
        return Agent(model, **opts)
