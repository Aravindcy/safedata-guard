"""
Policy profiles: one object that bundles the privacy/safety settings.

The library has many individual knobs (safe_mode, isolation, max_result_rows,
min_group_size, redact_result_pii, ...). A Policy packages them into a named
profile so callers pick an intent instead of remembering flags:

    import safedata as sd

    policy = sd.Policy.banking()
    result = sd.ask(df, "total revenue by region", model=my_llm, policy=policy)

Industry profiles (the names beginners reach for):
    Policy.general()    - non-regulated data, Python fallback allowed
    Policy.energy()     - SafePlan only, k>=5
    Policy.banking()    - SafePlan only, k>=10
    Policy.insurance()  - SafePlan only, k>=10
    Policy.healthcare() - SafePlan only, k>=15
    Policy.strict()     - maximum lockdown (container isolation, Presidio, k>=20)

Legacy profiles (still used internally): basic/regulated/audit_only.
Any field can be overridden: Policy.banking(min_group_size=25).
"""

from __future__ import annotations

from dataclasses import dataclass, replace, asdict


# Industry profiles a beginner can name instead of tuning flags. Mapped onto the
# engine fields below. allow_python_fallback=False means SafePlan-only (the
# guarded-Python engine is refused) - the default for regulated industries.
_PROFILES = {
    "general":    dict(min_group_size=None, max_result_rows=100,
                       allow_python_fallback=True),
    "energy":     dict(min_group_size=5, max_result_rows=50, pii_scan_rows="all",
                       enforce_minimal_result=True, block_1d_row_results=True,
                       allow_python_fallback=False),
    "banking":    dict(min_group_size=10, max_result_rows=50, pii_scan_rows="all",
                       enforce_minimal_result=True, block_1d_row_results=True,
                       allow_python_fallback=False),
    "insurance":  dict(min_group_size=10, max_result_rows=50, pii_scan_rows="all",
                       enforce_minimal_result=True, block_1d_row_results=True,
                       allow_python_fallback=False),
    "healthcare": dict(min_group_size=15, max_result_rows=30, pii_scan_rows="all",
                       enforce_minimal_result=True, block_1d_row_results=True,
                       allow_python_fallback=False),
}


@dataclass
class Policy:
    profile: str = "general"
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
    # v1.1.0 facade fields. allow_python_fallback gates the guarded-Python engine;
    # allow_raw_rows lets a plan return individual rows (off for regulated data).
    allow_python_fallback: bool = True
    allow_raw_rows: bool = False

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
            profile="strict",
            isolation="docker",
            max_result_rows=25,
            redact_result_pii=True,
            enforce_minimal_result=True,
            block_1d_row_results=True,
            min_group_size=20,
            pii_scan_rows="all",
            use_presidio=True,
            allow_python_fallback=False,
            allow_raw_rows=False,
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

    # --- v1.1.0 industry profiles (the names beginners reach for) ----------

    @classmethod
    def general(cls, **overrides) -> "Policy":
        """Non-regulated data: SafePlan first, guarded-Python fallback allowed."""
        return cls(profile="general", **_PROFILES["general"]).with_(**overrides)

    @classmethod
    def energy(cls, **overrides) -> "Policy":
        """Energy customer data: SafePlan-only, k>=5, deep PII scan."""
        return cls(profile="energy", **_PROFILES["energy"]).with_(**overrides)

    @classmethod
    def banking(cls, **overrides) -> "Policy":
        """Banking/finance data: SafePlan-only, k>=10, deep PII scan."""
        return cls(profile="banking", **_PROFILES["banking"]).with_(**overrides)

    @classmethod
    def insurance(cls, **overrides) -> "Policy":
        """Insurance data: SafePlan-only, k>=10, deep PII scan."""
        return cls(profile="insurance", **_PROFILES["insurance"]).with_(**overrides)

    @classmethod
    def healthcare(cls, **overrides) -> "Policy":
        """Healthcare data: SafePlan-only, k>=15, smallest result caps."""
        return cls(profile="healthcare", **_PROFILES["healthcare"]).with_(**overrides)

    @classmethod
    def from_profile(cls, profile: str, **overrides) -> "Policy":
        """Build a Policy from a profile name. Raises PolicyError if unknown."""
        from .exceptions import PolicyError
        builders = {"general": cls.general, "energy": cls.energy,
                    "banking": cls.banking, "insurance": cls.insurance,
                    "healthcare": cls.healthcare, "strict": cls.strict,
                    "basic": cls.basic, "regulated": cls.regulated,
                    "audit_only": cls.audit_only}
        if profile not in builders:
            raise PolicyError(
                f"Unknown profile '{profile}'. Choose one of {sorted(builders)}.")
        return builders[profile](**overrides)

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
