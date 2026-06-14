"""
Library-specific exceptions.

Public functions raise a SafedataError (or a subclass), never a bare Python
error, so callers can write one `except safedata.SafedataError` and catch
everything this library can raise. The engine's older SafetyError is a subclass
of SafedataError too, so guarded-execution blocks are caught the same way.
"""


class SafedataError(Exception):
    """Base class for every error this library raises on purpose."""


class PolicyError(SafedataError):
    """An invalid policy or an unknown profile name."""


class PrivacyError(SafedataError):
    """A privacy rule was violated (e.g. a request would expose individuals)."""


class UnsafeRequestError(SafedataError):
    """The request itself is unsafe under the active policy (raw rows/export)."""


class SafePlanValidationError(SafedataError):
    """The model's analysis plan failed validation before execution."""


class ModelAdapterError(SafedataError):
    """The model object/callable could not be called or returned nothing usable."""


class DataValidationError(SafedataError):
    """The input DataFrame or question is missing/invalid."""
