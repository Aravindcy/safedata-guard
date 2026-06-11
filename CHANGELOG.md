# Changelog

All notable changes to **safedata-guard** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.7]

### Added
- **Container isolation mode.** `run_safely(..., isolation="docker")` and
  `Agent(..., isolation="docker")` run generated code inside a throwaway
  container with no network, a read-only root filesystem, and memory/CPU limits
  â€” a real boundary for genuinely untrusted model output. Tune with
  `docker_image=`, `memory=`, `cpus=`, `network=`.
- **Result guards.** `max_result_rows`, `max_result_bytes`, and
  `redact_result_pii` on `run_safely`/`Agent` cap the size of the returned value
  and scrub PII from it, preventing accidental full-data leakage after execution.

### Fixed
- **Scoping of generated code.** Code now runs in a single shared namespace, so a
  module-level variable is visible inside a function/lambda/comprehension defined
  in the same snippet (previously raised `NameError`).
- **Static screen** now also rejects bare dunder *names* (e.g. `__build_class__`),
  not only dunder attributes.

### Changed
- `excel` extra now includes `xlrd>=2.0` for legacy `.xls` files.
- Documented that the HTML `report()` supports pandas; other APIs support pandas
  and Polars.

## [1.0.6]
- Baseline release on PyPI.
