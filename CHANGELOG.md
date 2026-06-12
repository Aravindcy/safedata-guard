# Changelog

All notable changes to **safedata-guard** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.8]

### Security
- **Closed a `str.format`/`str.format_map` information-disclosure bypass.** A
  format template like `'{0.__init__.__globals__}'.format(df)` performs attribute
  traversal inside the string literal — invisible to the AST screen — and could
  read a reachable module's globals (config, secrets) into the result. The static
  screen now inspects `.format`/`.format_map` calls: it refuses fields that reach
  into the argument (`{0.attr}` / `{0[key]}`) and refuses non-literal templates it
  cannot inspect. Plain formatting (`'{:.2f}'.format(x)`) still works; use an
  f-string for anything richer.

### Fixed
- **Editable installs.** Declare the package explicitly (`[tool.setuptools]
  packages = ["safedata"]`) instead of `packages.find`, so `pip install -e .`
  from the repo root can't be treated as a namespace package (which could leave
  `safedata.__file__` None and the API unimportable).

### Changed
- Added per-version Python classifiers (3.8–3.13) so PyPI shows the supported
  versions. Docker runner image tag bumped to `1.0.8`.

## [1.0.7]

### Added
- **Container isolation mode.** `run_safely(..., isolation="docker")` and
  `Agent(..., isolation="docker")` run generated code inside a throwaway
  container with no network, a read-only root filesystem, and memory/CPU limits
  — a real boundary for genuinely untrusted model output. Tune with
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
