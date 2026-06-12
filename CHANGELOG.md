# Changelog

All notable changes to **safedata-guard** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.8]

### Security / Privacy
- **`Agent.ask()` now withholds PII columns from the prompt by default.** It
  previously sent `summarize(df)` with raw samples, so name/address columns
  (which regex masking can't catch) leaked to the model and into the audit
  report. It now masks detected PII columns' values (new `mask_prompt_pii=True`
  default; set False to opt out). Column names/types are still shown, so the
  model can still operate on them.
- **`redact_result_pii` is now deep and name-aware.** It fully redacts PII
  columns of a returned DataFrame/Series (catching `customer_name`, not just
  regex-matchable emails) and recurses into dict/list/tuple/set results,
  redacting values under PII-looking keys. `product_name` and other non-personal
  fields are left untouched.

### Added
- **`Agent.safe()` / `Agent.strict()` presets.** One call gives the secure
  configuration: result-size caps + PII redaction + process isolation (`safe`)
  or full container isolation (`strict`). Any keyword overrides the preset.
- **`create_contract(df)` — a Data Safety Contract.** A machine-readable policy
  derived from the read-only heuristics: allowed/blocked columns, data traps the
  model must account for, allowed/blocked operations, column types, and a privacy
  level. A declarative policy layer for AI access to a dataset.
- **`AgentResult.audit_report(path=None)`.** Renders a self-contained HTML audit
  of one `agent.ask()`: question, exact summary sent, every attempt (and why any
  were blocked), final code/answer, data-quality warnings, withheld PII columns,
  and token saving.

### Fixed
- **Object-cell mutation.** `run_safely(..., isolate=False)` could mutate the
  caller's original DataFrame when a cell held a mutable object (e.g. a list),
  because `.copy(deep=True)` (and `copy.deepcopy`, which pandas delegates to it)
  don't copy cell objects. The in-process copy now deep-copies object-column
  cells. (Default `isolate=True` was already safe via pickling.)
- **Clear errors on bad input.** `run_safely` now raises a `TypeError` naming the
  bad type when `df` isn't a DataFrame, instead of an opaque `AttributeError`
  (or `KeyError: 'out'` on the threaded fallback); worker-thread exceptions now
  propagate to the caller.

### Security
- **Hardened the docker command** so values spliced into `sh -c` (result_var,
  pip target) are `shlex.quote`-escaped, removing a shell-injection avenue.

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
