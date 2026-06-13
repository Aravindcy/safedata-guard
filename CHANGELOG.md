# Changelog

All notable changes to **safedata-guard** are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.9]

### Fixed
- **`Agent.ask` now accepts a raw text-in/text-out LLM directly.** It previously
  required the model to return bare code, so a real LLM's ```python-fenced reply
  caused a "syntax error" block until you wrapped it with `safedata.wrap()`. Agent
  now runs the model output through `extract_code` (a wrapped model still passes
  through cleanly), matching `safe_answer`'s behaviour. Found in live testing.

### Added
- **Query-aware privacy firewall** (`safedata.firewall`): `create_privacy_plan`,
  `make_safe_view`, `safe_answer`, plus `PrivacyPlan` and `detect_operation`.
  For a given question it builds the *minimum safe view* of the data, runs the
  analysis only on that view, and returns an audit of what was dropped.
  - `safe_mode="drop_unneeded_pii"` (**default**): drop the PII columns the
    question doesn't need, **keep every non-PII column** — strong privacy with no
    risk of dropping a column the analysis needed (so no wrong answers). The
    unneeded PII values are simply not present in the view the model/code sees.
  - `safe_mode="minimal"` (opt-in, advanced): also drop non-PII columns the
    question doesn't reference. Stronger, but relevance is heuristic, so it
    carries a warning and is never the default.
  - `safe_answer` is self-correcting: a guardrail block (e.g. too many rows) is
    fed back to the model and retried (like `Agent.ask`); it returns
    `blocked=True` with a reason instead of raising.
  - Private surrogate filters and k-anonymity/min-group-size suppression are
    deliberately deferred until they can be implemented and tested properly.

## [1.0.8]

### Security / Privacy
- **PII name detection now splits camelCase/PascalCase.** `FullName`,
  `CustomerName`, `EmailAddress` are now recognised like their snake_case forms.
- **Card numbers stored as integers are detected via the Luhn checksum.** A
  CSV/Excel import that inferred a card column as numeric is now flagged, without
  false-flagging ordinary long integers (random long ints don't pass Luhn). Added
  `safedata.pii.luhn_ok()` and card/account name hints.
- **`quality_score` no longer looks "Good" when PII is present.** It now returns
  `safe_to_send_raw` and an `ai_readiness` verdict that folds in `privacy_risk`
  (e.g. "Needs Review" when privacy risk is High), so a clean-but-sensitive table
  isn't mistaken for safe-to-send.
- **CLI `check` output is now privacy-aware by default.**

### Fixed
- **`Agent.safe(model, isolate=False)` is honored.** The presets set
  `isolation="process"`, which used to silently override an explicit
  `isolate=False`; now passing `isolate=False` (without an explicit `isolation=`)
  drops the preset isolation so in-process execution actually takes effect.
- **Test timeouts.** Added `pytest-timeout` (`timeout = 60` in config) and a
  `slow` marker on subprocess/docker tests, so a wedged isolation test fails
  loudly instead of stalling a full run. It previously regex-
  masked emails but still printed name/address samples; it now fully withholds
  detected PII columns (`--no-redact` opts out).
- **`scan_rows` threads through the privacy-aware APIs.** `ai_risk_score`,
  `create_contract`, `build_prompt`, `quality_score`, and `ai_readiness` take
  `scan_rows=N|"all"`, `Agent(...)` takes `pii_scan_rows`, and `safedata
  check`/`risk` gain `--pii-scan-rows/--pii-scan-all` — so rare PII past the fast
  default window is caught consistently everywhere, not just in `privacy_report`.
- **`Agent.strict()` now blocks 1-D per-row results** (`block_1d_row_results`):
  a Series/list with one value per input row (e.g. `df['name'].tolist()`) is
  refused in strict mode, closing a row-level leak that the full-width-only
  minimisation allowed. Off elsewhere (it can false-flag a groupby with N groups).
- **Column firewall is now enforced at runtime, not just statically.** The AST
  screen couldn't see positional/indirect access (`df.iloc[:, 0]`, `df.values`,
  `df.to_numpy()`, `df.columns[0]`), so blocked columns could leak. Blocked
  columns are now **blanked to `[RESTRICTED_*]` in the execution copy** before the
  code runs, so no access path can read them. (The static screen still blocks
  direct `df['col']` for a clear retry message.)
- **Result size caps and minimisation now see past `to_dict`/`to_numpy`.**
  `max_result_rows` and `enforce_minimal_result` count rows for list/tuple/
  dict-of-columns/records/ndarray results too, so converting a frame to a list
  of dicts no longer dodges the cap. (Minimisation only flags full-width row-
  level shapes, never a 1-D aggregate that coincidentally has N entries.)
- **`redact_result_pii` now also scrubs numpy string arrays** (regex PII).
- **`Agent.strict()` enables `enforce_minimal_result`** (lockdown); `safe()`
  leaves it off so legitimate full-table requests aren't surprised.
- **Deeper PII scanning on demand.** `privacy_report(df, scan_rows=N | "all")`
  (and `safedata check --pii-scan-rows N` / `--pii-scan-all`) inspect more unique
  values per column to catch PII that hides past the fast default window.
- **`Agent.ask()` now withholds PII columns from the prompt by default.** It
  previously sent `summarize(df)` with raw samples, so name/address columns
  (which regex masking can't catch) leaked to the model and into the audit
  report. It now masks detected PII columns' values (new `mask_prompt_pii=True`
  default; set False to opt out). Column names/types are still shown, so the
  model can still operate on them.
- **`build_prompt(df, ...)` masks PII by default.** Called directly on a
  DataFrame it used plain `summarize(df)` and could leak name/address samples;
  it now withholds detected PII columns (new `mask_pii=True` default). A summary
  string is still used verbatim.
- **`redact_result_pii` is now deep and name-aware.** It fully redacts PII
  columns of a returned DataFrame/Series (catching `customer_name`, not just
  regex-matchable emails) and recurses into dict/list/tuple/set results,
  redacting values under PII-looking keys. `product_name` and other non-personal
  fields are left untouched.

### Added
- **Question-aware column firewall.** `create_contract(df, question)` now
  returns `blocked_columns` = the PII columns the question doesn't reference, and
  `run_safely(..., blocked_columns=[...])` refuses generated code that touches
  them (by subscript or attribute). `Agent.safe()`/`strict()` enable it by
  default — least-privilege access, not just redaction. Only PII columns are
  firewalled, so a legitimate aggregate is never blocked for not naming a column.
- **Result-minimisation guard.** `run_safely(..., enforce_minimal_result=True)`
  (and `Agent(enforce_minimal_result=True)`) blocks a result that returns the
  full, unaggregated input frame.
- **`ai_risk_score(df, question=None)`** — a 0..100 risk score with reasons and a
  recommended mode, composed from the PII/quality signals. Also `safedata risk
  <file> [question]` on the CLI (exit 2 on high risk, to gate pipelines).
- **`detect_ai_traps(df)`** — the data traps that make an AI answer *wrong*
  (text-numeric, dates-as-text, Excel serials, messy categories, …), each with a
  short instruction for the model.
- **`shadow(df)`** — a synthetic DataFrame with the same columns/types but no real
  values (typed fakes for PII, cardinality-preserving labels otherwise), for
  testing generated code or sharing a dataset's shape safely.
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
- **Test suite exits cleanly in subprocess-restricted sandboxes.** The two
  infinite-loop timeout tests now `skip` when a Python subprocess can't be
  spawned — otherwise `isolate=True` falls back to an unkillable in-process
  thread spinning `while True`, which could wedge interpreter shutdown. CI also
  has a per-step `timeout-minutes` guard. (CI itself runs the full suite green.)
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
