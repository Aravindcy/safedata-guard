# safedata-guard

[![CI](https://github.com/Aravindcy/safedata-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Aravindcy/safedata-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safedata-guard.svg)](https://pypi.org/project/safedata-guard/)
[![Python versions](https://img.shields.io/pypi/pyversions/safedata-guard.svg)](https://pypi.org/project/safedata-guard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight framework for safely letting LLMs analyze pandas/Polars data
without exposing raw rows or blindly running the code they generate.

Most "chat with your data" tools send the whole table to the model and run
whatever code it writes, unchecked. safedata-guard fixes both halves: it sends a
compact, **quality-aware summary** instead of raw rows, and runs the model's code
behind **guardrails on a copy** of your data.

> **Status: beta.** Useful and tested, but treat it as a defense-in-depth safety
> *layer*, not a hardened sandbox. It is **not** a "fully secure sandbox",
> "compliance-grade PII protection", or "guaranteed safe execution" - PII
> detection and code screening are best-effort heuristics (see *Scope* below).
> For untrusted code, run it inside OS-level isolation (`isolation="docker"` or
> your own container/VM).

## Documentation

- **This README** - the pitch, the two execution modes, and a quick start.
- **[SECURITY.md](SECURITY.md)** - threat model, what it defends against, and the
  known limitations (read before relying on it).
- **[docs/examples.md](docs/examples.md)** - worked examples across banking,
  insurance, energy, healthcare, sales, and complaints data.
- **[BENCHMARKS.md](BENCHMARKS.md)** - measured privacy-leak rates vs plain
  LLM-generated code, with methodology and honest caveats.
- **[CHANGELOG.md](CHANGELOG.md)** - what changed in each release.

## The recommended path

Pick a **policy** for your data and use `safe_query` (SafePlan mode) for normal
analysis: the model returns a restricted JSON plan that safedata validates and
executes itself, so no generated Python runs.

```python
import safedata as sd

policy = sd.Policy.regulated()   # PII firewall + redaction + k-anonymity + caps

res = sd.safe_query(df, "What is total revenue by region?",
                    model=my_llm, policy=policy)
print(res.answer)
print(res.receipt)               # Data Safety Receipt: no Python run, PII dropped
```

Use `safe_answer` (guarded-Python mode) only when the analysis cannot be
expressed as a SafePlan operation. It builds the minimum safe view, runs the
model's code behind the guardrails, and returns the answer plus an audit:

```python
out = sd.safe_answer(df, "What is total revenue by region?",
                     model=my_llm, policy=policy)
print(out["answer"], out["audit"])
```

Profiles: `Policy.basic()`, `Policy.regulated()` (customer/PII data),
`Policy.strict()` (container isolation + Presidio), `Policy.audit_only()`. Any
field can be overridden: `Policy.regulated(min_group_size=10)`.

> **`Policy.strict()` needs Docker** (`isolation="docker"`, a prebuilt runner
> image) **and the optional Presidio install** (`use_presidio=True`). Both
> degrade gracefully if absent - Presidio is skipped, and Docker raises a clear
> error - but if you want strong defaults **without** Docker, use
> `Policy.regulated()` (process isolation, k-anonymity, deep PII scan).

`safe_query` + `Policy` is the recommended entry point for normal analysis, with
`safe_answer` as the guarded-Python fallback. The pieces below (`Agent`,
`run_safely`, `create_contract`, `privacy_report`, ...) are the lower-level
building blocks they are composed from, for when you need finer control.

## Two execution modes

safedata-guard can run AI analysis two ways:

1. **SafePlan mode (`safe_query`, safest).** The model never writes Python. It
   returns a restricted **JSON analysis plan** (operation + group-by + metrics +
   filters), which safedata validates and **executes itself** with a fixed
   interpreter. There is no generated code to escape, so the whole class of
   code-injection/exfiltration risk does not apply. Covers aggregate, group-by,
   counts, value_counts, and describe. k-anonymity is built in (we control the
   execution, so the group count always exists).

   ```python
   res = safedata.safe_query(df, "total revenue by region",
                             model=my_llm, policy=safedata.Policy.regulated())
   print(res.answer)
   print(res.receipt)        # Data Safety Receipt: PII dropped, no Python run, ...
   ```

2. **Guarded Python mode (`safe_answer` / `Agent`).** For richer/custom analysis
   the model *does* write Python, and safedata screens it (AST checks, isolation,
   result guards). Use this when SafePlan's operations aren't enough.

Every answer can carry a **Data Safety Receipt** (`res.receipt`,
`safedata.format_receipt`): an audit id, the mode, whether any Python ran, which
PII was detected/dropped, the policy in force, and the answer's shape.

## Privacy tooling around the query

Three optional helpers harden the SafePlan flow. Each is honestly a best-effort
heuristic, not a guarantee:

- **ShadowFrame** (`safedata.create_shadowframe`) builds a fully synthetic,
  same-shape stand-in (matching dtypes, ranges, cardinality, missingness, and PII
  flags). `safe_query` uses it by default (`use_shadow=True`) so the model sees a
  synthetic sample, not real cell values. The schema and aggregate stats are still
  real, so this de-identifies the prompt rather than hiding the data's structure.

- **LeakScore** (`safedata.leak_test`) runs a battery of attack prompts and scores
  0-100 by checking whether real PII values appear in the answers. A cooperative
  LLM through SafePlan usually scores ~100 (the defences hold by construction), so
  its discriminating value is with a simulated malicious model or the Python path.

  ```python
  report = safedata.leak_test(df, model=my_llm, policy=safedata.Policy.strict())
  print(report.score, report.risk_level)
  ```

- **SafeSession** (`safedata.SafeSession`) guards a whole conversation: it blocks
  reusing the same aggregate with a tightened filter (a differencing attack) and
  enforces a configurable per-question privacy budget. It is a practical heuristic,
  **not** differential privacy - for formal guarantees use a DP library.

  ```python
  s = safedata.SafeSession(df, model=my_llm, policy=safedata.Policy.regulated())
  s.ask("average order value in London")          # allowed
  s.ask("average order value in London below 500")  # blocked: differencing
  ```

## What it does

**1. Summarises before the data reaches the model.** Instead of 100,000 rows, it
sends columns, types, a few sample values, basic stats, and warnings about common
data traps: numbers stored as text (`"$500"`), the same category written several
ways (`"North"`/`"north "`), dates-as-text and Excel serial dates (`45292`),
non-unique IDs, empty/mostly-empty/constant columns, duplicate column names, and
unexpected negatives.

**2. Runs the model's code behind an AST screen.** Before running, a static
screen refuses anything outside in-memory analysis:

- imports beyond a small set (pandas, numpy, math, statistics, datetime, re)
- introspection/dunder tricks and dangerous builtins
- file/data readers and writers, **however reached**: `read_*`/`to_*`/`write_*`
  methods, file-backed classes (`ExcelFile`, `ExcelWriter`, `HDFStore`), aliases
  (`w = df.to_csv`), direct imports (`from numpy import save`), SQL readers, and
  internal helpers behind `pd.io.*` / `np.lib.*` / `np.ctypeslib` / `np.f2py`
- the `df.eval()` / `df.query()` string channels the screen can't inspect

It then runs on a **copy** of your data in a separate process with a timeout. The
model may add/transform columns freely; afterwards the guardrail checks it didn't
silently drop rows (unless `allow_row_reduction=True`) or return an empty result,
and feeds any error back so the model fixes its own code.

### Scope: please read honestly

This is **defense in depth** for cooperative or semi-trusted model output: it
stops the destructive accidents an honest model makes and the obvious escape
attempts. It is **not** a sandbox for deliberately malicious code. In-process
Python screening can be defeated, and a child process still shares your
filesystem permissions, so isolation here means timeout + crash safety, not a
filesystem jail. For untrusted code, run inside OS-level isolation (container,
locked-down user, or VM). PII masking and quality checks are best-effort
heuristics, not a compliance guarantee.

### Hardened isolation for untrusted code

The default (`isolate=True`) runs in a separate process with a timeout; crash
and hang safety, but the child still shares your filesystem permissions. For
genuinely untrusted model output, switch to container isolation:

Build the runner image once (it bundles safedata + pandas/numpy so the container
needs no network at run time; see the repo `Dockerfile`):

```bash
docker build -t safedata-guard-runner:1.1.0 .
```

```python
agent = safedata.Agent(model=..., isolation="docker",
                       memory="512m", cpus="1.0", network="none")
# or directly:
safedata.run_safely(code, df, isolation="docker")
```

The container runs with **no network**, a **read-only root filesystem**, and
**memory/CPU caps**; only a throwaway work directory is writable. The image must
already contain safedata (the locked-down defaults make a run-time `pip install`
impossible by design); point at your own with `docker_image=`.

### Guarding the result

Stop generated code from handing back the entire table (or raw sensitive rows):

```python
safedata.run_safely(code, df,
                    max_result_rows=50,        # block oversized results
                    max_result_bytes=1_000_000,
                    redact_result_pii=True)     # scrub PII from the answer
```

Oversized results are blocked with a message telling the model to aggregate,
rather than silently truncated. The same options are accepted by `Agent(...)`.

> **Limitation:** `redact_result_pii` works on DataFrames/Series (it knows the
> column) and on emails/phones in strings, but once names are flattened into a
> plain list (`df['customer_name'].tolist()`) the column context is lost and
> regex can't tell a name from any other text - so names can still leak that way.
> The robust defence is the **column firewall** (`blocked_columns=` /
> `Agent.safe()`), which masks unneeded PII columns *before* the code runs, so
> the values aren't there to leak in the first place.

### Secure presets

The secure configuration is one call away, so you don't have to remember the
flags:

```python
agent = safedata.Agent.safe(model)     # result caps + PII redaction, process isolation
agent = safedata.Agent.strict(model)   # same, but runs code in a locked-down container
```

Any keyword overrides the preset (e.g. `Agent.safe(model, timeout=30)`).

### Data Safety Contract (lower-level)

> Most users want `safe_answer` + `Policy` (above), or `create_privacy_plan()`
> (the modern firewall plan). `create_contract()` is the lower-level building
> block it composes; reach for it when you want the raw allowed/blocked policy
> without building a safe view.

Turn the read-only checks into a machine-readable policy you can gate AI access
on (no code is run). Pass the question to get a **least-privilege firewall** - the
PII columns the question doesn't need are blocked:

```python
contract = safedata.create_contract(df, question="total revenue by region")
# {"allowed_columns": ["revenue","region",...], "blocked_columns": ["email","customer_name"],
#  "data_traps": [...], "max_result_rows": 50, "privacy_level": "strict", ...}

safedata.run_safely(code, df, blocked_columns=contract["blocked_columns"])
# refuses code that touches a blocked column:
#   Blocked: the code accessed restricted column(s) the question does not need: email
```

`Agent.safe()` / `Agent.strict()` enable this firewall automatically. Add
`enforce_minimal_result=True` to also refuse a full-table answer to an aggregate
question.

### Query-aware privacy firewall (minimum safe data)

Instead of asking *"is this DataFrame safe?"*, ask *"what is the minimum safe
data needed to answer **this** question?"* The firewall builds a privacy-filtered
view, runs the analysis only on it, and returns an audit of what was dropped.

```python
plan = safedata.create_privacy_plan(df, "total revenue by region")
safe_df = safedata.make_safe_view(df, plan)        # privacy-filtered safe view
answer  = safedata.safe_answer(df, "total revenue by region", model=my_llm)
print(answer["answer"], answer["audit"])
```

**Safe by default.** `safe_mode="drop_unneeded_pii"` (the default) removes the PII
columns the question doesn't need and **keeps every non-PII column** - so the
model never sees unneeded names/emails, but the columns your analysis needs are
always present (no wrong answers). The audit explains exactly what was dropped:

> *Dropped 2 unneeded PII column(s) (customer_name, email) - never sent to the
> model. Retained 4 column(s) for analysis: ...*

`safe_mode="minimal"` is an **opt-in advanced mode** that also drops non-PII
columns the question doesn't appear to reference. It's stronger, but column
relevance is a heuristic - if it misses a column your analysis needed, the answer
can be wrong, so it carries a warning and is never the default.

### k-anonymity (stop singling-out)

A group of one re-identifies a person ("average salary by postcode" where a
postcode has one resident). Set `min_group_size` and grouped results must carry a
per-group `count`; groups below the threshold are **suppressed** - rows removed,
the figures that remain are exact (no number is fudged):

```python
safedata.run_safely(code, df, min_group_size=5)
safedata.safe_answer(df, "average salary by postcode", model=my_llm, min_group_size=5)
agent = safedata.Agent.safe(model, min_group_size=5)
# or the standalone utility on any grouped frame with a count column:
safedata.k_anonymize(grouped_df, min_group_size=5)
```

If a grouped result has no count column, it's refused with guidance (the model
adds counts and retries). *(Private surrogate filters - masking an individual
lookup behind a match flag - remain deferred until they can be done properly.)*

From the CLI, preview the safe view for a question without running anything:

```bash
safedata plan customers.csv "total revenue by region" --json
```

The plan reports `dropped_pii_columns`, `allowed_columns`, the audit, and both
`original_risk_level` and `safe_view_risk_level` (the raw frame can read "high"
while the exposed view is "low" because PII was dropped first).

### Is it safe to send this to an AI?

```python
safedata.ai_risk_score(df, "total revenue by region")
# {"risk_level": "high", "score": 65, "recommended_mode": "strict",
#  "reasons": ["High-sensitivity PII columns: email", ...]}

safedata.detect_ai_traps(df)   # traps that make an AI answer wrong, with fixes
safedata.shadow(df)            # synthetic same-shape frame, no real values
```

On the CLI: `safedata risk customers.csv "What is total revenue by region?"`
(exit code 2 on high risk, so it can gate a pipeline).

### Audit trail for an answer

Every `agent.ask()` result can write a self-contained HTML audit - the question,
the exact summary sent to the model, each attempt (and why any were blocked),
the final code/answer, data-quality warnings, withheld PII columns, and token
saving:

```python
out = agent.ask(df, "What were total sales in 2025?")
out.audit_report("audit.html")
```

## Install

```bash
pip install safedata-guard
pip install "safedata-guard[polars]"   # optional, for Polars support
```

Core APIs (summarize, run_safely, Agent, validate, tokens) support pandas and
Polars; the library detects the type. The HTML `report()` currently supports
pandas (pass a Polars frame through `df.to_pandas()` first).

## Quick start

```python
import safedata, pandas as pd

df = pd.DataFrame({"date": ["2025-01-01", "2024-05-01", "2025-08-01"],
                   "amount": [100.0, 50.0, 200.0]})

def my_model(prompt):          # plug in any LLM: text in, code out
    return "result = df[df['date'].str.startswith('2025')]['amount'].sum()"

agent = safedata.Agent(model=my_model)
out = agent.ask(df, "What were total sales in 2025?")
print(out.answer)              # 300.0
print(out.blocked, out.attempts, out.tokens)
```

### Connecting a real model

Real models return messy text (Markdown fences, chatter, occasional failures).
`safedata.wrap()` takes any text-in/text-out function, extracts the bare code,
and raises a clear `ModelError` on failure, so you're not tied to one provider.

```python
def my_call(prompt):
    return some_model_that_takes_and_returns_text(prompt)   # OpenAI, local, ...

agent = safedata.Agent(model=safedata.wrap(my_call))
out = agent.ask(df, "What were total sales in 2025?")
```

A stronger model just means good code on the first try and fewer retries; the
safety guarantees do not depend on it.

## Token saving

Sending a whole table costs tokens per row; the summary is far smaller. As a
rough illustration, a 1,000-row table estimates at **~18,180 -> ~229 tokens
(~98.7%)** for one question; on millions of rows the saving approaches 99.99%.

```python
print(safedata.token_savings(df))    # readable sentence
safedata.token_stats(df)             # {summary_tokens, raw_tokens, saved_*}
```

**These are estimates**, not tokenizer-exact counts: the library uses a
provider-agnostic ~4-characters-per-token heuristic and sizes the raw data from a
small row sample (it never serialises the whole table, so it stays cheap on huge
frames). Exact numbers vary by model/tokenizer - treat the figures as orders of
magnitude, not guarantees.

## Plug into Pandera / Great Expectations

safedata is the AI-safety layer; it connects to the schema and quality tools your
team already uses instead of replacing them. Export the inferred schema and
checks:

```python
schema = safedata.to_pandera_schema(df)            # a pandera DataFrameSchema
schema.validate(df)

suite = safedata.to_great_expectations_suite(df)   # a portable GX suite dict
# {"expectation_suite_name": ..., "expectations": [...],
#  "meta": {"pii_columns": ["customer_name", ...]}}
```

`to_pandera_schema` needs `pip install "safedata-guard[pandera]"`.
`to_great_expectations_suite` returns a plain dict that Great Expectations can
import, so safedata doesn't pin you to a specific (fast-moving) GX version.

## International PII (optional, Presidio)

The built-in detector (regex + name hints + Luhn) is strong for US/UK-style data
but misses names in free text, locations/addresses, IBANs and non-US formats. For
international coverage, install the optional extra and turn it on:

```bash
pip install "safedata-guard[presidio]"
python -m spacy download en_core_web_sm
```

```python
safedata.enable_presidio()        # call once; whole pipeline now uses it
safedata.privacy_report(df)       # also flags names/locations/IBANs, etc.
```

It augments (never replaces) the built-in detector and feeds the firewall,
contract, risk score, and Agent. Off by default, so there's no heavy dependency
unless you opt in.

## PII masking

The summary includes a few real sample values, which can contain personal data.
By default safedata masks obvious PII (emails, cards, phones, SSNs, IPs) before
the summary leaves your machine and notes which columns were masked.

```python
safedata.summarize(df)                    # regex PII (emails/cards/...) masked
safedata.summarize(df, mask_pii=True)     # ALSO withhold name/address columns
safedata.summarize(df, redact_pii=False)  # raw samples, if you are sure
```

Note: plain `summarize(df)` masks only **regex-detectable** PII (emails, cards,
phones, SSNs, IPs) - it does **not** hide names/addresses, so its raw output can
still contain `"Alice Smith"`. Pass `mask_pii=True` (or use `build_safe_prompt()`
/ `Agent.ask()`, which do this for you) before sending a summary to a model.

Regex masking cannot catch names or addresses; `build_safe_prompt(..., privacy=
"mask")` (below) goes further and **fully withholds** every detected PII column.

`Agent.ask()` does this withholding **by default** (`mask_prompt_pii=True`): name
and address columns are masked in the summary the model sees and in the audit
report, not just regex-matchable emails. Column names/types are still shown, so
the model can still operate on those columns. With `redact_result_pii=True`, the
returned value is also scrubbed - PII columns of a result frame are replaced with
`[REDACTED]`, and dict/list results are walked recursively.

## Data quality & AI-readiness API

The same findings are also available as **structured objects** you can act on,
each with a rule id, severity, confidence, column, evidence, and (where possible)
ready-to-run fix code.

```python
import safedata as sd

sd.validate(df)          # list[Issue]: rule_id, severity, confidence, evidence...
sd.suggest_fixes(df)     # [{issue, column, suggested_code}], runnable pandas
sd.explain_issue(issue)  # plain-language explanation
sd.quality_score(df)     # {score 0..100, breakdown, privacy_risk}
sd.ai_readiness(df)      # {ready_for_summary, safe_to_send_raw, needs_review, ...}
sd.privacy_report(df)    # {pii_columns, high_risk, medium_risk, actions}
sd.infer_columns(df)     # {col: "identifier"|"date"|"money"|"pii_email"|...}
sd.build_safe_prompt(df, "What are the top trends?", privacy="mask")
```

`validate()` is read-only and never runs code. `quality_score().privacy_risk` is
driven by the *kind* of PII found (one email column = High), kept separate from
the data-quality number. `build_safe_prompt(privacy="mask")` withholds all PII
columns, including the name/address columns regex cannot see, so they never
reach the model.

## Command line

```bash
safedata check sales.csv                     # summary + quality score + tokens
safedata check data.xlsx --report out.html   # also write an HTML report
safedata check sales.csv --no-redact --samples 5
safedata check sales.csv --json              # machine-readable for automation
safedata check customer.csv --fail-on pii    # exit 2 if PII present
safedata check sales.csv --fail-on high      # exit 2 on any high-severity issue
```

`--json` emits `quality_score`, `privacy_report`, `ai_readiness`, `issues`,
`pii_columns`, `tokens`. `--fail-on` (`low`/`medium`/`high`/`pii`/`any`) turns
safedata into a gate for CI/CD, Airflow, or pre-refresh checks. The CLI only
reads and summarises; it never executes model code. Supported formats: `.csv`,
`.tsv`, `.xlsx`, `.xls`, `.parquet`, `.json`. Also runs as
`python -m safedata check ...`.

## Function reference

**Agent loop**
- `Agent(model, max_retries=3, isolate=True, timeout=10.0, allow_row_reduction=False)`
  (`isolate`/`timeout`/`allow_row_reduction` pass through to `run_safely`).
- `agent.ask(df, question, verbose=False)` -> result with `.answer`, `.blocked`,
  `.reason`, `.attempts`, `.tokens`.

**Connecting a model**: `wrap(call, clean=...)`, `extract_code(text)`, `ModelError`.

**Running code safely**
- `run_safely(code, df, result_var="result", isolate=True, isolation=None,
  timeout=10.0, allow_row_reduction=False, max_result_rows=None,
  max_result_bytes=None, redact_result_pii=False, **docker_opts)` runs on a copy,
  blocks unsafe ops, checks invariants and result-size/PII guards, returns the
  result. Raises `SafetyError`. `isolation="docker"` runs in a locked-down
  container; if the subprocess runner is unavailable, the in-process fallback
  still enforces `timeout` via a thread.
- `check_code(code)` -> `CodeCheck(.safe, .reason)`; screens without running.

**Looking at the data**: `summarize(df, redact_pii=True, mask_columns=None)`,
`report(df, path=None)`.

**Structured analysis**: `validate`, `Issue`, `suggest_fixes`, `explain_issue`,
`quality_score`, `ai_readiness`, `privacy_report`, `infer_columns`,
`build_safe_prompt`.

**Tokens**: `token_savings(df)`, `token_stats(df)`, `estimate_tokens(text)`.

## Development

Run the test suite with the dev extras installed (they include `pytest-timeout`,
`polars`, and `openpyxl` so the full suite and its config apply):

```bash
pip install -e ".[dev]"
pytest -q
```

Running a bare `pytest` without the dev extras still works, but prints a harmless
`Unknown config option: timeout` warning because the optional `pytest-timeout`
plugin isn't present.

## License

MIT
