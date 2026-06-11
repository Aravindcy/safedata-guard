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
docker build -t safedata-guard-runner:1.0.7 .
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

Sending a whole table costs tokens per row; the summary is far smaller. Measured
against OpenAI's own counter, a 1,000-row table was **18,180 → 229 input tokens
(98.7%)** for one question; on millions of rows the saving approaches 99.99%.

```python
print(safedata.token_savings(df))    # readable sentence
safedata.token_stats(df)             # {summary_tokens, raw_tokens, saved_*}
```

The raw-data figure is estimated from a small row sample (never by serialising
the whole table), so it stays cheap even on huge frames; exact counts vary by
provider.

## PII masking

The summary includes a few real sample values, which can contain personal data.
By default safedata masks obvious PII (emails, cards, phones, SSNs, IPs) before
the summary leaves your machine and notes which columns were masked.

```python
safedata.summarize(df)                    # PII masked by default
safedata.summarize(df, redact_pii=False)  # raw samples, if you are sure
```

Regex masking cannot catch names or addresses; `build_safe_prompt(..., privacy=
"mask")` (below) goes further and **fully withholds** every detected PII column.

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
- `agent.ask(df, question, verbose=False)` → result with `.answer`, `.blocked`,
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
- `check_code(code)` → `CodeCheck(.safe, .reason)`; screens without running.

**Looking at the data**: `summarize(df, redact_pii=True, mask_columns=None)`,
`report(df, path=None)`.

**Structured analysis**: `validate`, `Issue`, `suggest_fixes`, `explain_issue`,
`quality_score`, `ai_readiness`, `privacy_report`, `infer_columns`,
`build_safe_prompt`.

**Tokens**: `token_savings(df)`, `token_stats(df)`, `estimate_tokens(text)`.

## License

MIT
