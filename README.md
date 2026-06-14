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
- **[docs/guide.md](docs/guide.md)** - full feature reference: isolation, result guards, firewall, k-anonymity, Pandera/GX export, CLI, and the function reference.
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

## Full feature guide

The detailed reference - hardened Docker isolation, result guards, the question-aware firewall, k-anonymity, Pandera/Great Expectations export, international PII, the CLI, and the full function reference - lives in **[docs/guide.md](docs/guide.md)**.

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
