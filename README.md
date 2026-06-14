# safedata-guard

[![CI](https://github.com/Aravindcy/safedata-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Aravindcy/safedata-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safedata-guard.svg)](https://pypi.org/project/safedata-guard/)
[![Python versions](https://img.shields.io/pypi/pyversions/safedata-guard.svg)](https://pypi.org/project/safedata-guard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A safety layer for asking AI questions over sensitive tabular data.**

safedata-guard scans your DataFrame, removes unnecessary sensitive fields,
executes the analysis through a safe engine (the model returns a validated JSON
plan, not raw Python), and returns an answer with an audit receipt.

> **Status: beta. A safety layer, not a compliance guarantee.** It reduces the
> exposure of sensitive data; it does not certify GDPR/HIPAA/PCI compliance and
> cannot promise nothing will ever leak. PII detection and code screening are
> best-effort heuristics. See [SECURITY.md](SECURITY.md).

## 30-second example

```python
import safedata as sd

def my_model(prompt):            # plug in any LLM (callable, or an object with .generate)
    ...                          # returns the model's text reply

result = sd.ask(df, "What is total revenue by region?",
                model=my_model, profile="banking")

print(result.answer)             # safe, aggregated answer
print(result.receipt.summary())  # audit trail: PII dropped, no Python run, ...
```

## Why this exists

Most "chat with your data" tools send the whole table to the model and run
whatever Python it writes, unchecked. In a measured benchmark (gpt-4o-mini, 6
synthetic datasets, 48 attack prompts), plain LLM-generated code leaked real PII
on ~85% of attacks while SafePlan leaked none (see [BENCHMARKS.md](BENCHMARKS.md)
for the full method and limitations). safedata-guard's default engine never runs
generated Python: the model returns a restricted JSON analysis plan that the
library validates and executes itself, with privacy rules applied.

## How it works

```text
       your DataFrame
             |
        sd.scan()            assess risk (PII, sensitive categories, quality)
             |
        sd.protect()         drop un-needed PII / sensitive / business-id columns
             |
   schema + synthetic sample only  ->  LLM returns a JSON plan (no raw rows)
             |
     validate the plan                 (allow-list, k-anonymity, caps)
             |
   execute it locally (no generated Python)
             |
       answer + audit Receipt
```

## The four doors

| You want to... | Use |
|---|---|
| Ask a question safely | `sd.ask(df, question, model, profile)` |
| Assess a dataset's risk | `sd.scan(df, profile)` |
| Get a privacy-filtered view | `sd.protect(df, question, profile)` |
| Reuse a configured setup | `sd.Guard(profile, model)` |

The everyday API is intentionally small (`sd.Policy` controls the behaviour).
Power-user tools live under `sd.advanced.*`.

### Ask safely

```python
result = sd.ask(df, "average balance by region", model=my_model, profile="banking")
print(result.answer)             # None if blocked; check result.ok / result.blocked
print(result.warnings)           # e.g. "all groups suppressed by k-anonymity"
```

`ask` uses the SafePlan engine by default. Guarded Python is only used when the
policy allows it (regulated profiles disable it). `mode=` can force `plan`,
`summary` (explain risk, no data execution), or `python`.

### Scan data risk

```python
report = sd.scan(df, profile="banking")
print(report.risk_level)                    # low | medium | high
print(report.pii_columns)                   # e.g. ["full_name", "email"]
print(report.business_identifier_columns)   # e.g. ["account_number", "sort_code"]
print(report.financial_columns, report.health_columns, report.free_text_columns)
print(report.quality_issues, report.recommendations)
```

### Protect data before AI

```python
safe_df = sd.protect(df, question="average balance by region", profile="banking")
# unneeded PII / sensitive identifiers dropped; analytical columns kept.
safe_df, report = sd.protect(df, question="...", profile="banking",
                             return_report=True)
```

### Reuse settings with Guard

```python
guard = sd.Guard(profile="banking", model=my_model)
guard.ask(df, "average balance by region")
guard.scan(df)
guard.protect(df, question="average balance by region")
session = guard.session(df)                 # multi-turn, privacy-budgeted
```

## Industry profiles

`profile=` (or `sd.Policy.from_profile(name)`) picks safe defaults:

| Profile | min group size | Python fallback | Notes |
|---|---|---|---|
| `general` | none | allowed | non-regulated data |
| `energy` | 5 | disabled | SafePlan only |
| `banking` | 10 | disabled | SafePlan only |
| `insurance` | 10 | disabled | SafePlan only |
| `healthcare` | 15 | disabled | smallest result caps |
| `strict` | 20 | disabled | Docker isolation + Presidio |

Override any field: `sd.Policy.banking(min_group_size=25)`.

## Audit receipts

Every `sd.ask()` returns a `Result` carrying a `Receipt`:

```python
r = result.receipt
print(r.audit_id, r.profile, r.engine, r.mode)
print(r.pii_columns, r.dropped_columns, r.min_group_size)
print(r.python_fallback_used, r.raw_rows_exposed, r.warnings)
print(r.summary())              # human-readable; r.to_dict() for JSON
```

## Advanced tools

The everyday API stays small; power-user tools are one level deeper under
`sd.advanced`:

```python
sd.advanced.leak_test(df, model=my_model)        # privacy red-team score
sd.advanced.create_shadowframe(df)               # synthetic same-shape stand-in
sd.advanced.run_safely(code, df)                 # guarded Python on a copy
sd.advanced.SafeSession(df, model=my_model)      # differencing/budget guard
sd.advanced.safe_query(df, q, model=my_model)    # low-level SafePlan call
sd.advanced.safe_answer(df, q, model=my_model)   # guarded-Python answer (dict)
sd.advanced.summarize(df)                         # quality-aware text summary
sd.advanced.token_stats(df)                       # token-saving estimate
sd.advanced.to_pandera_schema(df)                 # Pandera / Great Expectations
sd.advanced.redact_text("call +44 ...")          # best-effort PII masking
```

Everything from earlier versions is still here under `sd.advanced` (run
`dir(sd.advanced)` to see all of it) - the top level just stays small.

## Install

```bash
pip install safedata-guard
pip install "safedata-guard[polars]"     # optional Polars support
pip install "safedata-guard[presidio]"   # optional international PII detection
```

## CLI

```bash
safedata scan data.csv --profile banking
safedata protect data.csv --profile banking --question "revenue by region" --out safe.csv
safedata ask data.csv "revenue by region" --profile banking --model openai
safedata advanced inspect-policy banking
```

`scan` and `protect` need no model; `ask` (and `advanced leak-test`) use
`--model openai` with `OPENAI_API_KEY` set.

## Documentation

- **[SECURITY_MODEL.md](SECURITY_MODEL.md)** - what it protects against, reduces,
  and does not guarantee; the recommended enterprise deployment pattern.
- **[THREAT_MODEL.md](THREAT_MODEL.md)** - per-threat risk / mitigation /
  limitation / test coverage.
- **[SECURITY.md](SECURITY.md)** - how to report a vulnerability.
- **[BENCHMARKS.md](BENCHMARKS.md)** - measured leak rates vs plain LLM-generated
  code, with methodology and honest caveats.
- **[examples/](examples/)** - runnable per-domain scripts; **[docs/examples.md](docs/examples.md)** - the same as a guide.
- **[CHANGELOG.md](CHANGELOG.md)** - what changed in each release.

## Limitations

- This is a safety layer, **not** a compliance guarantee.
- PII detection is best-effort; names and free text are especially hard.
- k-anonymity here is a practical heuristic, not differential privacy.
- The recommended SafePlan engine is far safer than generated Python, but
  policies must be configured correctly. Review high-risk outputs yourself.

## License

MIT - see [LICENSE](LICENSE).
