# Migration guide: v1.x to v2.0.0

`safedata-guard` 2.0.0 introduces a redesigned public API. It is **not backward
compatible** with v1.x: several functions that used to be top-level
(`safe_answer`, `Agent`, `summarize`, `run_safely`, `privacy_report`, ...) are no
longer exposed at the top level. The logic still exists - it now powers the new
high-level API, or lives under `safedata.advanced`.

## The new public API

```python
import safedata as sd

sd.ask(df, question, model=..., profile=...)   # answer a question safely
sd.scan(df, profile=...)                        # assess privacy/quality risk
sd.protect(df, question=..., profile=...)       # privacy-filtered safe view
sd.Guard(profile=..., model=...)                # reusable, configured object
```

The everyday API is exactly nine names: `ask`, `scan`, `protect`, `Guard`,
`Policy`, `Result`, `ScanReport`, `Receipt`, `SafedataError`. Everything else
(including the old v1 functions) is reachable under `sd.advanced.*`.

## Old name -> new location

| v1.x | v2.0.0 |
|------|--------|
| `safe_query(...)` | `sd.ask(..., mode="plan")` or `sd.advanced.safe_query(...)` |
| `safe_answer(...)` | `sd.ask(..., mode="python")` or `sd.advanced.safe_answer(...)` |
| `Agent(...)` | `sd.Guard(...)` or `sd.advanced.Agent(...)` |
| `summarize(...)` | `sd.advanced.summarize(...)` |
| `run_safely(...)` | `sd.advanced.run_safely(...)` |
| `check_code(...)` | `sd.advanced.check_code(...)` |
| `build_safe_prompt(...)` | `sd.advanced.build_safe_prompt(...)` |
| `privacy_report(...)` | `sd.scan(...)` or `sd.advanced.privacy_report(...)` |
| `ai_readiness(...)` | `sd.scan(...)` or `sd.advanced.ai_readiness(...)` |
| `to_pandera_schema(...)` | `sd.advanced.to_pandera_schema(...)` |
| `leak_test(...)` | `sd.advanced.leak_test(...)` |
| `create_shadowframe(...)` | `sd.advanced.create_shadowframe(...)` |
| `k_anonymize(...)` | `sd.advanced.k_anonymize(...)` |
| `redact_text(...)` | `sd.advanced.redact_text(...)` |

If you relied on a function not listed here, it is almost certainly available
under the same name in `sd.advanced` (run `dir(safedata.advanced)`).

## Return types changed

The new high-level functions return typed objects, not loose dicts.

### `sd.scan(df, profile=...) -> ScanReport`

```python
report = sd.scan(df, profile="banking")
report.risk_level                  # "low" | "medium" | "high"
report.pii_columns                 # ["email", "full_name", ...]
report.business_identifier_columns # ["account_number", "sort_code", ...]
report.financial_columns
report.health_columns
report.free_text_columns
report.quasi_identifier_columns
report.quality_issues              # list of dicts
report.ai_readiness_score          # 0..100
report.recommendations
```

(Note: the field is `risk_level`, not `risk_score`, and quality findings are in
`quality_issues`.)

### `sd.protect(df, question=..., profile=...)`

By default it returns a **DataFrame** (the safe view):

```python
safe_df = sd.protect(df, question="total revenue by region", profile="banking")
```

Pass `return_report=True` to also get a `ProtectReport`:

```python
safe_df, report = sd.protect(df, question="total revenue by region",
                             profile="banking", return_report=True)
report.kept_columns
report.dropped_columns
report.masked_columns
```

(`protect()` returns a DataFrame, not an object with `.data`/`.receipt`. The
audit receipt comes from `ask()`.)

### `sd.ask(df, question, model=..., profile=...) -> Result`

```python
result = sd.ask(df, "total revenue by region", model=my_model, profile="banking")
result.answer       # the analysis output (None if blocked)
result.ok           # True if an answer was produced and not blocked
result.blocked      # bool
result.warnings     # e.g. "all groups suppressed by k-anonymity"
result.receipt      # a Receipt: audit_id, pii_columns, dropped_columns, ...
print(result.receipt.summary())
```

`ask()` needs a model in every mode except `mode="summary"` (a no-model risk
summary). A real model is any callable `(prompt) -> text`, or any object with a
`.generate(prompt)` method.

## Example migration

v1.x:

```python
import safedata as sd
out = sd.safe_answer(df, "total revenue by region", model=my_model)
print(out["answer"])
```

v2.0.0 (recommended):

```python
import safedata as sd
result = sd.ask(df, "total revenue by region", model=my_model, profile="banking")
print(result.answer)
print(result.receipt.summary())
```

Or, to keep the exact old guarded-Python behaviour, use the advanced namespace:

```python
out = sd.advanced.safe_answer(df, "total revenue by region", model=my_model)
print(out["answer"])
```

## Guard: reuse one configured object

```python
guard = sd.Guard(profile="insurance", model=my_model)
report = guard.scan(df)
result = guard.ask(df, "average claim amount by region")
safe_df = guard.protect(df, question="average claim amount by region")
session = guard.session(df)        # multi-turn, privacy-budgeted
```

## CLI changes

The CLI now mirrors the Python API:

```bash
safedata scan data.csv --profile banking
safedata protect data.csv --profile banking --question "revenue by region" --out safe.csv
safedata ask data.csv "revenue by region" --profile banking --model openai
safedata advanced inspect-policy banking
```

`scan` and `protect` need no model. `ask` needs `--model openai` (with
`OPENAI_API_KEY` set), or `--mode summary` for a no-model risk summary.

## Staying on v1 for now

If you are not ready to migrate, pin to the last v1 release:

```bash
pip install "safedata-guard<2"
```

For new projects, use 2.0.0 or later.

## Recommended migration path

1. Replace top-level calls with `sd.ask` / `sd.scan` / `sd.protect` / `sd.Guard`.
2. Move any remaining lower-level usage to `sd.advanced`.
3. Update code that expected the old dict return types to the new typed objects.
4. Switch CLI usage to `scan` / `protect` / `ask` / `advanced`.
5. Re-run your tests against 2.0.0.
