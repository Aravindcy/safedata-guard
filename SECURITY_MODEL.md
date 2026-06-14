# Security model

safedata-guard is a **safety layer, not a compliance guarantee.** It reduces the
exposure of sensitive data when an LLM analyses a DataFrame. It does not certify
GDPR/HIPAA/PCI compliance and cannot promise that no data will ever leak.

## What it protects against

- **Generated-code exfiltration.** The default engine (SafePlan) never runs
  model-written Python. The model returns a validated JSON plan that the library
  executes itself, so `df.to_csv`, `df.values.tolist()`, `df.to_dict('records')`,
  `df.iloc[...]`, file/network/OS access, etc. are not reachable for normal
  analysis.
- **Sending raw sensitive data to the model.** `protect()` and the privacy plan
  drop unneeded PII and sensitive identifiers and mask retained sensitive fields.
  The model receives a schema and a synthetic sample, not raw rows.
- **Re-identification via small groups / differencing.** k-anonymity suppresses
  small groups and small filtered aggregates/counts; `Guard.session()` adds a
  per-conversation budget and blocks repeated narrowing of the same aggregate.
- **Malformed / adversarial model output.** All model JSON is strictly validated
  (allow-listed operations/aggregations/filters, scalar filter values, integer
  row limits, no duplicate output columns). Bad output returns a blocked result,
  never a crash.

## What it reduces (but does not eliminate)

- PII reaching prompts (best-effort detection; names/free text are hard).
- The blast radius of an over-broad question (capped, aggregated, suppressed).
- The chance an answer contains an individual's record.

## What it does NOT guarantee

- Compliance with any regulation.
- Detection of every PII or sensitive field.
- Protection against a deliberately malicious *local* operator.
- Differential-privacy guarantees (k-anonymity and the session budget are
  practical heuristics).

## Supported safe execution modes

| Mode | Behaviour |
|---|---|
| `plan` (default via `auto`) | model returns JSON; library executes it. No generated Python. |
| `summary` | explain risk only; no data execution. |
| `python` | guarded Python (AST screen + isolation + result caps). Disabled by regulated profiles; opt-in. |

## Known limitations

- Guarded-Python mode is best-effort: it redacts PII columns and blocks
  bulk/row-shaped exfiltration, but cannot guarantee k-anonymity on a single
  scalar result. Use SafePlan when you need that guarantee.
- The privacy detector is keyword + heuristic based; review the `scan()` report
  for your data and configure the policy accordingly.

## Recommended enterprise deployment pattern

1. **Scan first.** Run `sd.scan(df, profile=...)` (or `safedata scan --fail-on
   high-risk`) in your pipeline; gate on the exit code.
2. **Protect before analysis.** Persist a `sd.protect(...)` safe view if data
   leaves a trusted boundary.
3. **Ask through a regulated profile.** Use `banking`/`insurance`/`healthcare`/
   `strict` so SafePlan is enforced and guarded Python is off.
4. **Keep the receipts.** Store `result.receipt.to_dict()` per answer for audit.
5. **Review high-risk outputs** with a human before acting on them.

See also [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) (how to
report a vulnerability).
