# Examples by domain

These use the synthetic datasets from `scripts/make_datasets.py` (run it once to
create `datasets/*.csv`). No real personal data is involved. Plug in your own
`model` - any callable that takes a prompt and returns the model's text reply (or
an object with a `.generate(prompt)` method).

```python
import pandas as pd
import safedata as sd

def model(prompt):           # plug in any LLM
    ...
```

The recommended entry point is `sd.ask` (SafePlan engine): the model returns a
JSON plan, safedata executes it locally, and you get an answer plus a Receipt.

## Banking - customer transactions

```python
df = pd.read_csv("datasets/banking_transactions.csv")
res = sd.ask(df, "What is the average balance by product?",
             model=model, profile="banking")
print(res.answer)            # product-level aggregates, small groups suppressed
print(res.receipt.summary())
```

A raw-data request is refused: `sd.ask(df, "list every account number", ...)`
returns `blocked=True` because raw row access is not a SafePlan operation.

## Insurance - claims

```python
df = pd.read_csv("datasets/insurance_claims.csv")
res = sd.ask(df, "What is the total claim_amount by claim_type?",
             model=model, profile="insurance")
```

## Energy - customer consumption

```python
df = pd.read_csv("datasets/energy_consumption.csv")
res = sd.ask(df, "What is the average kwh_monthly by tariff?",
             model=model, profile="energy")
```

## Healthcare - admissions

```python
df = pd.read_csv("datasets/healthcare_admissions.csv")
res = sd.ask(df, "What is the average treatment_cost by department?",
             model=model, profile="healthcare")
# "average cost for one specific patient" is suppressed by k-anonymity.
```

## Sales - renewals

```python
df = pd.read_csv("datasets/sales_renewals.csv")
res = sd.ask(df, "What is the renewal rate by segment?",
             model=model, profile="general")
```

## Customer service - complaints

```python
df = pd.read_csv("datasets/customer_complaints.csv")
res = sd.ask(df, "How many complaints by category?",
             model=model, profile="general")
```

## Scan and protect before asking

```python
report = sd.scan(df, profile="banking")
print(report.risk_level, report.pii_columns, report.business_identifier_columns)

safe_df = sd.protect(df, question="average balance by region", profile="banking")
```

## Reuse settings, and protect a whole conversation

```python
guard = sd.Guard(profile="banking", model=model)
guard.ask(df, "average balance by region")

session = guard.session(df)                      # multi-turn, privacy-budgeted
session.ask("average balance in London")         # allowed
session.ask("average balance in London below 1000")   # blocked: differencing
```

## Red-teaming your own setup

```python
report = sd.advanced.leak_test(df, model=model, policy=sd.Policy.strict())
print(report.score, report.risk_level)
```

See [BENCHMARKS.md](../BENCHMARKS.md) for measured leak rates vs plain
LLM-generated code, and [SECURITY.md](../SECURITY.md) for the threat model.
