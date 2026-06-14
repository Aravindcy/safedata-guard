"""Banking profile: SafePlan only (guarded Python disabled), k-anonymity >= 10."""
import safedata as sd
from _common import load, placeholder_model

df = load("banking_transactions.csv")
policy = sd.Policy.banking()
print("python fallback allowed:", policy.allow_python_fallback)   # False

model = placeholder_model({
    "operation": "groupby_aggregate", "group_by": ["city"],
    "metrics": [{"column": "balance", "agg": "mean", "as_name": "avg"}]})

result = sd.ask(df, "average balance by city", model=model, profile="banking")
print("blocked  :", result.blocked)
print("warnings :", result.warnings)        # small cities suppressed by k>=10
print(result.answer)
