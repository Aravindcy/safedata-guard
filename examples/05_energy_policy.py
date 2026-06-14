"""Energy profile: SafePlan only, k-anonymity >= 5."""
import safedata as sd
from _common import load, placeholder_model

df = load("energy_consumption.csv")

model = placeholder_model({
    "operation": "groupby_aggregate", "group_by": ["tariff"],
    "metrics": [{"column": "kwh_monthly", "agg": "mean", "as_name": "avg_kwh"}]})

result = sd.ask(df, "average monthly kWh by tariff", model=model, profile="energy")
print(result.answer)
print("engine:", result.engine, "| python:", result.receipt.python_fallback_used)
