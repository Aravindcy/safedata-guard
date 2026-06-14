"""sd.ask: answer a question safely, with an audit receipt."""
import safedata as sd
from _common import load, placeholder_model

df = load("banking_transactions.csv")

model = placeholder_model({
    "operation": "groupby_aggregate", "group_by": ["product"],
    "metrics": [{"column": "balance", "agg": "mean", "as_name": "avg_balance"}]})

result = sd.ask(df, "What is the average balance by product?",
                model=model, profile="banking")

print(result.answer)
print()
print(result.receipt.summary())
