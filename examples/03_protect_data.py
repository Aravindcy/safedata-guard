"""sd.protect: get a privacy-filtered safe view of a DataFrame (no model needed)."""
import safedata as sd
from _common import load

df = load("banking_transactions.csv")

safe_df, report = sd.protect(df, question="average balance by product",
                             profile="banking", return_report=True)

print("kept    :", report.kept_columns)
print("dropped :", report.dropped_columns)
print("masked  :", report.masked_columns)
print()
print(safe_df.head())
