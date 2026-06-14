"""sd.scan: assess a dataset's privacy and quality risk (no model needed)."""
import safedata as sd
from _common import load

df = load("banking_transactions.csv")
report = sd.scan(df, profile="banking")

print("risk level      :", report.risk_level)
print("PII columns     :", report.pii_columns)
print("business IDs    :", report.business_identifier_columns)
print("financial       :", report.financial_columns)
print("free text       :", report.free_text_columns)
print("AI-readiness    :", report.ai_readiness_score, "/100")
for r in report.recommendations:
    print("  -", r)
