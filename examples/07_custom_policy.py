"""Build a custom Policy instead of using a named profile."""
import safedata as sd
from _common import load, placeholder_model

df = load("healthcare_admissions.csv")

# Start from healthcare and tighten the row cap; or build from scratch.
policy = sd.Policy.healthcare(min_group_size=20, max_result_rows=10)
print("profile:", policy.profile, "| k:", policy.min_group_size,
      "| python:", policy.allow_python_fallback)

model = placeholder_model({
    "operation": "groupby_aggregate", "group_by": ["department"], "limit": 10,
    "metrics": [{"column": "treatment_cost", "agg": "mean", "as_name": "avg_cost"}]})

result = sd.ask(df, "average treatment cost by department", model=model,
                policy=policy)
print(result.answer)
