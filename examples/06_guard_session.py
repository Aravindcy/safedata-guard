"""Guard.session: multi-turn with a privacy budget and a differencing guard."""
import json
import safedata as sd
from _common import load

df = load("sales_renewals.csv")


def model(prompt):
    # A real LLM would read the prompt; here we vary the plan by question text.
    if "excluding" in prompt.lower() or "below" in prompt.lower():
        return json.dumps({"operation": "aggregate",
                           "filters": [{"column": "arr", "op": "<", "value": 50000}],
                           "metrics": [{"column": "arr", "agg": "mean", "as_name": "avg"}]})
    return json.dumps({"operation": "aggregate",
                      "metrics": [{"column": "arr", "agg": "mean", "as_name": "avg"}]})


guard = sd.Guard(profile="general", model=model)
s = guard.session(df)
print("Q1:", s.ask("average ARR")["blocked"])                       # allowed
print("Q2:", s.ask("average ARR excluding deals below 50000")["blocked"],
      "(differencing)")                                             # blocked
