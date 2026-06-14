"""Pass a model object with a .generate(prompt) method (auto-detected)."""
import json
import safedata as sd
from _common import load


class MyModel:
    """Any object exposing .generate(prompt) -> text works - no wrapping needed.
    Swap the body for a real client call (OpenAI, Bedrock, a local model, ...)."""

    def generate(self, prompt: str) -> str:
        return json.dumps({"operation": "count_rows"})


df = load("customer_complaints.csv")
result = sd.ask(df, "how many complaints are there?", model=MyModel(),
                profile="general")
print(result.answer)             # {'count': N}
