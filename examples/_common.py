"""Shared helpers for the examples (placeholder model + dataset loader)."""
import json
import os
import pandas as pd

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "datasets")


def load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        raise SystemExit("Run `python scripts/make_datasets.py` first.")
    return pd.read_csv(path)


def placeholder_model(plan: dict):
    """Return a callable that always emits `plan` as JSON. Stand-in for a real
    LLM so the examples run with no API key. Replace with your own model:

        def my_model(prompt):
            return my_llm(prompt)            # any callable (prompt) -> text
    """
    return lambda prompt: json.dumps(plan)
