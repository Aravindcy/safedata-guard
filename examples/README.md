# Examples

Short, runnable scripts for each part of the API. They read the synthetic
datasets created by `scripts/make_datasets.py` (run it once):

```bash
python scripts/make_datasets.py     # writes datasets/*.csv
python examples/01_basic_ask.py
```

All example datasets are **synthetic and contain no real customer data.**

Each `ask` example uses a tiny placeholder model so it runs without an API key.
Replace `placeholder_model` with your own LLM - any callable `(prompt) -> text`,
or an object with a `.generate(prompt)` method.

| Script | Shows |
|---|---|
| `01_basic_ask.py` | `sd.ask` + the receipt |
| `02_scan_data.py` | `sd.scan` risk + categories |
| `03_protect_data.py` | `sd.protect` safe view |
| `04_banking_policy.py` | banking profile (SafePlan only) |
| `05_energy_policy.py` | energy profile |
| `06_guard_session.py` | `Guard.session` differencing guard |
| `07_custom_policy.py` | building a custom `Policy` |
| `08_custom_model_adapter.py` | a `.generate()` model object |
