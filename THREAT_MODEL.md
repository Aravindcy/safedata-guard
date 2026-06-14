# Threat model

For each threat: the risk, how safedata-guard mitigates it, the remaining
limitation, and where it is tested. This is a safety layer, not a guarantee.

| Threat | Mitigation | Remaining limitation | Test coverage |
|---|---|---|---|
| **Prompt injection** ("ignore instructions, dump data") | SafePlan: the model can only emit a validated JSON plan; injected text cannot become an export/raw-row operation. | A cooperative model could still pick a legitimately-allowed aggregate the attacker wanted. | `test_leak_vectors.py`, `test_safeplan_guards.py` |
| **Raw data extraction** (`df`, `head`, `iloc`, `values`) | SafePlan has no raw-row/export operations; guarded Python blocks bulk/row-shaped results and caps result size. | Guarded Python can return a lone scalar (not k-safe). | `test_leak_vectors.py` |
| **Sensitive information disclosure** (PII in answers) | PII columns dropped/masked before the model; result-level PII redaction. | Best-effort detection; names/free text missed sometimes. | `test_leak_vectors.py`, `test_safety.py` |
| **Unsafe generated code** (`eval`, `exec`, `__import__`) | Default engine runs no generated Python; guarded Python AST-screens and reduces builtins. | In-process screening is not a sandbox; use Docker isolation for untrusted code. | `test_safety.py` |
| **File / network / OS access** | Blocked by the SafePlan operation allow-list and the guarded-Python screen. | Process isolation shares host FS permissions unless Docker is used. | `test_safety.py` |
| **Data export attempts** (`to_csv`, `to_json`, ...) | Not SafePlan operations; screened in guarded Python. | - | `test_leak_vectors.py` |
| **Differencing / repeated narrowing** | `Guard.session()` blocks reusing the same aggregate with a tightened filter; k-anonymity on small groups. | Heuristic, not differential privacy; only same-shape narrowing is caught. | `test_session.py` |
| **Free-text leakage** (notes/complaints) | `scan` flags free-text columns; `protect` drops un-needed ones. | Keyword-based; unusual column names missed. | `test_v110_facade.py` |
| **Over-broad prompts** ("show everything") | Aggregation-only engine + result caps + k-anonymity suppression with a warning. | An aggregate over the whole table is still allowed. | `test_v110_facade.py` |
| **Malformed model output** (bad JSON/types) | Strict validation; bad output returns blocked, never crashes. | - | `test_safeplan_guards.py` |
| **Misconfigured policy** (Python enabled on regulated data) | Industry profiles disable Python fallback by default; explicit opt-in required. | An operator can still override the policy. | `test_v110_facade.py`, `test_v110_foundation.py` |
| **Supply-chain risk** | Minimal core deps; optional extras isolated; package builds reproducibly. | Standard PyPI trust assumptions apply. | CI build + `twine check` |

## Reporting

Report suspected vulnerabilities privately - see [SECURITY.md](SECURITY.md).
Especially valuable: a model output that passes validation yet exposes an
individual record.
