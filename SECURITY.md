# Security Policy

safedata-guard is a **safety layer, not a compliance guarantee.** It reduces the
risk of an LLM exposing or exfiltrating sensitive tabular data; it does not
certify you against GDPR, HIPAA, PCI-DSS, or any other regime, and it cannot
promise that no data will ever leak. Treat it as defense in depth, and keep your
own review, access controls, and legal sign-off.

## Scope and threat model

safedata-guard is **defense in depth for cooperative / semi-trusted model
output**. The static AST screen, reduced builtins, and invariant checks stop the
destructive accidents an honest model makes and the obvious escape attempts. They
are **not** a sandbox for deliberately malicious code: in-process Python
screening can be defeated, and the default subprocess runner shares the host's
filesystem permissions.

For **untrusted** code, use `isolation="docker"` (no network, read-only root
filesystem, memory/CPU limits) or run inside your own OS-level isolation
(container, locked-down user, or VM). PII masking and data-quality checks are
best-effort heuristics, not a compliance guarantee.

## What it defends against

1. **Generated-code exfiltration.** When an LLM writes Python over your data, it
   can dump rows (`df.to_csv`, `df.values.tolist()`, `df.to_dict('records')`,
   `df.iloc[...]`, `itertuples`, indirect column access). Guarded-Python mode
   (`safe_answer`) screens the code, runs it on a privacy-filtered copy in an
   isolated process, caps result size, redacts PII columns, and can block
   row-shaped results.

2. **Sending raw sensitive data to the model.** The translator sends a compact,
   PII-masked summary instead of raw rows. ShadowFrame goes further: it sends a
   fully synthetic, same-shape sample so no real cell value reaches the model.

3. **Plan-based analysis with no generated code at all (recommended).** SafePlan
   mode (`safe_query`) has the model return a restricted JSON plan that the
   library validates and executes itself - no `eval`/`exec`, no generated Python,
   which removes the code-injection class for the operations it covers, and it
   enforces k-anonymity (`min_group_size`) natively.

4. **Re-identification through small groups and differencing.** k-anonymity
   suppresses small groups and small filtered aggregates/counts; SafeSession adds
   a per-conversation budget and blocks repeated narrowing of the same aggregate.

5. **Malformed / adversarial model output.** All model JSON is treated as
   untrusted and strictly validated (types, allow-listed operations/aggregations/
   filter operators, scalar filter values, integer row limits >= 1, no duplicate
   output columns). Bad output returns a blocked result, never a crash.

## Known limitations (read these)

- **Guarded-Python mode is best-effort, not airtight.** It redacts PII columns
  and blocks bulk/row-shaped exfiltration, but because it screens *arbitrary*
  generated code it **cannot guarantee k-anonymity on a single scalar result**
  (e.g. one isolated individual's numeric value via `...iloc[0]`). Use **SafePlan
  mode** when you need the k-anonymity guarantee. This is demonstrated in
  `tests/test_leak_vectors.py` and `BENCHMARKS.md`.
- **PII detection is best-effort.** Regex + optional Presidio cannot find every
  sensitive field; names / free text are especially hard. Configure
  `blocked_columns` and review the privacy plan for your data.
- **k-anonymity is not differential privacy.** SafeSession's budget and
  differencing checks are practical heuristics, not formal DP. For formal
  guarantees use a differential-privacy library (e.g. OpenDP).
- **Isolation is process-level by default.** `Policy.strict()` adds Docker
  container isolation for genuinely untrusted code; without it the child process
  shares your filesystem permissions.
- **Synthetic prompt, real schema.** ShadowFrame hides cell values but not the
  schema or the real aggregate statistics in the summary.

## Supported versions

The latest released `1.x` line receives security fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than a
public issue. Include a minimal reproduction (synthetic data only - never paste
real personal data) and the affected version. We aim to acknowledge within 5
business days.

Especially valuable: a code snippet that passes `check_code()` / the static
screen yet reaches the filesystem, network, or host process - that is exactly the
boundary this project documents as best-effort, and concrete bypasses help us
tighten it.
