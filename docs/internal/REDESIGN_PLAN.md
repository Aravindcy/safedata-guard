# safedata-guard v2.0.0 redesign plan

Goal: one front door, simple outside, powerful inside. Old public API removed;
only nine names are public.

## Decisions (locked)

- **Version: 2.0.0** (breaking redesign - correct semver for removing public
  names; upgraders from 1.x must read the CHANGELOG migration notes).
- **Hard remove** the old public API. No deprecation shim. Old logic stays as
  internal implementation modules; it is just not exported.
- **Build the facade over the existing engine now; defer the physical folder
  reorg** (core/privacy/quality/...) to a later internal pass - it is invisible
  to users and risky to do at the same time.

## Final public API (the only nine names)

    sd.ask, sd.scan, sd.protect, sd.Guard, sd.Policy,
    sd.Result, sd.ScanReport, sd.Receipt, sd.SafedataError

Mental model: ask (answer a question) / scan (assess risk) / protect (safe view) /
Guard (reusable, configured object). Policy controls everything. SafePlan before
Python. Receipt after every ask().

## Refinements beyond the original spec

- `model` accepts a plain callable OR an object with `.generate(prompt)` -
  auto-detected, so nobody is forced to wrap their LLM.
- `Result.ok` boolean and `Receipt.summary()` pretty-printer for good DX.
- `Policy.from_profile(name)` raises `PolicyError` on an unknown profile.
- CLI `--fail-on high-risk` drives process exit codes for enterprise pipelines.
- Regulated industry profiles are SafePlan-only by default
  (`allow_python_fallback=False`); the guarded-Python engine is opt-in per policy.

## Phases (each: separate commit, tests green, push held)

- **Phase 1 (done):** `exceptions.py` (SafedataError hierarchy; engine SafetyError
  now subclasses it), `results.py` (Result/ScanReport/Receipt/ProtectReport),
  `Policy` industry profiles (general/energy/banking/insurance/healthcare +
  from_profile), Policy made non-frozen. Additive; public API untouched.
- **Phase 2a (done):** `api.py` (ask/scan/protect with a light column classifier
  + model adapter accepting a callable or `.generate`), `guard.py` (Guard with
  ask/scan/protect/session), Receipt built for every ask(), typed Result/
  ScanReport returned. New names exposed ADDITIVELY (old names still present) so
  the suite stays green. `Policy.strict()` corrected to profile="strict",
  allow_python_fallback=False, k=20.
- **Phase 2b (done):** hard-cut `__init__` to the nine public names; old names are
  no longer importable from the package. Advanced tools live under
  `safedata.advanced.*` (leak_test, create_shadowframe, run_safely, check_code,
  SafeSession, ...). Migrated the entire existing test suite off the old public
  names to internal-module imports (no shim) - coverage preserved.
- **Phase 3 (done):** richer privacy detector (business_identifier / financial /
  health / location / free_text / quasi_identifier), separator-normalized name
  matching; scan() risk-level tuning (name-heavy data is now >= medium, health is
  high); protect() also drops un-needed business identifiers / free text; ask()
  warns when k-anonymity suppresses all groups. Live-validated on real energy/
  insurance datasets (15/15), which caught the "Offer ID" separator bug.
- **Phase 4 (done):** CLI redesign - `scan` / `protect` / `ask` top-level, plus
  `advanced` subgroup (`inspect-policy` / `shadow` / `leak-test`), with
  `--json/--out/--profile/--mode/--fail-on/--receipt-out`. `ask`/`leak-test` use
  `--model openai` (OPENAI_API_KEY). CLI tests migrated; live-validated on the
  real energy dataset (scan/protect/inspect-policy/ask).
- **Phase 5:** docs rewrite - README order per spec, `SECURITY_MODEL.md`,
  `THREAT_MODEL.md`, `examples/` scripts + synthetic `examples/data/` with a
  "synthetic, no real data" note. Rewrite all tests around the new API.
- **Phase 6 (done):** strengthened `MANIFEST.in` + `.gitignore` (caches/build/
  local outputs excluded; new docs included); CI `package` job (build +
  twine check + clean-env wheel install + public-API assertion + sdist hygiene
  check); rebuilt dist (wheel has api/guard/results/exceptions/advanced, sdist
  clean); benchmark scripts ported to `sd.ask`; live re-benchmark; acceptance
  check below.

## Acceptance criteria (status)

- [x] Top-level public API has fewer than 10 names (exactly 9 + `advanced`).
- [x] README starts with `sd.ask()`.
- [x] `sd.scan()` / `sd.protect()` / `sd.ask()` / `sd.Guard()` work.
- [x] Policy industry profiles work; banking/insurance/healthcare disable Python.
- [x] SafePlan is the default engine; a Receipt is returned for every ask().
- [x] CLI has scan/protect/ask (+ advanced).
- [x] Security / prompt-injection / differencing tests pass.
- [x] Package builds and the wheel installs cleanly; no cache/build files in sdist.
- [x] Docs state the limitations plainly (SECURITY_MODEL.md / THREAT_MODEL.md).
- [ ] Internal folder reorg (core/privacy/quality/...) - deliberately deferred;
      it is invisible to users and can be a later internal pass.

## Acceptance criteria (from the spec)

Fewer than 10 public names; README starts with `sd.ask()`; scan/protect/ask/Guard
work; profiles work; banking/insurance/healthcare disable Python by default;
SafePlan is the default engine; a Receipt is returned for every ask(); CLI has
scan/protect/ask; security + prompt-injection + differencing tests pass; package
builds and the wheel installs cleanly; no cache/build/local files in the sdist;
docs state the limitations plainly.
