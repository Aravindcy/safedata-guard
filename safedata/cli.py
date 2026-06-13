"""
Command-line interface for safedata-guard.

Lets you inspect a data file from the terminal without writing any Python:

    safedata check sales.csv
    safedata check data.xlsx --report out.html
    safedata check sales.csv --no-redact --samples 5

It is a thin wrapper over the library's existing functions (summarize,
token_savings, report). It never executes AI-written code and never touches the
safety screen, it only reads a file and prints the quality summary.
"""

import argparse
import sys

from . import __version__


def _load_dataframe(path: str):
    """Read a CSV/TSV/Excel/Parquet/JSON file into a pandas DataFrame.

    Done here in the CLI (not via the blocked reader methods in bodyguard),
    because loading the user's own named file from the terminal is the explicit
    point of the command, quite different from AI-written code trying to read
    arbitrary paths.
    """
    import os
    import pandas as pd

    if not os.path.exists(path):
        raise FileNotFoundError(f"No such file: {path}")

    lower = path.lower()
    try:
        if lower.endswith((".csv",)):
            return pd.read_csv(path)
        if lower.endswith((".tsv",)):
            return pd.read_csv(path, sep="\t")
        if lower.endswith((".xlsx", ".xls")):
            return pd.read_excel(path)
        if lower.endswith((".parquet",)):
            return pd.read_parquet(path)
        if lower.endswith((".json",)):
            return pd.read_json(path)
    except Exception as e:
        raise ValueError(f"Could not read '{path}': {e}")

    raise ValueError(
        f"Unsupported file type: '{path}'. Supported: .csv, .tsv, .xlsx, "
        f".xls, .parquet, .json")


def _fail_code(issues, pii_columns, fail_on):
    """Return a non-zero exit code if `fail_on` threshold is met, else 0."""
    from .analysis import SEVERITY_ORDER
    if not fail_on:
        return 0
    fail_on = fail_on.lower()
    if fail_on == "pii":
        return 2 if pii_columns else 0
    if fail_on == "any":
        return 2 if issues else 0
    threshold = SEVERITY_ORDER.get(fail_on)
    if threshold is None:
        return 0
    worst = max((SEVERITY_ORDER.get(i.severity, 0) for i in issues), default=0)
    return 2 if worst >= threshold else 0


def _cmd_check(args) -> int:
    from .translator import summarize
    from .tokens import token_savings, token_stats
    from .report import report
    from .analysis import (validate, quality_score, privacy_report,
                           ai_readiness)

    try:
        df = _load_dataframe(args.file)
    except (FileNotFoundError, ValueError) as e:
        if args.json:
            import json
            print(json.dumps({"error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        return 1

    scan_rows = "all" if getattr(args, "pii_scan_all", False) else \
        getattr(args, "pii_scan_rows", 20)
    issues = validate(df)
    priv = privacy_report(df, scan_rows=scan_rows)
    pii = priv["pii_columns"]

    if args.json:
        import json
        payload = {
            "file": args.file,
            "rows": int(len(df)),
            "columns": int(df.shape[1]),
            "quality_score": quality_score(df, scan_rows=scan_rows),
            "privacy_report": priv,
            "ai_readiness": ai_readiness(df, scan_rows=scan_rows),
            "pii_columns": pii,
            "issues": [i.to_dict() for i in issues],
            "tokens": token_stats(df),
        }
        print(json.dumps(payload, indent=2, default=str))
    else:
        # Default output is privacy-aware: fully withhold detected PII columns
        # (names/addresses regex can't catch), not just regex-mask. --no-redact
        # opts out entirely.
        print(summarize(df, max_samples=args.samples,
                        redact_pii=not args.no_redact,
                        mask_columns=set() if args.no_redact else set(pii)))
        print()
        print(token_savings(df))
        sc = quality_score(df, scan_rows=scan_rows)
        print(f"\nData quality score: {sc['score']}/100 ({sc['label']}) "
              f"| privacy risk: {sc['privacy_risk']}")
        if args.report:
            try:
                report(df, args.report)
                print(f"\nHTML report written to: {args.report}")
            except Exception as e:
                print(f"warning: could not write report: {e}", file=sys.stderr)

    return _fail_code(issues, pii, args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safedata",
        description="Inspect a data file: quality summary, data-trap warnings, "
                    "and token-saving estimate.")
    parser.add_argument("--version", action="version",
                        version=f"safedata-guard {__version__}")

    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser(
        "check", help="summarise a data file and flag quality traps")
    check.add_argument("file", help="path to a .csv, .tsv, .xlsx, .parquet, "
                                    "or .json file")
    check.add_argument("--report", metavar="OUT.html",
                       help="also write an HTML quality report to this path")
    check.add_argument("--no-redact", action="store_true",
                       help="show raw sample values (do NOT mask detected PII)")
    check.add_argument("--samples", type=int, default=3, metavar="N",
                       help="number of sample values per column (default 3)")
    check.add_argument("--json", action="store_true",
                       help="emit machine-readable JSON (score, issues, PII, "
                            "tokens) instead of text")
    check.add_argument("--fail-on", metavar="LEVEL", dest="fail_on",
                       choices=["low", "medium", "high", "pii", "any"],
                       help="exit non-zero (2) if an issue at/above LEVEL is "
                            "found; 'pii' fails on any PII, 'any' on any issue")
    check.add_argument("--pii-scan-rows", type=int, default=20, metavar="N",
                       dest="pii_scan_rows",
                       help="unique values per column scanned for PII (default "
                            "20; higher catches rarer PII, slower)")
    check.add_argument("--pii-scan-all", action="store_true", dest="pii_scan_all",
                       help="scan every value for PII (most thorough, slowest)")
    check.set_defaults(func=_cmd_check)

    risk = sub.add_parser(
        "risk", help="score how risky it is to send a dataset (and question) to AI")
    risk.add_argument("file", help="path to a data file")
    risk.add_argument("question", nargs="?", default=None,
                      help="optional question, to flag PII the answer doesn't need")
    risk.add_argument("--json", action="store_true",
                      help="emit machine-readable JSON")
    risk.add_argument("--pii-scan-rows", type=int, default=20, metavar="N",
                      dest="pii_scan_rows",
                      help="unique values per column scanned for PII (default 20)")
    risk.add_argument("--pii-scan-all", action="store_true", dest="pii_scan_all",
                      help="scan every value for PII (most thorough, slowest)")
    risk.set_defaults(func=_cmd_risk)

    plan = sub.add_parser(
        "plan", help="show the privacy plan (safe view) for a question")
    plan.add_argument("file", help="path to a data file")
    plan.add_argument("question", help="the question to plan for")
    plan.add_argument("--minimal", action="store_true",
                      help="advanced: also drop non-PII columns the question "
                           "doesn't reference (heuristic; may affect correctness)")
    plan.add_argument("--json", action="store_true",
                      help="emit the full plan as JSON")
    plan.set_defaults(func=_cmd_plan)

    return parser


def _cmd_plan(args) -> int:
    from .firewall import create_privacy_plan
    try:
        df = _load_dataframe(args.file)
    except (FileNotFoundError, ValueError) as e:
        if args.json:
            import json
            print(json.dumps({"error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        return 1

    mode = "minimal" if args.minimal else "drop_unneeded_pii"
    plan = create_privacy_plan(df, args.question, safe_mode=mode)
    if args.json:
        import json
        print(json.dumps(plan.to_dict(), indent=2, default=str))
    else:
        print(f"Question : {args.question}")
        print(f"Mode     : {plan.safe_mode}  (operation: {plan.operation})")
        print(f"Allowed  : {', '.join(plan.allowed_columns) or '(none)'}")
        print(f"Dropped PII: {', '.join(plan.dropped_pii_columns) or '(none)'}")
        if plan.retained_pii_columns:
            print(f"Kept PII (masked): {', '.join(plan.retained_pii_columns)}")
        print(f"Risk     : original={plan.original_risk_level} -> "
              f"safe view={plan.safe_view_risk_level}")
        print(f"Audit    : {plan.audit}")
        for w in plan.warnings:
            print(f"warning  : {w}")
    return 0


def _cmd_risk(args) -> int:
    from .analysis import ai_risk_score
    try:
        df = _load_dataframe(args.file)
    except (FileNotFoundError, ValueError) as e:
        if args.json:
            import json
            print(json.dumps({"error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        return 1

    scan_rows = "all" if getattr(args, "pii_scan_all", False) else \
        getattr(args, "pii_scan_rows", 20)
    r = ai_risk_score(df, args.question, scan_rows=scan_rows)
    if args.json:
        import json
        print(json.dumps(r, indent=2, default=str))
    else:
        print(f"AI risk: {r['risk_level'].upper()} ({r['score']}/100) "
              f"| recommended mode: {r['recommended_mode']}")
        for reason in r["reasons"]:
            print(f"  - {reason}")
    # non-zero exit for high risk, so it can gate a pipeline
    return 2 if r["risk_level"] == "high" else 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # Output was piped into something that closed early (e.g. `| head`).
        # Silence the traceback and exit quietly.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
