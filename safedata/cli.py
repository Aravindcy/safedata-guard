"""
Command-line interface for safedata-guard.

Mirrors the Python API's four doors:

    safedata scan     data.csv --profile banking
    safedata protect  data.csv --profile banking --question "balance by region" --out safe.csv
    safedata ask      data.csv "revenue by region" --profile banking --model openai
    safedata advanced inspect-policy banking
    safedata advanced shadow data.csv --rows 10
    safedata advanced leak-test data.csv --profile strict --model openai

`scan` and `protect` need no model. `ask` and `leak-test` need a model: pass
`--model openai` with OPENAI_API_KEY set (and `pip install safedata-guard[benchmark]`).
"""

import argparse
import json
import sys

from . import __version__


def _load_dataframe(path: str):
    """Read a CSV/TSV/Excel/Parquet/JSON file into a pandas DataFrame."""
    import os
    import pandas as pd

    if not os.path.exists(path):
        raise FileNotFoundError(f"No such file: {path}")
    lower = path.lower()
    try:
        if lower.endswith(".csv"):
            return pd.read_csv(path)
        if lower.endswith(".tsv"):
            return pd.read_csv(path, sep="\t")
        if lower.endswith((".xlsx", ".xls")):
            return pd.read_excel(path)
        if lower.endswith(".parquet"):
            return pd.read_parquet(path)
        if lower.endswith(".json"):
            return pd.read_json(path)
    except Exception as e:
        raise ValueError(f"Could not read '{path}': {e}")
    raise ValueError(
        f"Unsupported file type: '{path}'. Supported: .csv, .tsv, .xlsx, "
        f".xls, .parquet, .json")


def _df_or_error(args):
    try:
        return _load_dataframe(args.file), None
    except (FileNotFoundError, ValueError) as e:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        return None, 1


def _openai_model():
    """Return a (prompt -> text) callable backed by OpenAI, or raise SystemExit."""
    import os
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("error: set OPENAI_API_KEY to use --model openai.")
    try:
        from openai import OpenAI
    except ImportError:
        raise SystemExit("error: install OpenAI support: pip install safedata-guard[openai]")
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    model_name = os.environ.get("SAFEDATA_MODEL", "gpt-4o-mini")

    def _call(prompt):
        r = client.chat.completions.create(
            model=model_name, messages=[{"role": "user", "content": prompt}],
            temperature=0)
        return r.choices[0].message.content
    return _call


def _resolve_model(args):
    if getattr(args, "model", None) == "openai":
        return _openai_model()
    return None


# --- commands ---------------------------------------------------------------

def _cmd_scan(args) -> int:
    from . import scan
    df, err = _df_or_error(args)
    if err:
        return err
    report = scan(df, profile=args.profile)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(f"File        : {args.file}  ({report.rows} rows x {report.columns} cols)")
        print(f"Risk level  : {report.risk_level.upper()}  "
              f"(AI-readiness {report.ai_readiness_score}/100)")
        print(f"PII         : {report.pii_columns}")
        print(f"Business IDs: {report.business_identifier_columns}")
        print(f"Financial   : {report.financial_columns}")
        print(f"Health      : {report.health_columns}")
        print(f"Free text   : {report.free_text_columns}")
        print(f"Quasi-ID    : {report.quasi_identifier_columns}")
        for r in report.recommendations:
            print(f"  - {r}")
    if args.fail_on == "high-risk":
        return 2 if report.risk_level == "high" else 0
    if args.fail_on == "pii":
        return 2 if report.pii_columns else 0
    return 0


def _cmd_protect(args) -> int:
    from . import protect
    df, err = _df_or_error(args)
    if err:
        return err
    safe_df, report = protect(df, question=args.question, profile=args.profile,
                              return_report=True)
    if args.out:
        safe_df.to_csv(args.out, index=False)
    if args.json:
        print(json.dumps({"out": args.out, "kept": report.kept_columns,
                          "dropped": report.dropped_columns,
                          "masked": report.masked_columns}, indent=2, default=str))
    else:
        print(f"Kept    : {report.kept_columns}")
        print(f"Dropped : {report.dropped_columns}")
        print(f"Masked  : {report.masked_columns}")
        if args.out:
            print(f"Safe view written to: {args.out}")
        else:
            print("(no --out given; safe view not written)")
    return 0


def _cmd_ask(args) -> int:
    from . import ask
    df, err = _df_or_error(args)
    if err:
        return err
    model = _resolve_model(args)
    if model is None and args.mode != "summary":
        print("error: `ask` needs a model. Pass --model openai (with "
              "OPENAI_API_KEY set), or use --mode summary for a no-model risk "
              "summary.", file=sys.stderr)
        return 2
    result = ask(df, args.question, model=model, profile=args.profile,
                 mode=args.mode)
    if args.receipt_out:
        with open(args.receipt_out, "w", encoding="utf-8") as fh:
            json.dump(result.receipt.to_dict(), fh, indent=2, default=str)
    if args.json:
        print(json.dumps({"blocked": result.blocked, "reason": result.reason,
                          "engine": result.engine, "warnings": result.warnings,
                          "answer": result.answer,
                          "receipt": result.receipt.to_dict()},
                         indent=2, default=str))
    else:
        print(f"Engine  : {result.engine}  | blocked: {result.blocked}")
        if result.reason:
            print(f"Reason  : {result.reason}")
        for w in result.warnings:
            print(f"warning : {w}")
        print(f"Answer  :\n{result.answer}")
        print(f"\nAudit   : {result.receipt.audit_id} "
              f"(python_fallback={result.receipt.python_fallback_used})")
    return 0 if not result.blocked else 2


def _cmd_advanced_inspect_policy(args) -> int:
    from .policy import Policy
    from .exceptions import PolicyError
    try:
        p = Policy.from_profile(args.profile)
    except PolicyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(p.to_dict(), indent=2, default=str))
    return 0


def _cmd_advanced_shadow(args) -> int:
    from .advanced import create_shadowframe
    df, err = _df_or_error(args)
    if err:
        return err
    shadow = create_shadowframe(df, rows=args.rows)
    if args.out:
        shadow.shadow_df.to_csv(args.out, index=False)
        print(f"Synthetic same-shape data written to: {args.out}")
    else:
        print(shadow.shadow_df.to_string(index=False))
    return 0


def _cmd_advanced_leak_test(args) -> int:
    from .advanced import leak_test
    from .policy import Policy
    df, err = _df_or_error(args)
    if err:
        return err
    model = _resolve_model(args)
    if model is None:
        print("error: leak-test needs --model openai.", file=sys.stderr)
        return 1
    report = leak_test(df, model=model, policy=Policy.from_profile(args.profile))
    print(f"LeakScore: {report.score}/100  ({report.risk_level} risk)")
    for a in report.attempts:
        flag = "LEAK" if a.leaked else ("blocked" if a.blocked else "ok")
        print(f"  [{flag:7}] {a.question[:60]}")
    return 0


# --- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safedata",
        description="Scan, protect, and safely ask AI questions over tabular data.")
    parser.add_argument("--version", action="version",
                        version=f"safedata-guard {__version__}")
    sub = parser.add_subparsers(dest="command")

    sc = sub.add_parser("scan", help="assess a dataset's privacy/quality risk")
    sc.add_argument("file")
    sc.add_argument("--profile", default="general")
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--fail-on", dest="fail_on", choices=["high-risk", "pii"],
                    help="exit non-zero (2) on high risk, or on any PII")
    sc.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("protect", help="write a privacy-filtered safe view")
    pr.add_argument("file")
    pr.add_argument("--profile", default="general")
    pr.add_argument("--question", default=None,
                    help="keep columns this question needs")
    pr.add_argument("--out", default=None, metavar="SAFE.csv")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=_cmd_protect)

    ak = sub.add_parser("ask", help="answer a question safely (needs --model)")
    ak.add_argument("file")
    ak.add_argument("question")
    ak.add_argument("--profile", default="general")
    ak.add_argument("--mode", default="auto",
                    choices=["auto", "plan", "summary", "python"])
    ak.add_argument("--model", default=None, choices=["openai"],
                    help="use OpenAI (needs OPENAI_API_KEY)")
    ak.add_argument("--receipt-out", dest="receipt_out", default=None,
                    metavar="RECEIPT.json")
    ak.add_argument("--json", action="store_true")
    ak.set_defaults(func=_cmd_ask)

    adv = sub.add_parser("advanced", help="advanced/power-user tools")
    advsub = adv.add_subparsers(dest="advanced_command")

    ip = advsub.add_parser("inspect-policy", help="print a profile's policy")
    ip.add_argument("profile")
    ip.set_defaults(func=_cmd_advanced_inspect_policy)

    sh = advsub.add_parser("shadow", help="synthetic same-shape data (no real values)")
    sh.add_argument("file")
    sh.add_argument("--rows", type=int, default=10)
    sh.add_argument("--out", default=None, metavar="SHADOW.csv")
    sh.set_defaults(func=_cmd_advanced_shadow)

    lt = advsub.add_parser("leak-test", help="privacy red-team score (needs --model)")
    lt.add_argument("file")
    lt.add_argument("--profile", default="strict")
    lt.add_argument("--model", default=None, choices=["openai"])
    lt.set_defaults(func=_cmd_advanced_leak_test)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if args.command == "advanced" and not getattr(args, "advanced_command", None):
        parser.parse_args(["advanced", "--help"])
        return 0
    try:
        return args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        from .exceptions import SafedataError
        if isinstance(e, SafedataError):
            print(f"error: {e}", file=sys.stderr)
            return 2
        raise
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
