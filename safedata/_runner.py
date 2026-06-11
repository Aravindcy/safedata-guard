"""
Child-process entry point for the bodyguard's isolated runner.

Invoked as:
    python -m safedata._runner <df.pkl> <code.py> <out.pkl> <result_var> <params.json>

params.json carries the guard options (allow_row_reduction, max_result_rows,
max_result_bytes, redact_result_pii). For backward compatibility a bare "1"/"0"
in that position is still accepted as allow_row_reduction.

It loads the DataFrame and code, runs the already-screened code through the same
invariant checks used in-process, and writes ('ok', result) or
('blocked', message) to <out.pkl>. Running here (rather than in the host
process) is what lets the caller enforce a timeout and survive a crash.
"""

import sys
import json
import pickle


def _load_params(arg):
    """Parse the 5th argv: a params.json path, the literal '1'/'0' (legacy
    allow_row_reduction flag), or absent."""
    if not arg:
        return {}
    if arg in ("0", "1"):
        return {"allow_row_reduction": arg == "1"}
    try:
        with open(arg, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def main(argv):
    df_path, code_path, out_path, result_var = argv[1], argv[2], argv[3], argv[4]
    params = _load_params(argv[5] if len(argv) > 5 else None)

    with open(df_path, "rb") as f:
        df = pickle.load(f)
    with open(code_path, "r", encoding="utf-8") as f:
        code = f.read()

    from safedata.bodyguard import _execute_checked
    status, payload = _execute_checked(code, df, result_var, **params)

    try:
        with open(out_path, "wb") as f:
            pickle.dump((status, payload), f)
    except Exception as e:
        # Result wasn't picklable (rare). Report it as a clear block instead of
        # leaving the parent with no output file.
        with open(out_path, "wb") as f:
            pickle.dump(
                ("blocked",
                 f"The result could not be returned across the sandbox "
                 f"({type(e).__name__}: {e}). Return a simpler value in "
                 f"'{result_var}' (number, string, list, dict, or DataFrame)."),
                f)


if __name__ == "__main__":
    main(sys.argv)
