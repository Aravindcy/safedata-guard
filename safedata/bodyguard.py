"""
THE BODYGUARD.

Takes AI-written code and runs it with guardrails:
  1. AST screen: parse the code and refuse imports, dunder/introspection
     access, dangerous builtins, and data/file writers BEFORE running.
  2. Run on a COPY of the data, in a separate process with a timeout, so a
     hang or crash cannot take down the host and the original is never exposed.
  3. Check invariants: did the code silently shrink df (drop/filter away
     rows)? is the result silently empty? (In-place column edits and type
     conversions are allowed: the code only ever touches a deep copy.)
  4. Return either a clean result OR an actionable error message the AI can
     use to fix its own code.

IMPORTANT: what this is and is NOT.
This is DEFENSE IN DEPTH for cooperative / semi-trusted model output: it stops
the destructive accidents an honest model makes, and the obvious escape
attempts. It is NOT a security sandbox for deliberately malicious untrusted
code. In-process Python "sandboxes" have a long history of clever escapes, and
on Windows there is no cheap way to drop a child process's filesystem
permissions. For genuinely untrusted code, run this inside OS-level isolation
(a container, a locked-down user, or a VM). See run_safely(isolate=...).
"""

import ast
import os
import re
import sys
import copy
import shlex
import shutil
import pickle
import tempfile
import subprocess
import pandas as pd

try:
    import numpy as np  # pandas dependency, so effectively always present
    _HAS_NUMPY = True
except Exception:  # pragma: no cover
    np = None
    _HAS_NUMPY = False

try:
    import polars as pl  # optional; only needed if the caller uses Polars
    _HAS_POLARS = True
except Exception:  # pragma: no cover - import failure path
    pl = None
    _HAS_POLARS = False


def _is_frame(obj):
    """True for a pandas or polars DataFrame."""
    if isinstance(obj, pd.DataFrame):
        return True
    return _HAS_POLARS and isinstance(obj, pl.DataFrame)


class SafetyError(Exception):
    """Raised when code is blocked. Message is meant to be fed back to the AI."""


class _IsolationUnavailable(Exception):
    """Internal: the subprocess runner could not be used; fall back in-process."""


# --- static screen (AST, not regex) ----------------------------------------
#
# A regex denylist only stops what you remembered to list (this library shipped
# with exactly that bug: it blocked to_csv but not to_json). We parse the code
# instead and reason about real syntax nodes. This is still a static check and
# is not unbreakable, getattr(obj, computed_string) can defeat any static
# analysis, which is why getattr itself is blocked and why real isolation lives
# in the subprocess runner. Treat this as fast-fail, not as the boundary.

# Builtins / names that have no place in an in-memory analysis and are the usual
# tools of an escape.
_BLOCKED_BUILTINS = {
    "eval", "exec", "compile", "open", "input", "breakpoint", "help",
    "getattr", "setattr", "delattr", "globals", "locals", "vars",
    "memoryview", "__import__", "exit", "quit",
}

# Modules that mean filesystem / system / serialization access.
_BLOCKED_MODULES = {
    "os", "sys", "subprocess", "shutil", "socket", "importlib", "ctypes",
    "builtins", "pickle", "marshal", "code", "pty", "posix", "nt", "pathlib",
}

# Internal IO gateways of pandas/numpy. Their private file helpers (get_handle,
# file_exists, DataSource, ...) can read and write the filesystem just like the
# public read_*/to_* methods, but a method-name denylist can never enumerate
# them all. You cannot REACH those helpers without first traversing one of these
# submodule names, so we block the gateway segment instead and close the whole
# subtree (pd.io.*, pandas.io.*, np.lib.*, numpy.lib.*, ...) in one rule.
# These are namespace traversals, not values an analyst computes with, so
# refusing them does not get in the way of real work.
_BLOCKED_ATTR_SEGMENTS = {"io", "lib", "common", "npyio", "compat", "_libs",
                          "ctypeslib", "f2py"}

# Refuse these names directly, however they are reached. Two kinds live here:
# private file helpers (get_handle/file_exists/DataSource/urlopen) and public
# file-backed CLASSES (ExcelWriter/ExcelFile/HDFStore) and the native-library
# loader (load_library). None are method calls, so the writer/reader screens
# (which match df.to_*/read_* attributes) miss them; we list them explicitly.
_BLOCKED_HELPERS = {"get_handle", "file_exists", "DataSource", "urlopen",
                    "ExcelWriter", "ExcelFile", "HDFStore", "load_library"}

# IO writers that put data on disk or in a database. Blocked always, none of
# these are needed to COMPUTE an answer in memory. Covers both pandas (to_*)
# and polars (write_*, plus lazy sink_*).
_WRITER_METHODS = {
    # pandas
    "to_csv", "to_excel", "to_parquet", "to_sql", "to_pickle", "to_hdf",
    "to_feather", "to_json", "to_xml", "to_stata", "to_orc", "to_gbq",
    "to_clipboard", "to_latex",
    # polars eager writers
    "write_csv", "write_excel", "write_parquet", "write_json", "write_ndjson",
    "write_ipc", "write_ipc_stream", "write_avro", "write_delta",
    "write_database", "write_clipboard", "write_iceberg",
    # polars lazy sinks (stream straight to disk)
    "sink_csv", "sink_parquet", "sink_ipc", "sink_ndjson", "sink_delta",
    "sink_iceberg", "sink_batches",
    # numpy writers (now reachable since numpy import + np are allowed)
    "save", "savez", "savez_compressed", "savetxt", "tofile", "dump",
}

# Dual-use: these RETURN a string with no argument (legitimate display) but can
# also write to a path/buffer when given one. Block only when called with args.
_DUAL_WRITERS = {"to_html", "to_markdown", "to_string"}

# pandas/polars string-expression channels. These parse their OWN mini-language
# at runtime, which our AST screen never sees, so a model could smuggle work past
# the static analysis through them (e.g. df.query("...")). They are rarely needed
# for analysis the model can express directly in Python, so we refuse them and
# tell the model to write the expression as normal code instead.
_EXPR_CHANNELS = {"eval", "query"}

# str.format / str.format_map are a second string mini-language the AST never
# sees. A field like '{0.__init__.__globals__}' performs attribute traversal
# INSIDE the literal, walking object -> __init__ -> __globals__ to read a
# module's globals (config, secrets, API keys) and return them as a string.
# f-strings are safe because their fields are real AST nodes the dunder screen
# already inspects; .format()/.format_map() are not. We refuse any format whose
# template we cannot prove harmless, and tell the model to use an f-string.
_FORMAT_CHANNELS = {"format", "format_map"}

# Modules a data analyst legitimately needs. `import pandas as pd` is a near-
# universal reflex even though pd is already provided, and date/number work
# needs these. We allow only this small set; anything else (os, sys, requests,
# ...) is still refused. Note: even an allowed import can't reach the filesystem,
# because the dunder/module-name screen below still blocks `pandas.io...os` etc.
_ALLOWED_IMPORTS = {"pandas", "numpy", "math", "statistics", "datetime", "re"}

# Readers that pull data IN from disk/network. Not needed to analyse the df we
# already handed in, and some (read_pickle) execute arbitrary code from the
# file. Blocked always. Covers pandas (read_*) and polars (read_*, scan_*).
_READER_METHODS = {
    # pandas
    "read_pickle", "read_csv", "read_excel", "read_parquet", "read_sql",
    "read_sql_query", "read_sql_table",
    "read_hdf", "read_feather", "read_json", "read_xml", "read_stata",
    "read_orc", "read_gbq", "read_clipboard", "read_html", "read_table",
    "read_fwf", "read_sas", "read_spss",
    # polars eager + lazy readers
    "read_avro", "read_database", "read_database_uri", "read_delta",
    "read_ipc", "read_ipc_stream", "read_ndjson", "read_ods", "read_lines",
    "scan_csv", "scan_parquet", "scan_ipc", "scan_ndjson", "scan_delta",
    "scan_iceberg", "scan_lines", "scan_pyarrow_dataset",
    # numpy readers (some load arbitrary objects; all touch disk)
    "load", "loadtxt", "genfromtxt", "fromfile", "fromregex", "memmap",
}


def _refuse_blocked_components(parts, full_name):
    """Refuse a dotted import path whose any component names a blocked module.

    Catches re-exported stdlib modules reached through an allowed package, e.g.
    `pandas.io.common.os`, which would otherwise smuggle the filesystem past the
    root-only allowlist.
    """
    for part in parts:
        if part in _BLOCKED_MODULES or part in _BLOCKED_ATTR_SEGMENTS:
            raise SafetyError(
                f"Blocked: '{full_name}' reaches the internal '{part}' "
                f"namespace (filesystem/system access) through an allowed "
                f"package. Compute the answer in memory instead.")


def _format_field_is_dangerous(field_name: str) -> bool:
    """True if a format replacement field traverses into the object.

    A plain field ('', '0', 'name') only substitutes a value and is safe. A
    field with attribute access ('0.attr') or indexing ('0[key]') reaches INTO
    the argument, which is the escape route ('{0.__init__.__globals__}'). We
    treat any '.' or '[' in the field name as dangerous.
    """
    return bool(field_name) and ("." in field_name or "[" in field_name)


def _format_template_is_dangerous(template: str) -> bool:
    """Scan a literal format string for fields that traverse the argument.

    Also recurses into nested fields inside a format spec (e.g.
    '{0:{1.__class__}}'). If the template can't be parsed, treat it as dangerous
    (fail closed)."""
    import string as _string
    try:
        for _lit, field, spec, _conv in _string.Formatter().parse(template):
            if _format_field_is_dangerous(field):
                return True
            if spec and "{" in spec:
                for _l2, f2, _s2, _c2 in _string.Formatter().parse(spec):
                    if _format_field_is_dangerous(f2):
                        return True
    except Exception:
        return True
    return False


def _static_screen(code: str):
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as e:
        raise SafetyError(
            f"Your code has a syntax error: {e}. Fix the syntax and try again.")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # Allowlist the root, AND refuse if any dotted component names a
                # blocked module. Otherwise `import pandas.io.common.os as safe`
                # binds the real os module to an unscreened name (`safe.system`).
                parts = alias.name.split(".")
                if parts[0] not in _ALLOWED_IMPORTS:
                    raise SafetyError(
                        f"Blocked: importing '{alias.name}' is not allowed. "
                        f"Only {sorted(_ALLOWED_IMPORTS)} may be imported; "
                        f"`df`, `pd`, and `np` are already available.")
                _refuse_blocked_components(parts, alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            parts = module.split(".") if module else []
            if not parts or parts[0] not in _ALLOWED_IMPORTS:
                raise SafetyError(
                    f"Blocked: importing from '{node.module}' is not allowed. "
                    f"Only {sorted(_ALLOWED_IMPORTS)} may be imported; "
                    f"`df`, `pd`, and `np` are already available.")
            # The module path may itself end in a blocked module...
            _refuse_blocked_components(parts, module)
            # ...and so may the imported SYMBOL. This is the real-world hole:
            # `from pandas.io.common import os as safe` re-exports the stdlib os
            # module under a name the rest of the screen never inspects.
            for alias in node.names:
                leaf = alias.name.split(".")[-1]
                if leaf in _BLOCKED_MODULES or leaf in _BLOCKED_BUILTINS:
                    raise SafetyError(
                        f"Blocked: importing '{alias.name}' from "
                        f"'{node.module}' pulls in a system module/builtin "
                        f"({leaf}). Compute the answer in memory instead.")
                # A writer/reader is screened by ATTRIBUTE name (df.to_csv), but
                # `from numpy import save` / `from pandas import read_csv` binds
                # it as a BARE callable the attribute screen never sees. Refuse
                # importing those functions by name too.
                if leaf in _WRITER_METHODS or leaf in _DUAL_WRITERS:
                    raise SafetyError(
                        f"Blocked: importing '{leaf}' from '{node.module}' "
                        f"imports a data writer. Return the value in `result` "
                        f"instead of writing it out.")
                if leaf in _READER_METHODS:
                    raise SafetyError(
                        f"Blocked: importing '{leaf}' from '{node.module}' "
                        f"imports a disk/network reader. Use only the provided "
                        f"`df`; everything you need is already in it.")
                if leaf in _BLOCKED_HELPERS:
                    raise SafetyError(
                        f"Blocked: importing '{leaf}' from '{node.module}' "
                        f"imports a file/native-library helper. Compute the "
                        f"answer in memory instead.")
                if leaf in _BLOCKED_ATTR_SEGMENTS:
                    raise SafetyError(
                        f"Blocked: importing the internal '{leaf}' namespace "
                        f"from '{node.module}'. Use only the public, in-memory "
                        f"API of `df`.")

        if isinstance(node, ast.Attribute):
            attr = node.attr
            if attr.startswith("__") and attr.endswith("__"):
                raise SafetyError(
                    f"Blocked: access to dunder attribute '{attr}'. This is the "
                    f"classic introspection-escape route; remove it.")
            if attr in _BLOCKED_MODULES:
                raise SafetyError(
                    f"Blocked: reaching the '{attr}' module (filesystem/system "
                    f"access). Compute the answer in memory instead.")
            if attr in _BLOCKED_ATTR_SEGMENTS:
                raise SafetyError(
                    f"Blocked: reaching the internal '{attr}' namespace (e.g. "
                    f"pd.{attr}.*, np.{attr}.*), which exposes private file "
                    f"helpers. Use only the public, in-memory API of `df`.")
            if attr in _BLOCKED_HELPERS:
                raise SafetyError(
                    f"Blocked: '{attr}' is an internal file helper. Compute the "
                    f"answer in memory instead.")
            # Catch writers/readers at the ATTRIBUTE site, not just the call site.
            # Otherwise `w = df.to_csv; w('x')` (binding the bound method to a
            # name, then calling the name) slips past a call-only check. We refuse
            # the moment the dangerous attribute is referenced at all, however it
            # is later invoked. (Dual-use display writers like to_string stay
            # call-site-only below, so `df.to_string()` with no args still works.)
            if attr in _WRITER_METHODS:
                raise SafetyError(
                    f"Blocked: '{attr}' writes data to disk/database. Return the "
                    f"value in `result` instead of writing it out (and don't "
                    f"alias the method to another name to dodge this).")
            if attr in _READER_METHODS:
                raise SafetyError(
                    f"Blocked: '{attr}' reads from disk/network (and some readers "
                    f"run code from the file). Use only the provided `df`; "
                    f"everything you need is already in it.")

        if isinstance(node, ast.Name):
            if node.id in _BLOCKED_BUILTINS or node.id in _BLOCKED_MODULES:
                raise SafetyError(
                    f"Blocked: '{node.id}' is not allowed here. Compute the "
                    f"answer in memory without it.")
            # Bare dunder NAMES (not just attributes), e.g. `__build_class__`,
            # `__builtins__`, used as a default arg or free variable to reach the
            # builtins namespace. The attribute screen above only sees `x.__y__`;
            # this catches the name on its own.
            if node.id.startswith("__") and node.id.endswith("__"):
                raise SafetyError(
                    f"Blocked: access to dunder name '{node.id}'. This is a "
                    f"classic introspection-escape route; remove it.")

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            # Writers/readers are already refused at the attribute site above;
            # here we only need the two call-shape-dependent checks.
            if name in _DUAL_WRITERS and (node.args or node.keywords):
                raise SafetyError(
                    f"Blocked: '{name}(...)' with arguments can write to a file. "
                    f"Call it with no arguments, or build the answer in memory.")
            if name in _EXPR_CHANNELS:
                raise SafetyError(
                    f"Blocked: '{name}(...)' evaluates a string expression that "
                    f"this safety screen cannot inspect. Write the calculation as "
                    f"normal Python on `df` instead (e.g. df['a'] * 2, not "
                    f"df.eval('a * 2')).")
            if name in _FORMAT_CHANNELS:
                recv = node.func.value
                # A literal template we can inspect: refuse only if a field
                # traverses the argument ('{0.attr}'); plain '{:.2f}' stays fine.
                if (isinstance(recv, ast.Constant)
                        and isinstance(recv.value, str)):
                    if _format_template_is_dangerous(recv.value):
                        raise SafetyError(
                            f"Blocked: '.{name}(...)' uses a format field that "
                            f"reaches into the object (e.g. "
                            f"'{{0.__init__.__globals__}}'), a known way to read "
                            f"internals past this screen. Use an f-string or plain "
                            f"Python instead.")
                else:
                    # Non-literal template: the screen can't see its contents,
                    # so it can't prove safety. Refuse, like df.eval/df.query.
                    raise SafetyError(
                        f"Blocked: '.{name}(...)' on a non-literal template, "
                        f"whose contents this screen cannot inspect. Build the "
                        f"string with an f-string or normal Python instead.")


class CodeCheck:
    """Result of check_code(): does the code pass the static screen, and why not.

    Attributes
    ----------
    safe : bool
        True if the code passed the static screen (imports, dunder/introspection,
        system modules, dangerous builtins, file readers/writers).
    reason : str or None
        If not safe, an explanation suitable to show a user or feed back to a
        model. None when safe.

    Truthy when safe, so you can write `if check_code(code): ...`.
    """

    __slots__ = ("safe", "reason")

    def __init__(self, safe: bool, reason: str = None):
        self.safe = safe
        self.reason = reason

    def __bool__(self):
        return self.safe

    def __repr__(self):
        if self.safe:
            return "CodeCheck(safe=True)"
        return f"CodeCheck(safe=False, reason={self.reason!r})"


def check_code(code: str) -> CodeCheck:
    """Statically check whether `code` would be allowed, WITHOUT running it.

    This runs the exact same static screen that run_safely() uses, but never
    executes anything and never needs a DataFrame. Use it as a standalone
    guardrail inside your own agent loop: inspect first, then decide whether to
    run, rewrite, or reject.

        verdict = check_code("df.to_csv('x.csv')")
        if not verdict.safe:
            handle(verdict.reason)   # e.g. ask the model to fix it

    IMPORTANT: same scope as the rest of the library. The static screen is
    fast-fail defense in depth, not a proof of safety: a passing result means
    "none of the screened dangers were found", not "guaranteed harmless". It
    does not run the code, so it cannot catch a runtime problem (an infinite
    loop, a wrong answer), only run_safely() applies the timeout and invariant
    checks. For untrusted code, still use OS-level isolation.
    """
    try:
        _static_screen(code)
        return CodeCheck(safe=True)
    except SafetyError as e:
        return CodeCheck(safe=False, reason=str(e))


def _screen_blocked_columns(code: str, blocked_columns):
    """Refuse code that references any forbidden column (least-privilege firewall).

    Catches both subscript access (df['email'], df[['email', ...]]) — seen as a
    string Constant — and attribute access (df.email). Refusing a column whose
    name merely appears as a string literal is acceptable here: blocked columns
    are the sensitive ones a question doesn't need, and the model is told exactly
    which to drop.
    """
    blocked = {str(c) for c in blocked_columns}
    if not blocked:
        return
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError:
        return  # the main screen reports syntax errors
    hit = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in blocked:
                hit.add(node.value)
        elif isinstance(node, ast.Attribute) and node.attr in blocked:
            hit.add(node.attr)
    if hit:
        names = ", ".join(sorted(hit))
        raise SafetyError(
            f"Blocked: the code accessed restricted column(s) the question does "
            f"not need: {names}. Remove them and use only the allowed columns.")


# --- the checked execution (shared by in-process and subprocess paths) ------

def _mask_blocked_columns(df, blocked_columns):
    """Replace forbidden columns' values with placeholders BEFORE the code runs.

    This is the real firewall: a static AST screen can refuse df['email'] but not
    positional/indirect access (df.iloc[:, 0], df.values, df.to_numpy(),
    df.columns[0]). If the restricted values simply aren't present in the copy
    the code executes against, none of those routes can leak them. Operates on
    the already-made deep copy, so the caller's frame is untouched.
    """
    blocked = {str(c) for c in (blocked_columns or [])}
    if not blocked:
        return df
    if isinstance(df, pd.DataFrame):
        n = len(df)
        for col in list(df.columns):
            if str(col) in blocked:
                df[col] = [f"[RESTRICTED_{j:03d}]" for j in range(n)]
        return df
    if _HAS_POLARS and isinstance(df, pl.DataFrame):
        exprs = [pl.Series(c, [f"[RESTRICTED_{j:03d}]" for j in range(df.height)])
                 for c in df.columns if str(c) in blocked]
        return df.with_columns(exprs) if exprs else df
    return df


def _execute_checked(code: str, df: pd.DataFrame, result_var: str = "result",
                     allow_row_reduction: bool = False,
                     max_result_rows=None, max_result_bytes=None,
                     redact_result_pii: bool = False, deepcopy_input: bool = True,
                     enforce_minimal_result: bool = False, blocked_columns=None,
                     block_1d_row_results: bool = False):
    """
    Run already-screened `code` against a deep copy of `df` and enforce the
    runtime invariants. Returns ('ok', result) or ('blocked', message).
    Never touches the `df` it is handed beyond reading it.

    allow_row_reduction : if True, the code may shrink `df` (drop/filter rows).
    Off by default because silently throwing away rows is the classic mistake;
    turn it on for questions whose answer legitimately reduces the frame.

    max_result_rows / max_result_bytes : cap the size of the returned value so a
    model can't hand back the entire table (the classic accidental full-data
    leak). Exceeding either is blocked with an actionable message rather than
    silently truncated, so the model can aggregate instead.
    redact_result_pii : if True, apply best-effort PII redaction to the returned
    value (frame object columns / strings) before it leaves the runner.
    """
    original_rows = df.shape[0]

    df_copy = _deep_copy_frame(df, deep_python=deepcopy_input)
    # Firewall: blank out restricted columns in the copy so NO access path
    # (subscript, attribute, .iloc, .values, .to_numpy(), itertuples) can read
    # them. The static screen still blocks direct df['col'] access for a clear
    # retry message; this guarantees the values are gone even when it can't see.
    if blocked_columns:
        df_copy = _mask_blocked_columns(df_copy, blocked_columns)
    # ONE shared namespace for globals and locals. Using separate dicts puts the
    # model's top-level assignments in `locals`, which functions/lambdas/comprehensions
    # defined in the same code cannot see (they resolve free names through the
    # module globals, not the exec locals). That makes ordinary code fail, e.g.
    #   threshold = 2
    #   result = df['a'].map(lambda x: x > threshold)   # NameError on threshold
    # Sharing one dict gives module-level scoping, which is what such code expects.
    sandbox = {"pd": pd, "__builtins__": _safe_builtins(), "df": df_copy}
    if _HAS_NUMPY:
        sandbox["np"] = np
    if _HAS_POLARS:
        sandbox["pl"] = pl

    try:
        exec(code, sandbox, sandbox)
    except Exception as e:
        return ("blocked",
                f"Your code raised {type(e).__name__}: {e}. Fix the code so it "
                f"runs without error.")

    # The original is safe by construction, code only ever sees a deep copy, so
    # the real object handed to us is never exposed. We therefore do NOT police
    # in-place column edits or type conversions: those are normal, harmless
    # analysis on the copy (this is what `df['col'] = pd.to_datetime(...)` needs).
    #
    # The one thing we still guard is silently SHRINKING the data: dropping rows
    # or rebinding df to a filtered subset, which is the classic "I accidentally
    # threw away rows" mistake. Adding rows/columns is fine; losing rows is not.
    df_after = sandbox.get("df")
    if (not allow_row_reduction and _is_frame(df_after)
            and df_after.shape[0] < original_rows):
        return ("blocked",
                f"Your code reduced df from {original_rows} to "
                f"{df_after.shape[0]} rows. Don't drop rows from df or reassign "
                f"it to a filtered subset; put any filtered data in a NEW "
                f"variable and keep df at its full length.")

    if result_var not in sandbox:
        return ("blocked",
                f"Your code did not assign the answer to a variable named "
                f"'{result_var}'. End your code with {result_var} = <answer>.")

    result = sandbox[result_var]

    if _is_frame(result) and len(result) == 0 and original_rows > 0:
        return ("blocked",
                "Your result is EMPTY although the input had rows. Likely a "
                "filter that matched nothing; check your condition.")

    # Result-minimisation: returning every input row as a full-width, row-level
    # structure (frame, records list, 2-D array, dict-of-columns) is almost never
    # the answer to an aggregate question and over-exposes data. We deliberately
    # do NOT flag a 1-D aggregate (a groupby Series) that merely happens to have
    # original_rows entries, to avoid false-blocking legitimate aggregates.
    if enforce_minimal_result and original_rows > 1:
        rrows = _result_rows(result)
        # block_1d_row_results widens this to 1-D per-row results (a Series or
        # list of scalars with one value per input row), which leak row-level
        # data even though they aren't full-width. Stricter, with a small chance
        # of flagging a groupby that happens to have original_rows groups — which
        # is why it's opt-in (on in Agent.strict).
        row_level = _looks_row_level(result) or (
            block_1d_row_results and rrows is not None)
        if row_level and rrows is not None and rrows == original_rows:
            return ("blocked",
                    f"Your result returns all {original_rows} input rows. The "
                    f"question expects an aggregated/summary answer, not the full "
                    f"table. Group or aggregate (e.g. groupby(...).mean()) and "
                    f"return that.")

    return _guard_result(result, max_result_rows, max_result_bytes,
                         redact_result_pii)


def _looks_row_level(result):
    """True for a FULL-WIDTH, row-level structure (vs a 1-D aggregate).

    Used by enforce_minimal_result so a groupby Series that coincidentally has N
    entries isn't mistaken for "returned all rows". Frames, 2-D arrays, dict-of-
    columns, and lists-of-records count; a bare 1-D Series/list of scalars does
    not.
    """
    if _is_frame(result):
        return True
    if _HAS_NUMPY and isinstance(result, np.ndarray):
        return result.ndim >= 2
    if isinstance(result, dict):
        return any(isinstance(v, (list, tuple, pd.Series))
                   for v in result.values())
    if isinstance(result, (list, tuple)):
        return len(result) > 0 and all(
            isinstance(x, (dict, list, tuple)) for x in result)
    return False


def _result_rows(result):
    """Row count for a row-shaped result, or None if size isn't row-shaped.

    Covers the ways a model can hand back rows while dodging a frame check:
    list/tuple of rows, a dict-of-columns (df.to_dict('list')), a list-of-dicts
    (df.to_dict('records'), counted by the outer list), and numpy arrays.
    """
    if _is_frame(result):
        return result.shape[0]
    if isinstance(result, pd.Series):
        return len(result)
    if _HAS_POLARS and isinstance(result, pl.Series):
        return len(result)
    if isinstance(result, (list, tuple)):
        return len(result)
    if isinstance(result, dict):
        lengths = [len(v) for v in result.values()
                   if isinstance(v, (list, tuple, pd.Series))]
        return max(lengths) if lengths else None
    if _HAS_NUMPY and isinstance(result, np.ndarray):
        return result.shape[0] if result.ndim >= 1 else None
    return None


def _guard_result(result, max_result_rows, max_result_bytes, redact_result_pii):
    """Enforce result-size and result-privacy caps, then return ('ok', result).

    Blocks (with an AI-friendly message) when the result is too large; redaction
    transforms the value in place rather than blocking, since it can't fail the
    answer, only sanitise it.
    """
    if max_result_rows is not None:
        rows = _result_rows(result)
        if rows is not None and rows > max_result_rows:
            return ("blocked",
                    f"Your result has {rows} rows, over the {max_result_rows}-row "
                    f"limit. Return an aggregate or the top-N rows (e.g. "
                    f".head({max_result_rows})), not the full table.")

    if max_result_bytes is not None:
        try:
            size = len(pickle.dumps(result))
        except Exception:
            size = None
        if size is not None and size > max_result_bytes:
            return ("blocked",
                    f"Your result is ~{size} bytes, over the {max_result_bytes}-"
                    f"byte limit. Return a summary/aggregate instead of the raw "
                    f"data.")

    if redact_result_pii:
        result = _redact_result(result)

    return ("ok", result)


# Tokens in a key/column name that mark it as PII. The strong set is PII on its
# own; "name" is ambiguous ("product name"), so we only treat it as PII when a
# person-context token is also present, or the key is literally name/names.
# Mirrors safedata.analysis._pii_name_hints so the two agree.
_PII_KEY_STRONG = {"email", "phone", "mobile", "telephone", "msisdn", "ssn",
                   "nino", "sin", "address", "postcode", "zipcode", "zip",
                   "dob", "birth", "surname"}
_PII_KEY_PERSON = {"first", "last", "sur", "full", "fore", "middle", "maiden",
                   "given", "family", "contact", "person", "customer", "client",
                   "employee", "user", "holder", "patient", "member",
                   "applicant", "policyholder", "driver"}


def _key_suggests_pii(key) -> bool:
    """True if a dict key / name string looks like personal data."""
    toks = set(re.findall(r"[a-z0-9]+", str(key).lower()))
    if toks & _PII_KEY_STRONG:
        return True
    if "name" in toks and (toks & _PII_KEY_PERSON or toks <= {"name", "names"}):
        return True
    return False


def _redact_result(result):
    """Best-effort PII redaction of a returned value before it leaves the runner.

    Recursive and name-aware: strings get regex redaction; DataFrame/Series PII
    columns (detected by value AND by name, so 'customer_name' is caught) are
    fully replaced with [REDACTED], other object cells get regex redaction;
    dict/list/tuple/set are walked, redacting values under PII-looking keys.
    Numeric and other types pass through. Best-effort only (it cannot catch a
    name buried in a free-text scalar); see safedata.pii for the limits.
    """
    from . import pii as _pii

    if isinstance(result, str):
        return _pii.redact_text(result)
    if isinstance(result, dict):
        return {k: ("[REDACTED]" if _key_suggests_pii(k) else _redact_result(v))
                for k, v in result.items()}
    if isinstance(result, list):
        return [_redact_result(v) for v in result]
    if isinstance(result, tuple):
        return tuple(_redact_result(v) for v in result)
    if isinstance(result, set):
        return {_redact_result(v) for v in result}

    if isinstance(result, pd.DataFrame):
        out = result.copy()
        pii_cols = _detected_pii_columns(out)
        for col in out.columns:
            if col in pii_cols:
                out[col] = "[REDACTED]"
            elif out[col].dtype == object:
                out[col] = out[col].map(
                    lambda v: _pii.redact_text(v) if isinstance(v, str) else v)
        return out
    if isinstance(result, pd.Series):
        if _key_suggests_pii(result.name):
            return result.map(lambda v: "[REDACTED]")
        if result.dtype == object:
            return result.map(
                lambda v: _pii.redact_text(v) if isinstance(v, str) else v)
        return result
    if _HAS_NUMPY and isinstance(result, np.ndarray):
        # Regex-redact string cells. NOTE: once a column has been flattened into
        # an array its name context is gone, so this catches emails/phones but
        # not bare names — the firewall's column masking is what stops those.
        if result.dtype == object or result.dtype.kind in ("U", "S"):
            out = result.astype(object).copy()
            flat = out.reshape(-1)
            for i, v in enumerate(flat):
                if isinstance(v, str):
                    flat[i] = _pii.redact_text(v)
            return out
        return result
    return result


def _detected_pii_columns(df):
    """PII column names for a result frame: name-hinted (catches 'customer_name')
    plus value-detected, via the analysis layer; falls back to name hints only."""
    try:
        from .analysis import privacy_report
        return set(privacy_report(df)["pii_columns"])
    except Exception:
        return {c for c in df.columns if _key_suggests_pii(c)}


# Default resource limits for the container ("docker"/"container") isolation
# mode. Conservative on purpose: no network, a read-only root filesystem, and
# modest memory/CPU so a runaway analysis can't exhaust the host. Override any of
# them per call via run_safely(..., docker_image=..., memory=..., cpus=...,
# network=...).
#
# IMPORTANT: the image must ALREADY have safedata + pandas/numpy installed.
# The locked-down defaults (no network, read-only root fs) deliberately make a
# run-time `pip install` impossible — there is nothing to download from and
# nowhere to write it. Build the bundled image once (see the repo Dockerfile):
#     docker build -t safedata-guard-runner:1.0.8 .
# then this mode runs offline and read-only. `pip_install` stays None by default
# for exactly that reason; set it (and relax network/read_only) only if you
# really want run-time installation in a throwaway, trusted-network container.
DOCKER_DEFAULTS = {
    "image": "safedata-guard-runner:1.0.8",
    "memory": "512m",
    "cpus": "1.0",
    "network": "none",       # no network at all
    "read_only": True,        # read-only root fs; only the work mount is writable
    "pip_install": None,      # image must already contain safedata (see Dockerfile)
}


def run_safely(code: str, df: pd.DataFrame, result_var: str = "result",
               isolate: bool = True, timeout: float = 10.0,
               allow_row_reduction: bool = False, isolation: str = None,
               max_result_rows: int = None, max_result_bytes: int = None,
               redact_result_pii: bool = False, blocked_columns=None,
               enforce_minimal_result: bool = False,
               block_1d_row_results: bool = False, **docker_opts):
    """
    Execute `code` against a copy of `df`, enforcing safety invariants.

    The code should assign its answer to a variable named `result_var` and may
    read a DataFrame named `df`. Returns the value of `result_var`.

    Parameters
    ----------
    isolate : bool
        Legacy switch. True (default) runs in a separate process with `timeout`
        enforced; False runs in-process. `isolation=` (below) takes precedence
        when given.
    isolation : str or None
        Explicit isolation mode, overrides `isolate` when set:
          - "process" (or None+isolate=True): separate OS process + timeout.
          - "thread"/"inprocess" (or None+isolate=False): in-process, soft
            timeout via a worker thread. No filesystem isolation.
          - "docker"/"container": run inside a throwaway container with NO
            network, a read-only root filesystem, and memory/CPU limits, so even
            deliberately hostile code can't reach the host. Requires Docker and
            an image with safedata installed (see DOCKER_DEFAULTS); tune via
            docker_image=, memory=, cpus=, network=. This is the mode to use for
            UNTRUSTED model output in production.
    timeout : float
        Seconds before isolated code is stopped. Ignored for in-process mode.
    allow_row_reduction : bool
        If True, the code may shrink `df` (drop/filter rows). Off by default,
        because silently discarding rows is the most common accidental-damage
        pattern; enable it for questions whose answer legitimately reduces the
        frame.
    max_result_rows / max_result_bytes : int or None
        Cap the size of the returned value so a model can't hand back the whole
        table. Exceeding either is blocked (the model is told to aggregate),
        rather than silently truncated.
    redact_result_pii : bool
        Apply best-effort PII redaction to the returned value before it leaves
        the runner.
    blocked_columns : iterable of str or None
        Column names the generated code may NOT touch (a least-privilege
        firewall). Referencing one — by subscript ``df['col']`` or attribute
        ``df.col`` — is blocked before the code runs. Pair with
        ``create_contract(df, question)`` to forbid the PII columns a question
        doesn't need.
    enforce_minimal_result : bool
        If True, block a result that is the full, unaggregated input frame
        (row-for-row), so an aggregate question can't quietly return every row.

    Raises SafetyError (with an AI-friendly message) if anything is unsafe.
    """
    if not _is_frame(df):
        raise TypeError(
            f"safedata.run_safely expects a pandas or polars DataFrame, got "
            f"{type(df).__name__}. Pass the DataFrame you want analysed as `df`.")

    _static_screen(code)
    if blocked_columns:
        _screen_blocked_columns(code, blocked_columns)

    guards = dict(allow_row_reduction=allow_row_reduction,
                  max_result_rows=max_result_rows,
                  max_result_bytes=max_result_bytes,
                  redact_result_pii=redact_result_pii,
                  enforce_minimal_result=enforce_minimal_result,
                  block_1d_row_results=block_1d_row_results,
                  blocked_columns=list(blocked_columns) if blocked_columns else None)

    mode = _resolve_isolation(isolation, isolate)

    if mode == "docker":
        try:
            return _run_docker(code, df, result_var, timeout, guards,
                               docker_opts)
        except _IsolationUnavailable as e:
            # Deliberately do NOT silently downgrade to in-process for untrusted
            # code; fail loudly so the caller fixes the environment.
            raise RuntimeError(
                f"isolation='docker' could not run: {e}. Fix the Docker setup, "
                f"or choose isolation='process' if this code is not untrusted."
            ) from e

    if mode == "process":
        try:
            return _run_isolated(code, df, result_var, timeout, guards)
        except _IsolationUnavailable:
            # Subprocess unavailable (e.g. df not picklable). Fall back, but keep
            # the timeout promise by running in-process on a worker thread.
            return _run_inprocess_with_timeout(
                code, df, result_var, timeout, guards)

    if mode == "thread":
        return _run_inprocess_with_timeout(code, df, result_var, timeout, guards)

    status, payload = _execute_checked(code, df, result_var, **guards)
    if status == "blocked":
        raise SafetyError(payload)
    return payload


def _resolve_isolation(isolation, isolate):
    """Normalise the isolation choice to one of: process | thread | docker | none."""
    if isolation is None:
        return "process" if isolate else "none"
    m = str(isolation).lower()
    if m in ("docker", "container"):
        return "docker"
    if m in ("process", "subprocess"):
        return "process"
    if m in ("thread", "inprocess", "in-process"):
        return "thread"
    if m in ("none", "off"):
        return "none"
    raise ValueError(
        f"unknown isolation={isolation!r}; use 'process', 'thread', 'docker', "
        f"or 'none'.")


def _run_inprocess_with_timeout(code, df, result_var, timeout, guards):
    """In-process execution with a soft timeout via a daemon worker thread.

    A Python thread cannot be force-killed, so a truly wedged C-level call can
    still run on in the background, but the CALLER is freed at `timeout` with a
    clear SafetyError instead of hanging forever. This is the best we can do
    when the subprocess runner is unavailable; for hard isolation use a
    container.
    """
    import threading

    box = {}

    def _work():
        # Capture any exception so the caller gets a real error, not a bare
        # KeyError('out') from a worker that died before storing its result.
        try:
            box["out"] = _execute_checked(code, df, result_var, **guards)
        except BaseException as e:  # noqa: BLE001 - re-raised on the main thread
            box["err"] = e

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise SafetyError(
            f"Your code did not finish within {timeout:g}s and was abandoned "
            f"(possible infinite loop or runaway operation). Make it terminate "
            f"quickly.")
    if "err" in box:
        raise box["err"]
    status, payload = box["out"]
    if status == "blocked":
        raise SafetyError(payload)
    return payload


def _write_job(tmp, df, code, guards):
    """Serialise the job (df, code, guard params) into `tmp` for a runner.

    Shared by the subprocess and docker runners. Returns the in-tmp file names.
    """
    import json
    df_path = os.path.join(tmp, "df.pkl")
    code_path = os.path.join(tmp, "code.py")
    params_path = os.path.join(tmp, "params.json")
    out_path = os.path.join(tmp, "out.pkl")
    try:
        with open(df_path, "wb") as f:
            pickle.dump(df, f)
    except Exception as e:
        raise _IsolationUnavailable(f"could not serialize df: {e}")
    with open(code_path, "w", encoding="utf-8") as f:
        f.write(code)
    with open(params_path, "w", encoding="utf-8") as f:
        json.dump(guards, f)
    return df_path, code_path, params_path, out_path


def _run_isolated(code: str, df: pd.DataFrame, result_var: str, timeout: float,
                  guards: dict):
    tmp = tempfile.mkdtemp(prefix="safedata_")
    try:
        df_path, code_path, params_path, out_path = _write_job(
            tmp, df, code, guards)

        # The child runs with cwd=tmp, so it would not find the safedata package
        # when we are running from a source checkout that was never installed
        # (only on sys.path of THIS process). Replicate our import paths into the
        # child via PYTHONPATH so `-m safedata._runner` resolves there too;
        # otherwise isolation silently degrades to the in-process fallback.
        env = os.environ.copy()
        parent_paths = [p for p in sys.path if p]
        existing = env.get("PYTHONPATH")
        if existing:
            parent_paths.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(parent_paths)

        try:
            proc = subprocess.run(
                [sys.executable, "-m", "safedata._runner",
                 df_path, code_path, out_path, result_var, params_path],
                cwd=tmp, capture_output=True, text=True, timeout=timeout,
                env=env)
        except subprocess.TimeoutExpired:
            raise SafetyError(
                f"Your code did not finish within {timeout:g}s and was stopped "
                f"(possible infinite loop or runaway operation). Make it "
                f"terminate quickly.")

        if not os.path.exists(out_path):
            raise _IsolationUnavailable(
                proc.stderr.strip() or "runner produced no output")

        with open(out_path, "rb") as f:
            status, payload = pickle.load(f)

        if status == "blocked":
            raise SafetyError(payload)
        return payload
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run_docker(code, df, result_var, timeout, guards, docker_opts):
    """Run the same checked job inside a throwaway, locked-down container.

    This is the real isolation boundary: no network, a read-only root
    filesystem, and memory/CPU caps, so even deliberately hostile code can't
    reach the host. Only the per-job work directory is mounted writable. Requires
    Docker and an image with safedata installed.

    Raises SafetyError on timeout/limit; _IsolationUnavailable if Docker itself
    is missing (so the caller can decide whether to fall back, but for untrusted
    code you should NOT silently fall back to in-process).
    """
    cfg = dict(DOCKER_DEFAULTS)
    # accept either docker_image=/image=, etc.
    for k, v in docker_opts.items():
        cfg[k[len("docker_"):] if k.startswith("docker_") else k] = v

    if shutil.which("docker") is None:
        raise _IsolationUnavailable(
            "isolation='docker' requested but the docker CLI was not found. "
            "Install Docker, or use isolation='process' for non-malicious code.")

    tmp = tempfile.mkdtemp(prefix="safedata_")
    try:
        try:
            _write_job(tmp, df, code, guards)
        except _IsolationUnavailable:
            raise  # df not picklable: surface, don't silently downgrade isolation

        # Inside the container the job lives at /job (writable mount); everything
        # else is read-only. The runner reads df.pkl/code.py/params.json and
        # writes out.pkl back into the same mounted dir.
        inner = "/job"
        argv = [
            "docker", "run", "--rm",
            "--network", str(cfg["network"]),
            "--memory", str(cfg["memory"]),
            "--cpus", str(cfg["cpus"]),
            "-v", f"{tmp}:{inner}:rw",
            "-w", inner,
        ]
        if cfg.get("read_only"):
            # read-only root, but give the process a small writable tmpfs for
            # scratch (pip, /tmp) without exposing the host fs.
            argv += ["--read-only", "--tmpfs", "/tmp:size=64m",
                     "--tmpfs", "/root:size=64m"]
        # Install safedata in the container, then run the same checked runner.
        # Every value spliced into the `sh -c` string is shell-quoted, so a
        # crafted result_var/pip_install can't break out into shell injection.
        pip_pkg = cfg.get("pip_install")
        runner = (
            "python -m safedata._runner "
            + " ".join(shlex.quote(a) for a in (
                f"{inner}/df.pkl", f"{inner}/code.py", f"{inner}/out.pkl",
                str(result_var), f"{inner}/params.json")))
        if pip_pkg:
            inner_cmd = f"pip install --quiet --no-input {shlex.quote(str(pip_pkg))} && {runner}"
        else:
            inner_cmd = runner
        argv += [str(cfg["image"]), "sh", "-c", inner_cmd]

        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SafetyError(
                f"Your code did not finish within {timeout:g}s in the container "
                f"and was stopped (possible infinite loop or runaway "
                f"operation). Make it terminate quickly.")

        out_path = os.path.join(tmp, "out.pkl")
        if not os.path.exists(out_path):
            raise _IsolationUnavailable(
                "container produced no output: "
                + (proc.stderr.strip() or "unknown error"))

        with open(out_path, "rb") as f:
            status, payload = pickle.load(f)
        if status == "blocked":
            raise SafetyError(payload)
        return payload
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _deep_copy_frame(df, deep_python: bool = True):
    """Independent copy for either pandas (.copy) or polars (.clone).

    pandas' .copy(deep=True) deep-copies the block structure but NOT the Python
    objects stored inside object-dtype cells (e.g. a list in a cell) — and
    copy.deepcopy(df) is no help, because pandas' __deepcopy__ just delegates to
    .copy(deep=True). So df.loc[0, 'x'].append(99) would mutate the CALLER's
    original list. When `deep_python` is True we additionally deep-copy each cell
    of every object column, so nested mutables are independent of the caller's.

    The subprocess runner passes deep_python=False: its `df` is already a private,
    freshly-unpickled copy (the pickle round-trip isolated every nested object
    from the parent process), so the per-cell copy would only waste time.
    """
    if isinstance(df, pd.DataFrame):
        out = df.copy(deep=True)
        if deep_python:
            try:
                # map() applies Python's deepcopy to each cell value, so a list
                # or dict stored in a cell becomes a fresh object. Guarded: a
                # pathological frame (e.g. duplicate column names) or an
                # un-deepcopyable cell object falls back to the block copy above.
                for col in out.columns[out.dtypes == object]:
                    out[col] = out[col].map(copy.deepcopy)
            except Exception:
                pass
        return out
    if _HAS_POLARS and isinstance(df, pl.DataFrame):
        return df.clone()
    return df.copy(deep=True)  # last resort; pandas-like


def _safe_builtins():
    """A reduced set of builtins, no open, eval, exec, getattr, etc.
    Defense in depth only: the AST screen is the primary gate, because library
    internals (e.g. pandas IO) resolve builtins in their own namespace, not this
    one. A guarded __import__ is included so the whitelisted analysis modules
    (pandas, numpy, math, ...) can actually be imported; it refuses everything
    else."""
    import builtins as _b
    allowed = ["abs", "min", "max", "sum", "len", "round", "sorted",
               "list", "dict", "set", "tuple", "float", "int", "str",
               "bool", "range", "enumerate", "zip", "map", "filter",
               "any", "all", "print", "True", "False", "None"]
    out = {name: getattr(_b, name) for name in allowed if hasattr(_b, name)}

    _real_import = _b.__import__

    def _guarded_import(name, *args, **kwargs):
        root = name.split(".")[0]
        if root not in _ALLOWED_IMPORTS:
            raise ImportError(
                f"import of '{name}' is not allowed; only "
                f"{sorted(_ALLOWED_IMPORTS)} may be imported.")
        return _real_import(name, *args, **kwargs)

    out["__import__"] = _guarded_import
    return out
