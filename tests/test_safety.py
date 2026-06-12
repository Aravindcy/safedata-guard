"""
Tests for the safety engine and the self-correction loop.
Run with: pytest -q
"""

import pandas as pd
import pytest
import safedata
from safedata import run_safely as _run_safely, SafetyError, summarize


# Speed: by default these tests exercise the static screen and the runtime
# invariant checks, which are identical on both code paths. Running them
# in-process (isolate=False) avoids spawning an interpreter and re-importing
# pandas on every call, cutting the suite from ~50s to a few seconds. The few
# tests that genuinely need the subprocess (timeout enforcement, the
# isolate=True smoke test) pass isolate=True explicitly, which overrides this.
def run_safely(code, df, **kwargs):
    kwargs.setdefault("isolate", False)
    return _run_safely(code, df, **kwargs)


def test_subprocess_isolation_smoke():
    # One explicit exercise of the real subprocess path (isolate=True).
    assert _run_safely("result = df['amount'].sum()", sample_df(),
                       isolate=True) == 650.0


def sample_df():
    return pd.DataFrame({
        "date": ["2025-01-01", "2025-06-01", "2024-03-01", "2026-02-01"],
        "amount": [100.0, 200.0, 50.0, 300.0],
    })


# ---- bodyguard: good code passes ------------------------------------------

def test_valid_code_returns_answer():
    df = sample_df()
    result = run_safely("result = df['amount'].sum()", df)
    assert result == 650.0


# ---- bodyguard: dangerous code is blocked ---------------------------------

def test_blocks_file_write():
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("df.to_csv('out.csv'); result = 1", df)


def test_blocks_os_access():
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("import os; result = os.listdir('.')", df)


def test_blocks_mutation_of_original():
    df = sample_df()
    # tries to overwrite df in place by reassigning its contents
    code = "df.drop(df.index, inplace=True)\nresult = 0"
    with pytest.raises(SafetyError):
        run_safely(code, df)
    # original must be untouched
    assert len(df) == 4


def test_requires_result_variable():
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("answer = df['amount'].sum()", df)


def test_flags_empty_result():
    df = sample_df()
    code = "result = df[df['amount'] > 99999]"
    with pytest.raises(SafetyError):
        run_safely(code, df)


# ---- the self-correction loop ---------------------------------------------

def test_self_correction_recovers():
    """
    A model that first writes destructive code, then (seeing the error)
    writes correct code. The Agent should recover and return the answer.
    """
    df = sample_df()
    state = {"call": 0}

    def flaky_model(prompt):
        state["call"] += 1
        if state["call"] == 1:
            # destructive: overwrites df, then computes
            return "df = df[df['date'].str.startswith('2025')]\nresult = df['amount'].sum()"
        # corrected: does not touch df
        return "result = df[df['date'].str.startswith('2025')]['amount'].sum()"

    agent = safedata.Agent(model=flaky_model, max_retries=3, isolate=False)
    out = agent.ask(df, "total 2025 sales")

    assert out.blocked is False
    assert out.answer == 300.0          # 100 + 200
    assert len(out.attempts) == 2       # failed once, fixed on retry
    assert len(df) == 4                 # original untouched throughout


def test_gives_up_after_max_retries():
    df = sample_df()

    def always_bad(prompt):
        return "import os; result = 1"

    agent = safedata.Agent(model=always_bad, max_retries=2, isolate=False)
    out = agent.ask(df, "anything")
    assert out.blocked is True
    assert len(out.attempts) == 2


# ---- v0.2.0 new translator checks -----------------------------------------

import numpy as np
from safedata import summarize


def test_detects_empty_and_high_missing_columns():
    df = pd.DataFrame({
        "keep": [1, 2, 3, 4],
        "all_empty": [np.nan, np.nan, np.nan, np.nan],
        "mostly_empty": [1.0, np.nan, np.nan, np.nan],
    })
    out = summarize(df)
    assert "COMPLETELY EMPTY" in out
    assert "'all_empty'" in out
    assert "mostly empty" in out          # grouped high-missing line
    assert "'mostly_empty'" in out


def test_negative_zero_not_flagged():
    # -0.0, and tiny rounding noise relative to column scale, should NOT flag.
    # Here -0.01 is dust next to a max of ~200 (like the real GWh columns).
    df = pd.DataFrame({"Volume GWh": [-0.01, 0.5, 0.4, 200.0]})
    out = summarize(df)
    assert "NEGATIVE values" not in out


def test_real_negative_still_flagged():
    # -5 against a max of ~1 is material -> should flag.
    df = pd.DataFrame({"Volume GWh": [-5.0, 0.5, 0.4, 1.2]})
    out = summarize(df)
    assert "NEGATIVE values" in out


def test_detects_excel_serial_date():
    df = pd.DataFrame({"Renewal Date": [45292, 45293, 45294]})
    out = summarize(df)
    assert "Excel SERIAL DATE" in out


def test_flags_unexpected_negative():
    df = pd.DataFrame({"Order Quantity": [-3.0, 5.0, 4.0]})
    out = summarize(df)
    assert "NEGATIVE values" in out


def test_margin_negatives_not_flagged():
    # a margin/CGM column may legitimately be negative -> should NOT warn
    df = pd.DataFrame({"Annual CGM": [-200.0, 500.0, 100.0]})
    out = summarize(df)
    assert "NEGATIVE values" not in out


# ---- v0.3.0 HTML report ----------------------------------------------------

from safedata import report


def test_report_returns_html_string():
    df = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
    html = report(df)
    assert "<html" in html.lower()
    assert "Data quality report" in html


def test_report_writes_file(tmp_path):
    df = pd.DataFrame({
        "Offer ID": ["Q_1", "Q_1", "Q_2"],          # non-unique id -> red
        "clean": [1, 2, 3],
    })
    out = tmp_path / "r.html"
    returned = report(df, str(out))
    assert returned == str(out)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "NOT unique" in text


def test_report_handles_duplicate_columns():
    # df[col] returns a DataFrame for duplicate names; report must not crash and
    # should flag the duplication, mirroring the text summary.
    d = pd.DataFrame([[1, 2], [3, 4]])
    d.columns = ["a", "a"]
    html = report(d)
    assert "<html" in html.lower()
    assert "DUPLICATED" in html


def test_report_rejects_non_dataframe():
    try:
        report([1, 2, 3])
        assert False, "should raise"
    except TypeError:
        pass


# ---- v0.4.0 universal wrap() ----------------------------------------------

from safedata import wrap, extract_code, ModelError


def test_extract_code_strips_python_fence():
    reply = "Here is the code:\n```python\nresult = df['a'].sum()\n```"
    assert extract_code(reply) == "result = df['a'].sum()"


def test_extract_code_strips_plain_fence():
    reply = "```\nresult = 1\n```"
    assert extract_code(reply) == "result = 1"


def test_extract_code_passthrough_when_no_fence():
    reply = "result = df['a'].mean()"
    assert extract_code(reply) == "result = df['a'].mean()"


def test_wrap_runs_full_loop():
    df = pd.DataFrame({"amount": [10.0, 20.0, 30.0]})

    # a fake "model" that returns messy text with a fence, like a real LLM
    def fake_call(prompt):
        return "Sure! Here you go:\n```python\nresult = df['amount'].sum()\n```"

    agent = safedata.Agent(model=wrap(fake_call), isolate=False)
    out = agent.ask(df, "total amount")
    assert out.blocked is False
    assert out.answer == 60.0


def test_wrap_handles_model_failure_gracefully():
    df = pd.DataFrame({"amount": [1.0, 2.0]})

    def broken_call(prompt):
        raise ConnectionError("no internet")

    agent = safedata.Agent(model=wrap(broken_call), isolate=False)
    out = agent.ask(df, "total")
    assert out.blocked is True
    assert "failed" in out.reason.lower()


def test_wrap_rejects_non_callable():
    try:
        wrap("not a function")
        assert False, "should raise"
    except TypeError:
        pass


# ---- v0.4.0 token counter -------------------------------------------------

from safedata import token_savings, token_stats, estimate_tokens


def test_estimate_tokens_basic():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") >= 1


def test_token_stats_shows_saving_on_wide_data():
    # a big-ish frame: the summary should be far smaller than the raw data
    df = pd.DataFrame({f"col{i}": list(range(500)) for i in range(10)})
    r = token_stats(df)
    assert r["raw_tokens"] > r["summary_tokens"]
    assert 0 <= r["saved_percent"] <= 100
    assert r["saved_tokens"] == r["raw_tokens"] - r["summary_tokens"]


def test_token_savings_is_readable_text():
    df = pd.DataFrame({"a": list(range(100)), "b": list(range(100))})
    msg = token_savings(df)
    assert "tokens" in msg
    assert "%" in msg


def test_agent_result_includes_tokens():
    df = pd.DataFrame({"amount": [1.0, 2.0, 3.0]})
    agent = safedata.Agent(model=lambda p: "result = df['amount'].sum()",
                           isolate=False)
    out = agent.ask(df, "total")
    assert out.tokens is not None
    assert "summary_tokens" in out.tokens


# ---- v0.5.0 hardening: regression tests for known bypasses ----------------
#
# IMPORTANT: these tests are NECESSARY but NOT SUFFICIENT. Passing them proves
# we stopped *these specific payloads*, not the whole class of escapes, that is
# exactly the denylist fallacy that produced the original to_csv/to_json gap.
# The real boundary for untrusted code is OS-level isolation, not these asserts.
# Treat new green here as "this hole is closed", never as "the sandbox is safe".

def test_blocks_subclasses_introspection():
    # Bypass 1: reach the object graph via __class__ -> __subclasses__,
    # the standard gateway to os/subprocess without importing them.
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("result = ().__class__.__bases__[0].__subclasses__()", df)


def test_blocks_getattr_dynamic_dunder():
    # The dynamic version of bypass 1: build the attribute name to dodge a
    # literal-string screen. getattr itself is refused.
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("result = getattr((), '__cla' + 'ss__')", df)


def test_blocks_to_json_file_write():
    # Bypass 2: to_json was NOT in the old blocklist and actually wrote a file.
    import os
    df = sample_df()
    target = "PWNED_test_artifact.json"
    if os.path.exists(target):
        os.remove(target)
    with pytest.raises(SafetyError):
        run_safely(f"_ = pd.Series([1]).to_json('{target}'); result = 1", df)
    assert not os.path.exists(target), "file write was not actually prevented"


def test_blocks_other_unlisted_writers():
    # The whole point: a denylist misses writers; the AST screen catches the set.
    df = sample_df()
    for writer in ("to_pickle", "to_html", "to_excel"):
        with pytest.raises(SafetyError):
            run_safely(f"_ = df.{writer}('x.out'); result = 1", df)


def test_blocks_reaching_os_via_pandas_internals():
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("result = pd.io.common.os.listdir('.')", df)


def test_blocks_from_import_of_writer_reader_funcs(tmp_path):
    # `from numpy import save` / `from pandas import read_csv` bind a writer or
    # reader as a BARE callable the attribute screen never sees. Must be blocked.
    df = pd.DataFrame({"a": [1, 2, 3]})
    target = str(tmp_path / "np_pwned")
    bad = [
        f"from numpy import save\nsave({target!r}, df['a'].values)\nresult = 1",
        "from numpy import load\nresult = load('x.npy')",
        "from pandas import read_csv\nresult = read_csv('/etc/hostname')",
        "from pandas import read_pickle as rp\nresult = rp('x.pkl')",
    ]
    for code in bad:
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)
    import os
    assert not os.path.exists(target + ".npy"), "numpy save was not prevented"


def test_blocks_pandas_numpy_internal_io_gateways(tmp_path):
    # pandas/numpy expose private file helpers behind pd.io.* / np.lib.*. A
    # method-name denylist can't enumerate them; we block the gateway segment.
    df = pd.DataFrame({"a": [1, 2, 3]})
    target = str(tmp_path / "pwned.txt")
    bad = [
        f'h = pd.io.common.get_handle({target!r}, "w")\nresult = 1',
        'result = pd.io.common.file_exists("/etc/hostname")',
        'f = np.lib.npyio.DataSource()\nr = f.open("/etc/hostname")\nresult = 1',
        "from pandas.io.common import get_handle\nresult = 1",
        "from numpy.lib.npyio import DataSource\nresult = 1",
        "from pandas.io import common\nresult = common.file_exists('/x')",
    ]
    for code in bad:
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)
    import os
    assert not os.path.exists(target), "internal-helper file write not prevented"


def test_blocks_pandas_io_classes():
    df = sample_df()
    bad = [
        "result = pd.ExcelFile('/tmp/x.xlsx')",
        "result = pd.ExcelWriter('/tmp/x.xlsx')",
        "result = pd.HDFStore('/tmp/x.h5')",
        "from pandas import ExcelFile\nresult = ExcelFile('/tmp/x.xlsx')",
        "from pandas import ExcelWriter\nresult = ExcelWriter('/tmp/x.xlsx')",
        "from pandas import HDFStore\nresult = HDFStore('/tmp/x.h5')",
    ]
    for code in bad:
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)


def test_blocks_sql_reader_variants():
    df = sample_df()
    bad = [
        "result = pd.read_sql_query('select 1', None)",
        "result = pd.read_sql_table('x', None)",
        "from pandas import read_sql_query\nresult = 1",
        "from pandas import read_sql_table\nresult = 1",
    ]
    for code in bad:
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)


def test_allows_any_all_builtins():
    # any()/all() are normal analysis helpers and must be available.
    df = pd.DataFrame({"amount": [50.0, 120.0, 200.0]})
    assert run_safely("result = any(df['amount'] > 100)", df,
                      isolate=False) is True
    assert run_safely("result = all(df['amount'] > 100)", df,
                      isolate=False) is False


def test_isolation_works_from_source_checkout():
    # The subprocess child must be able to import safedata even when the package
    # is only on this process's sys.path (running from a source checkout). If the
    # PYTHONPATH is not propagated, isolate=True silently degrades; here we prove
    # the real subprocess path enforces the timeout rather than falling back.
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError) as ei:
        run_safely("while True:\n    pass\nresult = 1", df,
                   isolate=True, timeout=3)
    # the subprocess timeout message (not the thread-fallback "abandoned" one)
    assert "stopped" in str(ei.value).lower()


def test_token_savings_wording_for_tiny_input():
    from safedata import token_savings
    tiny = pd.DataFrame({"a": [1]})
    msg = token_savings(tiny)
    assert "no token saving" in msg
    assert "0.0%" not in msg


def test_blocks_numpy_f2py():
    df = sample_df()
    bad = [
        "result = np.f2py",
        "result = np.f2py.run_main",
        "from numpy import f2py\nresult = 1",
    ]
    for code in bad:
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)


def test_blocks_numpy_ctypeslib():
    df = sample_df()
    bad = [
        "result = np.ctypeslib.load_library('x', '/tmp')",
        "from numpy.ctypeslib import load_library\nresult = 1",
        "from numpy import ctypeslib\nresult = 1",
    ]
    for code in bad:
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)


def test_internal_gateway_block_allows_normal_numpy():
    # The gateway block must NOT break ordinary numpy/pandas analysis.
    df = pd.DataFrame({"a": [1.0, 4.0, 9.0]})
    assert run_safely("result = int(np.sqrt(df['a']).sum())", df,
                      isolate=False) == 6
    assert run_safely("result = np.linalg.norm(df['a'].values) > 0", df,
                      isolate=False) == True


def test_blocks_from_import_of_reexported_os():
    # Bypass: `from pandas.io.common import os as safe` binds the REAL os module
    # to a name the rest of the screen never inspects. Must be blocked, and
    # check_code must agree (it shares the screen).
    df = sample_df()
    for code in (
        "from pandas.io.common import os as safe\nresult = safe.getcwd()",
        "from pandas.io.common import os\nresult = os.getcwd()",
        "import pandas.io.common.os as safe\nresult = safe.getcwd()",
        "from numpy import os as o\nresult = 1",
    ):
        assert safedata.check_code(code).safe is False, code
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)


def test_timeout_stops_infinite_loop():
    # Real boundary win: a hang is stopped instead of freezing the host.
    df = sample_df()
    with pytest.raises(SafetyError):
        run_safely("while True:\n    pass\nresult = 1", df,
                   isolate=True, timeout=3)


# ---- v0.5.0: the screen must NOT break legitimate analysis -----------------

def test_allows_harmless_to_methods():
    # to_dict / to_numpy / to_list are conversions, not file writers.
    df = sample_df()
    out = run_safely("result = df['amount'].to_numpy().sum()", df)
    assert out == 650.0
    out2 = run_safely("result = df.to_dict()", df)
    assert isinstance(out2, dict)


def test_allows_no_arg_dual_writer():
    # to_string() with no args returns text for display, must stay allowed.
    df = sample_df()
    out = run_safely("result = df.to_string()", df)
    assert isinstance(out, str)


def test_in_process_path_still_screens():
    # isolate=False keeps the static screen and invariant checks.
    df = sample_df()
    out = run_safely("result = df['amount'].sum()", df, isolate=False)
    assert out == 650.0
    with pytest.raises(SafetyError):
        run_safely("result = ().__class__", df, isolate=False)


def test_blocks_read_pickle_arbitrary_code():
    # read_pickle executes arbitrary code from the file; must be blocked.
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("result = pd.read_pickle('/tmp/x.pkl')", df)


def test_blocks_reading_other_files():
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("result = pd.read_csv('/etc/hostname')", df)


def test_allows_legitimate_inmemory_conversions():
    # to_dict / to_numpy must NOT be false-positived as writers.
    df = pd.DataFrame({"a": [1, 2, 3]})
    assert run_safely("result = df.to_numpy().sum()", df) == 6
    assert run_safely("result = df.to_dict()", df) == {"a": {0: 1, 1: 2, 2: 3}}


# --- Polars support (only the polars tests skip if polars is missing) -------
# NOTE: do NOT importorskip at module level, that would skip every test BELOW
# this point (PII, CLI, check_code, ...), not just the polars ones. Guard each
# polars test individually so the rest of the suite always runs.
try:
    import polars as pl
    _HAS_POLARS = True
except ImportError:               # pragma: no cover
    pl = None
    _HAS_POLARS = False

requires_polars = pytest.mark.skipif(
    not _HAS_POLARS, reason="polars not installed")


@requires_polars
def test_polars_legit_operations_run():
    df = pl.DataFrame({"amount": [100, 200, 300]})
    assert run_safely("result = df['amount'].sum()", df) == 600


@requires_polars
def test_polars_blocks_write_csv(tmp_path):
    df = pl.DataFrame({"a": [1, 2, 3]})
    target = str(tmp_path / "out.csv")
    with pytest.raises(SafetyError):
        run_safely(f"result = df.write_csv({target!r})", df)
    assert not __import__("os").path.exists(target)


@requires_polars
def test_polars_blocks_lazy_sink(tmp_path):
    df = pl.DataFrame({"a": [1, 2, 3]})
    target = str(tmp_path / "out.csv")
    with pytest.raises(SafetyError):
        run_safely(f"result = df.lazy().sink_csv({target!r})", df)


@requires_polars
def test_polars_blocks_scan_and_read():
    df = pl.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("result = pl.scan_csv('/etc/hostname')", df)
    with pytest.raises(SafetyError):
        run_safely("result = pl.read_csv('/etc/hostname')", df)


@requires_polars
def test_polars_summary_flags_messy_categories():
    df = pl.DataFrame({"region": ["North", "north ", "NORTH"]})
    out = summarize(df)
    assert "several ways" in out


@requires_polars
def test_polars_summary_flags_empty_column():
    df = pl.DataFrame({"a": [1, 2], "blank": [None, None]})
    out = summarize(df)
    assert "EMPTY" in out


# --- PII masking ------------------------------------------------------------
from safedata import redact_text


def test_redact_text_catches_common_pii():
    assert "[EMAIL]" in redact_text("contact ann@example.com please")
    assert "[CARD]" in redact_text("card 4111 1111 1111 1111 used")
    assert "[SSN]" in redact_text("ssn 123-45-6789 on file")
    assert "[IP]" in redact_text("from 192.168.0.1 yesterday")


def test_redact_text_leaves_clean_text_alone():
    clean = "North region total sales"
    assert redact_text(clean) == clean


def test_summary_masks_email_samples():
    df = pd.DataFrame({"email": ["a@x.com", "b@y.com", "c@z.com"],
                       "region": ["N", "S", "E"]})
    out = summarize(df)
    assert "@" not in out            # raw emails gone
    assert "[EMAIL]" in out          # masked token present
    assert "PII was detected and masked" in out


def test_summary_does_not_flag_clean_category_column():
    df = pd.DataFrame({"region": ["North", "South", "East"]})
    out = summarize(df)
    assert "PII was detected" not in out
    assert "North" in out            # clean samples still shown


def test_redact_pii_false_shows_raw():
    df = pd.DataFrame({"email": ["a@x.com", "b@y.com"]})
    out = summarize(df, redact_pii=False)
    assert "a@x.com" in out


# ---- v0.5.0 usability fixes (found via live LLM testing) -------------------
#
# Both gpt-4o and gpt-4o-mini failed the same legitimate question (convert an
# Excel serial-date column, then read it) because (1) in-place column edits on
# the copy were blocked and (2) a reflexive `import pandas as pd` was blocked.
# These tests pin the relaxed behavior so it can't regress.

def test_allows_inplace_column_transform():
    # The exact pattern both models wrote. It runs on a copy, so it's safe.
    df = pd.DataFrame({"serial": [45292, 45293, 45294]})
    code = ("df['d'] = pd.to_datetime(df['serial'], unit='D', "
            "origin='1899-12-30')\nresult = df['d'].min().year")
    assert run_safely(code, df) == 2024
    # original is untouched (it only ever saw a copy)
    assert "d" not in df.columns


def test_allows_adding_a_column():
    df = pd.DataFrame({"a": [1, 2, 3]})
    assert run_safely("df['b'] = df['a'] * 2\nresult = df['b'].sum()", df) == 12
    assert "b" not in df.columns


def test_allows_safe_imports():
    df = pd.DataFrame({"a": [1.0, 4.0, 9.0]})
    assert run_safely("import math\nresult = math.sqrt(df['a'].sum())", df) == \
        pytest.approx(3.7416, rel=1e-3)
    # reflexive 'import pandas as pd' no longer breaks anything
    assert run_safely("import pandas as pd\nresult = df['a'].sum()", df) == 14.0
    # numpy is available without importing
    assert run_safely("result = int(np.sum(df['a'].values))", df) == 14


def test_blocks_unsafe_import_still():
    df = pd.DataFrame({"a": [1, 2, 3]})
    for bad in ("import os", "import sys", "from subprocess import run",
                "import requests"):
        with pytest.raises(SafetyError):
            run_safely(f"{bad}\nresult = 1", df)


def test_blocks_row_reduction():
    # Shrinking df (the genuinely risky case) is still blocked, in place...
    df = pd.DataFrame({"a": [1, 2, 3, 4]})
    with pytest.raises(SafetyError):
        run_safely("df = df[df['a'] > 2]\nresult = df['a'].sum()", df)
    # ...and via drop. Using a NEW variable is the correct, allowed way:
    assert run_safely("sub = df[df['a'] > 2]\nresult = sub['a'].sum()", df) == 7


# --- numpy writer/reader holes (opened when numpy imports were allowed) -----
def test_blocks_numpy_save(tmp_path):
    df = pd.DataFrame({"a": [1, 2, 3]})
    target = str(tmp_path / "x")
    with pytest.raises(SafetyError):
        run_safely(f"import numpy as np; result = np.save({target!r}, "
                   f"df['a'].values)", df)
    import os as _os
    assert not _os.path.exists(target + ".npy")


def test_blocks_numpy_savetxt_tofile_dump(tmp_path):
    df = pd.DataFrame({"a": [1, 2, 3]})
    for snippet in (
        f"import numpy as np; result = np.savetxt({str(tmp_path/'a.txt')!r}, df['a'].values)",
        f"import numpy as np; result = df['a'].values.tofile({str(tmp_path/'b.bin')!r})",
        f"import numpy as np; result = df['a'].values.dump({str(tmp_path/'c.pkl')!r})",
    ):
        with pytest.raises(SafetyError):
            run_safely(snippet, df)


def test_blocks_numpy_load():
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("import numpy as np; result = np.load('/tmp/x.npy')", df)


def test_allows_numpy_compute():
    df = pd.DataFrame({"a": [1, 2, 3]})
    assert run_safely("import numpy as np; result = int(np.sum(df['a'].values))",
                      df) == 6


# --- CLI --------------------------------------------------------------------
from safedata import cli as _cli


def _write_csv(tmp_path):
    p = tmp_path / "data.csv"
    pd.DataFrame({
        "region": ["North", "South"],
        "email": ["a@x.com", "b@y.com"],
        "amount": [10, 20],
    }).to_csv(p, index=False)
    return str(p)


def test_cli_check_runs_and_masks(tmp_path, capsys):
    rc = _cli.main(["check", _write_csv(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Dataset: 2 rows" in out
    assert "[EMAIL]" in out and "a@x.com" not in out      # masked by default
    assert "tokens" in out                                 # token line printed


def test_cli_no_redact_shows_raw(tmp_path, capsys):
    rc = _cli.main(["check", _write_csv(tmp_path), "--no-redact"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "a@x.com" in out                                # raw shown


def test_cli_missing_file_errors(tmp_path, capsys):
    rc = _cli.main(["check", str(tmp_path / "nope.csv")])
    assert rc == 1
    assert "No such file" in capsys.readouterr().err


def test_cli_unsupported_type_errors(tmp_path, capsys):
    bad = tmp_path / "f.bin"
    bad.write_text("x")
    rc = _cli.main(["check", str(bad)])
    assert rc == 1
    assert "Unsupported file type" in capsys.readouterr().err


def test_cli_report_flag_writes_html(tmp_path, capsys):
    out_html = tmp_path / "r.html"
    rc = _cli.main(["check", _write_csv(tmp_path), "--report", str(out_html)])
    assert rc == 0
    assert out_html.exists()
    assert "<html" in out_html.read_text().lower()


def test_cli_no_command_shows_help(capsys):
    rc = _cli.main([])
    assert rc == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_pii_does_not_flag_timestamps():
    # Real-world false positive: a datetime column was being mangled into
    # [PHONE]. Timestamps and dates must be left intact.
    from safedata import redact_text
    assert redact_text("2024-10-07 16:38:46") == "2024-10-07 16:38:46"
    assert redact_text("2020-01-01 00:00:00") == "2020-01-01 00:00:00"
    # but a genuine phone is still masked
    assert "[PHONE]" in redact_text("call +44 20 7946 0958")


def test_summary_no_pii_note_for_datetime_column():
    df = pd.DataFrame({"ts": ["2024-10-07 16:38:46", "2025-03-06 11:22:16"]})
    out = summarize(df)
    assert "PII was detected" not in out
    assert "16:38:46" in out


# --- previously-untested public helpers ------------------------------------
from safedata import build_prompt, extract_code, estimate_tokens


def test_build_prompt_accepts_dataframe_or_summary():
    df = pd.DataFrame({"a": [1, 2, 3]})
    p1 = build_prompt(df, "sum of a?")                 # frame
    p2 = build_prompt(summarize(df), "sum of a?")      # summary string
    for p in (p1, p2):
        assert "QUESTION: sum of a?" in p
        assert "Dataset:" in p


def test_build_prompt_includes_previous_error():
    p = build_prompt("Dataset: 1 rows", "q?", previous_error="it broke")
    assert "it broke" in p and "BLOCKED" in p


def test_extract_code_strips_fences_and_chatter():
    assert extract_code("```python\nresult = 1\n```") == "result = 1"
    assert extract_code("Sure! ```python\nx=5\nresult=x\n``` done") == "x=5\nresult=x"
    assert extract_code("result = 2") == "result = 2"


def test_estimate_tokens_scales_with_length():
    assert estimate_tokens("") == 0
    assert estimate_tokens("a" * 400) == 100   # ~4 chars/token
    assert estimate_tokens("hello") >= 1


# --- check_code (standalone static guard for agent builders) ----------------
from safedata import check_code, CodeCheck


def test_check_code_passes_safe_code():
    v = check_code("result = df['a'].sum()")
    assert v.safe is True
    assert v.reason is None
    assert bool(v) is True            # truthy when safe


def test_check_code_blocks_and_explains():
    v = check_code("df.to_csv('x.csv')")
    assert v.safe is False
    assert "to_csv" in v.reason
    assert bool(v) is False


def test_check_code_never_executes(tmp_path):
    # Code that WOULD create a file if run. check_code must not run it.
    target = tmp_path / "should_not_exist.txt"
    check_code(f"open({str(target)!r}, 'w').write('x')")
    assert not target.exists()


def test_check_code_handles_syntax_error():
    v = check_code("result = (1 +")
    assert v.safe is False
    assert "syntax" in v.reason.lower()


def test_check_code_agrees_with_run_safely_screen():
    df = pd.DataFrame({"a": [1, 2, 3]})
    for code in ["import os", "result = eval('1')", "df.to_csv('x')",
                 "result = ().__class__"]:
        assert check_code(code).safe is False
        with pytest.raises(SafetyError):
            run_safely(code, df, isolate=False)
    # and a safe one passes both
    assert check_code("result = df['a'].sum()").safe is True
    assert run_safely("result = df['a'].sum()", df, isolate=False) == 6


def test_python_dash_m_entrypoint_exists():
    # `python -m safedata` must work as a PATH-independent fallback.
    import importlib
    mod = importlib.import_module("safedata.__main__")
    assert hasattr(mod, "main")


def test_cli_runs_via_subprocess_module(tmp_path):
    # Exercise the actual `python -m safedata check <file>` path.
    import subprocess, sys
    csv = tmp_path / "d.csv"
    pd.DataFrame({"a": [1, 2]}).to_csv(csv, index=False)
    out = subprocess.run(
        [sys.executable, "-m", "safedata", "check", str(csv)],
        capture_output=True, text=True)
    assert out.returncode == 0
    assert "Dataset: 2 rows" in out.stdout


def test_summarize_handles_duplicate_columns():
    # Duplicate column names must not crash and should be reported.
    d = pd.DataFrame([[1, 2], [3, 4]])
    d.columns = ["a", "a"]
    out = summarize(d)
    assert "Dataset: 2 rows" in out
    assert "DUPLICATED" in out


def test_summarize_empty_dataframe():
    out = summarize(pd.DataFrame())
    assert "0 rows" in out


def test_summarize_mixed_type_column():
    out = summarize(pd.DataFrame({"m": [1, "two", 3.0, None]}))
    assert "Dataset:" in out


def test_trap_constant_column():
    df = pd.DataFrame({"country": ["UK", "UK", "UK"], "amount": [1, 2, 3]})
    out = summarize(df)
    assert "SAME value in every row" in out
    # a varied column must not be flagged
    assert "SAME value" not in summarize(pd.DataFrame({"a": [1, 2, 3]}))


def test_trap_dates_stored_as_text():
    df = pd.DataFrame({"signup": ["2024-01-15", "2024-02-20", "2024-03-25"]})
    assert "DATES stored as text" in summarize(df)
    # real datetimes and plain numbers must not be flagged as date-text
    assert "DATES stored as text" not in summarize(
        pd.DataFrame({"d": pd.to_datetime(["2024-01-15", "2024-02-20"])}))
    assert "DATES stored as text" not in summarize(
        pd.DataFrame({"n": ["100", "200", "300"]}))


def test_trap_single_row_no_false_constant():
    # one row should not be reported as a constant column
    assert "SAME value" not in summarize(pd.DataFrame({"a": [5]}))


# ---- v1.1.0 hardening: aliased writers/readers, expr channels --------------
#
# Bypass: bind the bound method to a name first, then call the NAME. A call-site
# only screen misses this; we now refuse at the attribute reference itself.

def test_blocks_aliased_writer(tmp_path):
    df = pd.DataFrame({"a": [1, 2, 3]})
    target = str(tmp_path / "aliased.csv")
    with pytest.raises(SafetyError):
        run_safely(f"w = df.to_csv\nw({target!r})\nresult = 1", df,
                   isolate=False)
    import os
    assert not os.path.exists(target), "aliased writer was not prevented"


def test_blocks_aliased_reader():
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("r = pd.read_csv\nresult = r('/etc/hostname')", df,
                   isolate=False)


def test_blocks_df_eval_string_channel():
    # df.eval/query parse a string the AST screen can't see -> refused.
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("result = df.eval('a * 2')", df, isolate=False)
    with pytest.raises(SafetyError):
        run_safely("result = df.query('a > 1')", df, isolate=False)
    # the normal-Python equivalent still works
    assert list(run_safely("result = df['a'] * 2", df, isolate=False)) == [2, 4, 6]


# ---- v1.1.0: opt-in row reduction ------------------------------------------

def test_row_reduction_blocked_by_default():
    df = pd.DataFrame({"a": [1, 2, 3, 4]})
    with pytest.raises(SafetyError):
        run_safely("df = df[df['a'] > 2]\nresult = df['a'].sum()", df,
                   isolate=False)


def test_row_reduction_allowed_when_enabled():
    df = pd.DataFrame({"a": [1, 2, 3, 4]})
    out = run_safely("df = df[df['a'] > 2]\nresult = df['a'].sum()", df,
                     isolate=False, allow_row_reduction=True)
    assert out == 7
    assert len(df) == 4   # original still untouched (worked on a copy)


def test_agent_allow_row_reduction_flag():
    df = pd.DataFrame({"a": [1, 2, 3, 4]})
    agent = safedata.Agent(
        model=lambda p: "df = df[df['a'] > 2]\nresult = df['a'].sum()",
        isolate=False, allow_row_reduction=True)
    out = agent.ask(df, "sum of a where a>2")
    assert out.blocked is False
    assert out.answer == 7


# ---- v1.1.0: generic (de-domained) name heuristics -------------------------

def test_generic_nonnegative_name_hint():
    # generic names like 'quantity'/'count' drive the negative-value check now
    assert "NEGATIVE values" in summarize(pd.DataFrame({"quantity": [-5, 1, 2]}))
    assert "NEGATIVE values" in summarize(pd.DataFrame({"item_count": [-5, 1, 2]}))
    # a column with no nonneg-implying name is left alone
    assert "NEGATIVE values" not in summarize(pd.DataFrame({"delta": [-5, 1, 2]}))


def test_date_hint_word_boundary_no_false_positive():
    # 'restart' contains 'start' as a substring but is not a date token; a plain
    # number column named this way must NOT be flagged as an Excel serial date
    df = pd.DataFrame({"restart_seq": [45292, 45293, 45294]})
    assert "Excel SERIAL DATE" not in summarize(df)
    # but a real date-named serial column still is
    assert "Excel SERIAL DATE" in summarize(
        pd.DataFrame({"order_date": [45292, 45293, 45294]}))


# ---- v1.1.0: token estimate stays cheap & exact on small frames ------------

def test_raw_token_estimate_exact_on_small_frame():
    # for frames at/under the sample size, the estimate equals the full CSV
    from safedata.tokens import _estimate_raw_tokens, estimate_tokens
    df = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
    assert _estimate_raw_tokens(df) == estimate_tokens(df.to_csv(index=False))


def test_raw_token_estimate_scales_for_big_frame():
    from safedata.tokens import _estimate_raw_tokens
    small = pd.DataFrame({"a": list(range(10)), "b": list(range(10))})
    big = pd.DataFrame({"a": list(range(100000)), "b": list(range(100000))})
    # ~10000x more rows -> estimate grows roughly proportionally (not exact, but
    # the same order of magnitude as the row ratio)
    assert _estimate_raw_tokens(big) > 100 * _estimate_raw_tokens(small)


# ============================================================================
# v1.0.6 structured analysis layer (validate / suggest_fixes / score / etc.)
# ============================================================================
from safedata import (validate, Issue, suggest_fixes, explain_issue,
                      quality_score, ai_readiness, privacy_report,
                      infer_columns, build_safe_prompt)


def _messy_df():
    return pd.DataFrame({
        "amount": ["$100", "$2,000", "$50"],            # text-numeric
        "signup": ["2024-01-15", "2024-02-20", "2024-03-25"],  # date-as-text
        "region": ["North", "north ", "NORTH"],         # messy category
        "email": ["a@x.com", "b@y.com", "c@z.com"],     # PII
        "country": ["UK", "UK", "UK"],                  # constant
    })


def test_validate_returns_structured_issues():
    issues = validate(_messy_df())
    assert issues and all(isinstance(i, Issue) for i in issues)
    rules = {i.rule_id for i in issues}
    assert {"TEXT_NUMERIC", "DATE_AS_TEXT", "MESSY_CATEGORY",
            "PII", "CONSTANT_COLUMN"} <= rules
    tn = next(i for i in issues if i.rule_id == "TEXT_NUMERIC")
    assert tn.severity == "high"
    assert 0 < tn.confidence <= 1
    assert tn.column == "amount"
    assert tn.evidence                      # has sample evidence
    # both attribute and dict-style access work
    assert tn["rule_id"] == "TEXT_NUMERIC"
    assert "rule_id" in tn.to_dict()


def test_validate_clean_df_has_no_issues():
    clean = pd.DataFrame({"a": [1, 2, 3], "b": [4.0, 5.0, 6.0]})
    assert validate(clean) == []


def test_suggest_fixes_emits_runnable_code():
    fixes = suggest_fixes(_messy_df())
    cols = {f["column"]: f for f in fixes}
    assert "to_numeric" in cols["amount"]["suggested_code"]
    assert "to_datetime" in cols["signup"]["suggested_code"]
    # the suggested code should actually parse
    import ast
    for f in fixes:
        ast.parse(f["suggested_code"])


def test_numeric_fix_actually_parses_currency():
    # The suggested numeric fix must turn '$2,000' into 2000.0, NOT NaN.
    df = pd.DataFrame({"amount": ["$100", "$2,000", "$50"]})
    code = next(f["suggested_code"] for f in suggest_fixes(df)
                if f["column"] == "amount")
    ns = {"df": df.copy(), "pd": pd}
    exec(code, ns)
    vals = ns["df"]["amount"].tolist()
    assert vals == [100.0, 2000.0, 50.0]


def test_category_fix_preserves_missing():
    # astype('string') keeps NaN as <NA> rather than the literal 'nan'/'none'.
    df = pd.DataFrame({"region": ["North", None, "north "]})
    code = next(f["suggested_code"] for f in suggest_fixes(df)
                if f["column"] == "region")
    ns = {"df": df.copy(), "pd": pd}
    exec(code, ns)
    out = ns["df"]["region"]
    assert out.isna().sum() == 1                      # missing preserved
    assert "nan" not in out.dropna().tolist()
    assert "none" not in out.dropna().tolist()


def test_explain_issue_is_human_readable():
    iss = next(i for i in validate(_messy_df()) if i.rule_id == "TEXT_NUMERIC")
    text = explain_issue(iss)
    assert "text" in text.lower()
    # also accepts a rule id directly
    assert explain_issue("PII")


def test_quality_score_shape_and_range():
    sc = quality_score(_messy_df())
    assert 0 <= sc["score"] <= 100
    assert set(sc["breakdown"]) == {"completeness", "type_consistency",
                                    "duplicate_risk", "pii_risk",
                                    "outlier_risk"}
    assert sc["privacy_risk"] in ("Low", "Medium", "High")
    # a clean frame scores higher than a messy one
    clean = pd.DataFrame({"a": [1, 2, 3], "b": [4, 5, 6]})
    assert quality_score(clean)["score"] > sc["score"]


def test_ai_readiness_flags_pii():
    r = ai_readiness(_messy_df())
    assert r["safe_to_send_raw"] is False
    assert "email" in r["summary"]
    assert any(c["check"] == "no_pii" and not c["ok"] for c in r["checks"])
    # clearer keys present and consistent
    assert r["needs_review"] is True
    assert r["ready_for_summary"] == r["ready"]   # alias kept for back-compat


def test_privacy_risk_high_for_single_email_among_many():
    # one email column among 100 clean ones must still read High, not Low.
    data = {f"c{i}": list(range(5)) for i in range(100)}
    data["work_email"] = ["a@x.com"] * 5
    sc = quality_score(pd.DataFrame(data))
    assert sc["privacy_risk"] == "High"


def test_privacy_report_detects_email():
    rep = privacy_report(_messy_df())
    assert "email" in rep["pii_columns"]
    assert rep["recommended_action"]


def test_privacy_does_not_falseflag_date_columns():
    # Consecutive date strings must NOT be matched as card/phone PII (they would
    # be if samples were joined before matching).
    df = pd.DataFrame({"signup": ["2024-01-15", "2024-02-20", "2024-03-25"]})
    assert privacy_report(df)["pii_columns"] == []
    assert not infer_columns(df)["signup"].startswith("pii_")


def test_pii_name_hint_uses_tokens_not_substrings():
    # Real-data false positives:
    #  - 'cover_noofnameddrivers' (a count) must NOT match because "named"
    #    contains the substring "name" (token matching fixes this)
    #  - 'Product Name' / 'Team Name' are not personal data (no person context)
    #  - 'Customer Name' / 'Surname' / 'first_name' SHOULD be flagged
    df = pd.DataFrame({
        "cover_noofnameddrivers": [0, 1, 2],
        "Product Name": ["A", "B", "C"],
        "Team Name": ["X", "Y", "Z"],
        "Customer Name": ["Jo", "Al", "Sam"],
        "Surname": ["Lee", "Roy", "Fox"],
        "first_name": ["Jo", "Al", "Sam"],
    })
    pii = set(privacy_report(df)["pii_columns"])
    assert "cover_noofnameddrivers" not in pii
    assert "Product Name" not in pii
    assert "Team Name" not in pii
    assert {"Customer Name", "Surname", "first_name"} <= pii


def test_email_name_hint_is_high_risk():
    df = pd.DataFrame({"work_email": ["a", "b"], "Customer Name": ["x", "y"]})
    rep = privacy_report(df)
    high = {h["column"] for h in rep["high_risk"]}
    medium = {m["column"] for m in rep["medium_risk"]}
    assert "work_email" in high          # email-by-name -> high
    assert "Customer Name" in medium     # person name-by-name -> medium


def test_infer_columns_types():
    types = infer_columns(_messy_df())
    assert types["email"].startswith("pii_")
    assert types["country"] in ("category", "text")
    ids = infer_columns(pd.DataFrame({"customer_id": [1, 2, 3],
                                      "price": [9.0, 8.0, 7.0]}))
    assert ids["customer_id"] == "identifier"
    assert ids["price"] == "money"


def test_build_safe_prompt_masks_by_default():
    p = build_safe_prompt(_messy_df(), "What are the trends?")
    assert "What are the trends?" in p
    assert "a@x.com" not in p                # PII column withheld
    assert "[REDACTED]" in p                 # withheld at column level
    p_raw = build_safe_prompt(_messy_df(), "q", privacy="raw")
    assert "a@x.com" in p_raw                 # raw on request


def test_build_safe_prompt_withholds_name_columns():
    # Regression: names are PII but regex can't detect them. With privacy="mask"
    # they must be fully withheld, not leaked into the prompt.
    df = pd.DataFrame({
        "Customer ID": [1, 2, 3],
        "Name": ["Alice", "Bob", "Cara"],
        "Surname": ["Lee", "Roy", "Fox"],
        "Order value": [10, 20, 30],
    })
    p = build_safe_prompt(df, "total order value?", privacy="mask")
    assert "Alice" not in p and "Lee" not in p
    assert "[REDACTED]" in p
    assert "Name" in p.split("USER QUESTION")[0]   # noted in the privacy line
    # numeric, non-PII columns are still summarised normally
    assert "Order value" in p


def test_cli_json_output(tmp_path, capsys):
    csv = tmp_path / "d.csv"
    _messy_df().to_csv(csv, index=False)
    rc = _cli.main(["check", str(csv), "--json"])
    out = capsys.readouterr().out
    import json
    data = json.loads(out)                    # must be valid JSON
    for key in ("quality_score", "privacy_report", "ai_readiness",
                "issues", "pii_columns", "tokens"):
        assert key in data, key
    assert "email" in data["pii_columns"]
    assert rc == 0


def test_cli_fail_on_pii_exits_nonzero(tmp_path, capsys):
    csv = tmp_path / "d.csv"
    _messy_df().to_csv(csv, index=False)
    rc = _cli.main(["check", str(csv), "--fail-on", "pii", "--json"])
    assert rc == 2                             # PII present -> non-zero
    # a clean file passes the gate
    clean = tmp_path / "clean.csv"
    pd.DataFrame({"a": [1, 2, 3]}).to_csv(clean, index=False)
    assert _cli.main(["check", str(clean), "--fail-on", "high", "--json"]) == 0


def test_validate_handles_polars_if_present():
    pl = pytest.importorskip("polars")
    issues = validate(pl.DataFrame({"amount": ["$1", "$2", "$3"]}))
    assert any(i.rule_id == "TEXT_NUMERIC" for i in issues)

# --- regression tests for v1.0.7 fixes --------------------------------------

def test_shared_scope_lambda_sees_module_var():
    # A module-level variable must be visible inside a lambda/comprehension
    # defined in the same snippet (previously raised NameError).
    df = pd.DataFrame({"a": [1, 2, 3, 4]})
    code = "threshold = 2\nresult = df['a'].map(lambda x: x > threshold).tolist()"
    assert run_safely(code, df) == [False, False, True, True]
    # also via the real subprocess path
    assert _run_safely(code, df, isolation="process") == [False, False, True, True]


def test_bare_dunder_name_blocked():
    assert not safedata.check_code("f = lambda x=__build_class__: x").safe
    assert not safedata.check_code("result = __builtins__").safe


def test_max_result_rows_blocks_oversized_frame():
    df = pd.DataFrame({"a": range(10)})
    with pytest.raises(SafetyError):
        run_safely("result = df", df, max_result_rows=3)
    # an aggregate is fine
    assert run_safely("result = int(df['a'].sum())", df, max_result_rows=3) == 45


def test_max_result_bytes_blocks_large_result():
    df = pd.DataFrame({"a": range(1000)})
    with pytest.raises(SafetyError):
        run_safely("result = df", df, max_result_bytes=50)


def test_redact_result_pii_scrubs_emails():
    df = pd.DataFrame({"email": ["a@b.com", "c@d.com"]})
    out = run_safely("result = df", df, redact_result_pii=True)
    assert out["email"].tolist() == ["[EMAIL]", "[EMAIL]"]


def test_docker_missing_raises_clear_error(monkeypatch):
    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: None)
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(RuntimeError):
        _run_safely("result = df['a'].sum()", df, isolation="docker")


# --- regression tests for the str.format/format_map escape (1.0.8) ----------

def test_format_attribute_escape_blocked():
    # The classic info-disclosure escape and its variants must be refused.
    for code in [
        "result = '{0.__init__.__globals__}'.format(df)",
        "result = '{0.__class__}'.format(df)",
        "result = '{x.__init__}'.format_map({'x': df})",
        "result = '{0[0]}'.format(df['a'].tolist())",
    ]:
        assert not safedata.check_code(code).safe, code


def test_format_nonliteral_template_blocked():
    # A template the screen can't see (built in a variable) is refused.
    code = "t = '{0.__class__}'\nresult = t.format(df)"
    assert not safedata.check_code(code).safe


def test_format_escape_blocked_at_runtime():
    df = pd.DataFrame({"a": [1, 2, 3]})
    with pytest.raises(SafetyError):
        run_safely("result = '{0.__init__.__globals__}'.format(df)", df)


def test_safe_format_still_allowed():
    # Plain value substitution / format specs must keep working.
    for code in [
        "result = '{:.2f}'.format(3.14159)",
        "result = '{}'.format(df['a'].sum())",
        "result = '{0} rows'.format(len(df))",
        "result = '{name}'.format(name='hi')",
    ]:
        assert safedata.check_code(code).safe, code
    df = pd.DataFrame({"a": [1, 2, 3]})
    assert run_safely("result = '{:.1f}'.format(df['a'].mean())", df) == "2.0"
