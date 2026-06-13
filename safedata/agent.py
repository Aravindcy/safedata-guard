"""
THE ORCHESTRATOR.

Ties the three pieces into one loop:
  1. translator.summarize(df)  -> tiny, quality-aware summary (cheap)
  2. the AI writes code from the summary + question
  3. bodyguard.run_safely()    -> runs on a copy, enforces invariants
  4. if blocked, feed the error back to the AI and retry (self-correction)

The AI is PLUGGABLE. You pass any callable that takes a prompt string and
returns code. This means the library works today with a stub, and you can drop
in a real model (local or API) later without changing anything else.
"""

from .translator import summarize
from .bodyguard import run_safely, SafetyError
from .wrap import ModelError
from .tokens import token_stats


SYSTEM_INSTRUCTIONS = (
    "You are a data analyst. You are given a SUMMARY of a DataFrame named df "
    "(you cannot see all rows). Write Python code that answers the question.\n"
    "Rules:\n"
    "- `df`, `pd` (pandas) and `np` (numpy) are ALREADY available. You normally "
    "don't need to import anything; if you must, only pandas, numpy, math, "
    "statistics, datetime, or re are permitted.\n"
    "- You MAY add or transform columns on df (e.g. df['x'] = pd.to_datetime(...)); "
    "it runs on a private copy, so this is safe.\n"
    "- Do NOT reduce df's rows: never drop rows from df or reassign df to a "
    "filtered subset. Put any filtered data in a NEW variable instead.\n"
    "- Do NOT read or write files; everything you need is already in df.\n"
    "- Do NOT use df.eval()/df.query() with string expressions; write the "
    "calculation as normal Python on df instead.\n"
    "- Assign the final answer to a variable named `result`.\n"
    "- Account for any DATA TRAPS listed. Return ONLY code."
)


def build_prompt(summary_or_df, question: str, previous_error: str = None,
                 mask_pii: bool = True, scan_rows=20) -> str:
    """Build the model prompt from a question and a data summary.

    The first argument may be either an already-computed summary string (as the
    Agent passes internally) or a DataFrame (pandas or polars), in the latter
    case it is summarized for you. This makes the function safe to call directly
    without a surprising type error.

    mask_pii : when a DataFrame is passed, withhold detected PII columns' values
        from the summary by default (names/addresses regex can't catch). Set
        False for raw samples. Ignored when a summary string is passed (that text
        is used verbatim — make it safe before passing it in).
    """
    if not isinstance(summary_or_df, str):
        # treat anything non-str as a frame and summarize it, masking PII columns
        # so a direct build_prompt(df, ...) is privacy-safe like Agent.ask().
        mask = set()
        if mask_pii:
            try:
                from .analysis import privacy_report
                mask = set(privacy_report(
                    summary_or_df, scan_rows=scan_rows)["pii_columns"])
            except Exception:
                mask = set()
        summary = summarize(summary_or_df, mask_columns=mask)
    else:
        summary = summary_or_df
    parts = [SYSTEM_INSTRUCTIONS, "", "DATA SUMMARY:", summary,
             "", f"QUESTION: {question}"]
    if previous_error:
        parts += ["", "YOUR LAST ATTEMPT WAS BLOCKED:", previous_error,
                  "Rewrite the code to fix this."]
    return "\n".join(parts)


class Agent:
    """
    Orchestrates a safe analysis over a DataFrame.

    Parameters
    ----------
    model : callable
        A function (prompt: str) -> code: str. Plug in any LLM here.
    max_retries : int
        How many times the AI may self-correct after a block.
    isolate : bool
        Run generated code in a separate process with a timeout (default True).
    isolation : str or None
        Explicit isolation mode ("process"/"thread"/"docker"); overrides
        `isolate` when set. Use "docker" for untrusted model output. See
        run_safely.
    timeout : float
        Seconds before isolated code is stopped (default 10).
    allow_row_reduction : bool
        Permit code that shrinks df (drop/filter rows). Off by default.
    max_result_rows / max_result_bytes : int or None
        Cap the size of the returned answer so the model can't hand back the
        whole table. Off by default.
    redact_result_pii : bool
        Apply best-effort PII redaction to the answer before returning it.
    mask_prompt_pii : bool
        If True (default), fully withhold detected PII columns' sample values
        from the summary sent to the model (and stored in the audit), including
        name/address columns that regex masking alone can't catch. The column
        names and types are still shown, so the model can still operate on them;
        only the example values are hidden. Set False to send raw samples.
    docker_opts : extra keyword args
        Forwarded to run_safely for isolation="docker" (docker_image=, memory=,
        cpus=, network=).
    """

    def __init__(self, model, max_retries: int = 3, isolate: bool = True,
                 timeout: float = 10.0, allow_row_reduction: bool = False,
                 isolation: str = None, max_result_rows: int = None,
                 max_result_bytes: int = None, redact_result_pii: bool = False,
                 mask_prompt_pii: bool = True, column_firewall: bool = False,
                 enforce_minimal_result: bool = False,
                 block_1d_row_results: bool = False, pii_scan_rows=20,
                 **docker_opts):
        self.model = model
        self.max_retries = max_retries
        self.isolate = isolate
        self.isolation = isolation
        self.timeout = timeout
        self.allow_row_reduction = allow_row_reduction
        self.max_result_rows = max_result_rows
        self.max_result_bytes = max_result_bytes
        self.redact_result_pii = redact_result_pii
        self.mask_prompt_pii = mask_prompt_pii
        # column_firewall: block generated code from touching PII columns the
        # question doesn't reference (least privilege) — on in safe() and
        # strict(). enforce_minimal_result: refuse a full-table answer — on in
        # strict() only (it can surprise a legitimate "return all rows" request),
        # off elsewhere. Both default off on a bare Agent(...).
        self.column_firewall = column_firewall
        self.enforce_minimal_result = enforce_minimal_result
        self.block_1d_row_results = block_1d_row_results
        # how many unique values/column the PII scan inspects (int or "all").
        self.pii_scan_rows = pii_scan_rows
        self.docker_opts = docker_opts

    # Preset constructors so the SECURE configuration is the easy one to reach
    # for. `safe` caps result size and masks PII in a separate process; `strict`
    # adds full container isolation for untrusted model output. Any keyword
    # overrides the preset (e.g. Agent.strict(model, timeout=30)).
    _SAFE_DEFAULTS = dict(max_result_rows=50, max_result_bytes=1_000_000,
                          redact_result_pii=True, allow_row_reduction=False,
                          isolation="process", column_firewall=True)

    @staticmethod
    def _honor_isolate(opts, overrides):
        """If the caller passes isolate=False without an explicit isolation=,
        drop the preset's isolation so isolate=False actually takes effect
        (isolation= otherwise wins over isolate=, which would be surprising)."""
        if overrides.get("isolate") is False and "isolation" not in overrides:
            opts.pop("isolation", None)

    @classmethod
    def safe(cls, model, **overrides):
        """Agent preset with result-size caps + PII redaction, process isolation."""
        opts = dict(cls._SAFE_DEFAULTS)
        cls._honor_isolate(opts, overrides)
        opts.update(overrides)
        return cls(model, **opts)

    @classmethod
    def strict(cls, model, **overrides):
        """Like `safe`, but container isolation + refuses full-table answers."""
        opts = dict(cls._SAFE_DEFAULTS)
        opts["isolation"] = "docker"
        opts["enforce_minimal_result"] = True
        opts["block_1d_row_results"] = True
        cls._honor_isolate(opts, overrides)
        opts.update(overrides)
        return cls(model, **opts)

    def ask(self, df, question: str, verbose: bool = False):
        facts = _audit_facts(df, question, scan_rows=self.pii_scan_rows)
        # Step 1: cheap, quality-aware summary. Withhold detected PII columns'
        # sample values (names/addresses regex can't catch) so they never reach
        # the model — this is what makes the agent privacy-aware by default.
        mask = set(facts["pii_columns"]) if self.mask_prompt_pii else set()
        summary = summarize(df, mask_columns=mask)
        facts["summary"] = summary           # store the EXACT text sent, for audit
        tokens = token_stats(df)        # estimate of tokens used vs raw data
        # Least-privilege firewall: forbid generated code from touching PII
        # columns the question doesn't reference.
        blocked_columns = None
        if self.column_firewall and facts["pii_columns"]:
            from .analysis import _question_mentions_column
            blocked_columns = [c for c in facts["pii_columns"]
                               if not _question_mentions_column(question, c)]
        error = None
        attempts = []
        trace = []                       # per-attempt (code, blocked, reason)

        def _result(**kw):
            return AgentResult(attempts=attempts, tokens=tokens, trace=trace,
                               **facts, **kw)

        for attempt in range(1, self.max_retries + 1):
            prompt = build_prompt(summary, question, previous_error=error)
            try:
                code = self.model(prompt)    # Step 2, AI writes code
            except ModelError as e:
                return _result(answer=None, code=None, blocked=True, reason=str(e))
            attempts.append(code)
            if verbose:
                print(f"--- attempt {attempt} ---\n{code}\n")
            try:
                result = run_safely(              # Step 3, bodyguard
                    code, df, isolate=self.isolate, isolation=self.isolation,
                    timeout=self.timeout,
                    allow_row_reduction=self.allow_row_reduction,
                    max_result_rows=self.max_result_rows,
                    max_result_bytes=self.max_result_bytes,
                    redact_result_pii=self.redact_result_pii,
                    blocked_columns=blocked_columns,
                    enforce_minimal_result=self.enforce_minimal_result,
                    block_1d_row_results=self.block_1d_row_results,
                    **self.docker_opts)
                trace.append({"code": code, "blocked": False, "reason": None})
                return _result(answer=result, code=code, blocked=False)
            except SafetyError as e:     # Step 4, feed error back, retry
                error = str(e)
                trace.append({"code": code, "blocked": True, "reason": error})
                if verbose:
                    print(f"BLOCKED: {error}\n")

        return _result(answer=None, code=attempts[-1], blocked=True, reason=error)


def _audit_facts(df, question, scan_rows=20):
    """Collect the data-quality and privacy facts shown in the audit report.

    Returns a dict with question/summary/issues/pii_columns; the caller fills in
    `summary` once it has built the (masked) text. Best-effort and defensive: if
    the analysis layer can't run on this frame, ask() still proceeds.
    """
    facts = {"question": question, "summary": None,
             "issues": [], "pii_columns": []}
    try:
        from .analysis import validate, privacy_report
        facts["issues"] = [i.to_dict() for i in validate(df)]
        facts["pii_columns"] = privacy_report(df, scan_rows=scan_rows)["pii_columns"]
    except Exception:
        pass
    return facts


class AgentResult:
    def __init__(self, answer, code, attempts, blocked, reason=None,
                 tokens=None, question=None, summary=None, issues=None,
                 pii_columns=None, trace=None):
        self.answer = answer
        self.code = code
        self.attempts = attempts
        self.blocked = blocked
        self.reason = reason
        self.tokens = tokens  # dict: summary_tokens, raw_tokens, saved_*, etc.
        # audit context
        self.question = question
        self.summary = summary            # the exact text sent to the model
        self.issues = issues or []        # data-quality findings (dicts)
        self.pii_columns = pii_columns or []
        self.trace = trace or []          # per-attempt: {code, blocked, reason}

    def __repr__(self):
        if self.blocked:
            return (f"<blocked after {len(self.attempts)} attempt(s): "
                    f"{self.reason}>")
        return f"<answer={self.answer!r} (after {len(self.attempts)} attempt(s))>"

    def audit_report(self, path=None) -> str:
        """Render a self-contained HTML audit of this answer.

        Shows the question, the exact summary sent to the model, every attempt
        (including blocked ones and why), the final code and answer, the
        data-quality warnings, which PII columns were withheld, and the token
        saving. Returns the HTML; also writes it to `path` if given.

        Useful as a compliance/debugging trail: it records what left your machine
        and what the guardrail did, for a single agent.ask() call.
        """
        from ._audit import build_audit_html
        html = build_audit_html(self)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        return html
