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


def build_prompt(summary_or_df, question: str, previous_error: str = None) -> str:
    """Build the model prompt from a question and a data summary.

    The first argument may be either an already-computed summary string (as the
    Agent passes internally) or a DataFrame (pandas or polars), in the latter
    case it is summarized for you. This makes the function safe to call directly
    without a surprising type error.
    """
    if not isinstance(summary_or_df, str):
        # treat anything non-str as a frame and summarize it
        summary = summarize(summary_or_df)
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
    docker_opts : extra keyword args
        Forwarded to run_safely for isolation="docker" (docker_image=, memory=,
        cpus=, network=).
    """

    def __init__(self, model, max_retries: int = 3, isolate: bool = True,
                 timeout: float = 10.0, allow_row_reduction: bool = False,
                 isolation: str = None, max_result_rows: int = None,
                 max_result_bytes: int = None, redact_result_pii: bool = False,
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
        self.docker_opts = docker_opts

    def ask(self, df, question: str, verbose: bool = False):
        summary = summarize(df)          # Step 1, cheap, quality-aware
        tokens = token_stats(df)        # estimate of tokens used vs raw data
        error = None
        attempts = []

        for attempt in range(1, self.max_retries + 1):
            prompt = build_prompt(summary, question, previous_error=error)
            try:
                code = self.model(prompt)    # Step 2, AI writes code
            except ModelError as e:
                return AgentResult(answer=None, code=None, attempts=attempts,
                                   blocked=True, reason=str(e), tokens=tokens)
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
                    **self.docker_opts)
                return AgentResult(answer=result, code=code,
                                   attempts=attempts, blocked=False,
                                   tokens=tokens)
            except SafetyError as e:     # Step 4, feed error back, retry
                error = str(e)
                if verbose:
                    print(f"BLOCKED: {error}\n")

        return AgentResult(answer=None, code=attempts[-1],
                           attempts=attempts, blocked=True, reason=error,
                           tokens=tokens)


class AgentResult:
    def __init__(self, answer, code, attempts, blocked, reason=None,
                 tokens=None):
        self.answer = answer
        self.code = code
        self.attempts = attempts
        self.blocked = blocked
        self.reason = reason
        self.tokens = tokens  # dict: summary_tokens, raw_tokens, saved_*, etc.

    def __repr__(self):
        if self.blocked:
            return (f"<blocked after {len(self.attempts)} attempt(s): "
                    f"{self.reason}>")
        return f"<answer={self.answer!r} (after {len(self.attempts)} attempt(s))>"
