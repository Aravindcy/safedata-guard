"""
THE UNIVERSAL MODEL ADAPTER.

The Agent's `model=` slot accepts any function that takes a prompt string and
returns Python code. But real models are messy: they wrap code in ```python
fences, add chatter like "Here's the code:", and sometimes fail. `wrap` takes
ANY text-in / text-out function (a Claude call, a GPT-4 call, a local model, or
your own custom function) and returns a clean model the Agent can use.

This is what makes safedata work with ANY model, not just specific providers.

    def my_call(prompt):
        # anything: an API call, a local model, your own function.
        # just take text in, return text out.
        return some_model(prompt)

    agent = safedata.Agent(model=safedata.wrap(my_call))
"""

import re


class ModelError(Exception):
    """Raised when the wrapped model call fails (network, key, bad output)."""


def extract_code(text: str) -> str:
    """
    Pull bare Python code out of a model's reply.

    Handles the common messy cases:
      - ```python ... ``` fenced blocks
      - ``` ... ``` fenced blocks with no language
      - leading chatter like "Here is the code:" before a fence
      - stray backticks
    If no fence is found, returns the text stripped (assume it's already code).
    """
    if text is None:
        raise ModelError("The model returned nothing (None).")

    text = text.strip()

    # Prefer a fenced block if present.
    fence = re.search(r"```(?:python|py)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        return fence.group(1).strip()

    # No fence: drop a leading line that is clearly prose, keep the rest.
    # (e.g. "Here is the code:\nresult = ...") Only strip if the first line has
    # no code-like characters.
    lines = text.splitlines()
    if lines and not re.search(r"[=\(\[\.]", lines[0]) and len(lines) > 1:
        lines = lines[1:]
    return "\n".join(lines).strip()


def wrap(call, clean=extract_code):
    """
    Turn ANY text-in / text-out function into a model the Agent can use.

    Parameters
    ----------
    call : callable
        A function (prompt: str) -> reply_text: str. This is YOUR model: an
        API call, a local model, anything. It just takes text and returns text.
    clean : callable, optional
        How to extract code from the reply. Defaults to extract_code, which
        handles ```python fences and chatter. Pass your own if your model needs
        special handling.

    Returns
    -------
    callable
        A (prompt) -> code function suitable for safedata.Agent(model=...).
        Network/format failures are raised as ModelError with a clear message.
    """
    if not callable(call):
        raise TypeError("safedata.wrap expects a function (prompt) -> text.")

    def model(prompt: str) -> str:
        try:
            reply = call(prompt)
        except Exception as e:
            # surface the real cause but in a clear, consistent way
            raise ModelError(
                f"The model call failed: {type(e).__name__}: {e}. "
                f"Check your connection, API key, or model setup.") from e

        if not isinstance(reply, str):
            # some clients return objects; try a sensible fallback
            reply = str(reply)
        return clean(reply)

    return model
