"""
PII REDACTION (best-effort, heuristic).

The translator sends a small SAMPLE of real cell values to the LLM so it can
write correct code. Those samples can contain personal data: emails, phone
numbers, card numbers, and the like. This module redacts the obvious cases
before the summary leaves the machine.

HONEST SCOPE, please read.
This is REGEX-BASED, BEST-EFFORT redaction, not a compliance guarantee. It
catches common, well-formed patterns (emails, long digit runs that look like
cards, phone-shaped numbers, US SSNs, IPs). It WILL miss things: unusual
formats, names, addresses, free-text notes, locale-specific IDs. Do not treat
a redacted summary as "safe to share" in any legal sense. If you handle
regulated data, keep it out of third-party LLMs by policy, not by trusting a
regex. Masking is on by default for the summary because leaking less is better
than leaking more, but it is a seatbelt, not a vault.
"""

import re

# Order matters: more specific patterns first, so a card number isn't partly
# eaten by the generic long-digit rule.
_PATTERNS = [
    # email
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    # credit-card-like: 13-16 digits, optionally split by space/dash in groups
    ("CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    # US SSN style nnn-nn-nnnn
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # IPv4
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # phone-shaped: optional +, groups of digits with space/-/() separators,
    # at least 10 digits total. Kept fairly strict to limit false hits.
    ("PHONE", re.compile(
        r"\+?\(?(?:\d{1,3}[\s.)-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}\b")),
]


def _looks_like_phone(text: str) -> bool:
    digits = sum(c.isdigit() for c in text)
    if digits < 10:
        return False
    # Don't treat dates/timestamps as phones. A run like "2024-10-07 16:38:46"
    # has enough digits to trip a phone matcher, but the ISO-ish date pattern
    # or a HH:MM:SS time clearly means it is not a phone number.
    if _DATELIKE.search(text) or _TIMELIKE.search(text):
        return False
    return True


# date like 2024-10-07 or 2024/10/07; time like 16:38 or 16:38:46
_DATELIKE = re.compile(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b")
_TIMELIKE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")


def redact_text(text: str) -> str:
    """Return `text` with obvious PII replaced by [EMAIL], [CARD], etc.

    Best-effort. See module docstring for the (important) limits.
    """
    if not text:
        return text
    out = text
    for label, pattern in _PATTERNS:
        if label == "PHONE":
            # extra guard: only redact phone-shaped hits with enough digits,
            # so we don't mangle short codes or ranges.
            def _sub_phone(m):
                return f"[{label}]" if _looks_like_phone(m.group(0)) else m.group(0)
            out = pattern.sub(_sub_phone, out)
        else:
            out = pattern.sub(f"[{label}]", out)
    return out


def luhn_ok(digits) -> bool:
    """True if a 13-19 digit string/number passes the Luhn checksum (cards).

    Used to spot card numbers a CSV/Excel import stored as INTEGERS (so the text
    regex never sees them) without false-flagging every long number - a random
    long int almost never passes Luhn.
    """
    s = "".join(ch for ch in str(digits) if ch.isdigit())
    if not (13 <= len(s) <= 19):
        return False
    total, alt = 0, False
    for ch in reversed(s):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def redact_samples(samples) -> list:
    """Redact each value in a list of sample values (returns strings)."""
    return [redact_text(str(v)) for v in samples]


def scan_columns(df_columns_and_samples) -> list:
    """Given an iterable of (column_name, [sample_values]), return the names of
    columns whose samples contain detected PII. Used to add a single summary
    warning so the model (and the user) know redaction happened."""
    hits = []
    for col, samples in df_columns_and_samples:
        joined = " ".join(str(v) for v in samples)
        if redact_text(joined) != joined:
            hits.append(col)
    return hits
