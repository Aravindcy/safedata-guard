"""
Optional Presidio-based PII detection for international coverage.

The built-in detector (regex + name hints + Luhn) is strong for US/UK-style
data, but misses names in free text, locations/addresses, IBANs and non-US
phone/ID formats. When Microsoft Presidio is installed and turned on, safedata
augments detection with Presidio's analyzer, which recognises many more entity
types and locales.

This is optional and heavy: it needs presidio-analyzer and a spaCy model
(pip install "safedata-guard[presidio]" plus e.g.
python -m spacy download en_core_web_sm). The engine is built lazily and cached,
so importing safedata stays cheap when Presidio is unused.
"""

# Presidio entity type -> safedata PII kind. None means "ignore" (too noisy or
# not personal data on its own).
_ENTITY_KIND = {
    "PERSON": "name",
    "LOCATION": "address",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "CREDIT_CARD": "card",
    "IBAN_CODE": "card",
    "US_SSN": "national_id",
    "US_ITIN": "national_id",
    "US_DRIVER_LICENSE": "national_id",
    "US_PASSPORT": "national_id",
    "UK_NHS": "national_id",
    "MEDICAL_LICENSE": "national_id",
    "IP_ADDRESS": "ip",
    "DATE_TIME": None,
    "NRP": None,
    "ORGANIZATION": None,
    "URL": None,
}

_engine = None
_load_error = None


def _build_engine():
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    import spacy

    model = None
    for candidate in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
        try:
            spacy.load(candidate)
            model = candidate
            break
        except Exception:
            continue
    if model is None:
        # No model found; let Presidio use its own default (it may try to load
        # en_core_web_lg and fail loudly, which is the right signal).
        return AnalyzerEngine()
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": model}],
    })
    return AnalyzerEngine(nlp_engine=provider.create_engine())


def _get_engine():
    """Return a cached AnalyzerEngine, or None if Presidio can't be loaded."""
    global _engine, _load_error
    if _engine is not None:
        return _engine
    if _load_error is not None:
        return None
    try:
        _engine = _build_engine()
        return _engine
    except Exception as e:  # presidio/spacy missing or no model
        _load_error = e
        return None


def available() -> bool:
    """True if Presidio and a usable NLP model are installed."""
    return _get_engine() is not None


def detect_pii_columns(df, scan_rows=20, score_threshold=0.5, language="en"):
    """Return {column: [kinds]} for object/string columns whose sampled values
    Presidio recognises as PII. Empty dict if Presidio is unavailable.

    `scan_rows` caps how many unique values per column are analysed (Presidio's
    NER is far slower than regex, so keep this modest on wide frames).
    """
    engine = _get_engine()
    if engine is None:
        return {}
    import pandas as pd

    unlimited = scan_rows in (None, "all")
    hits = {}
    for col in df.select_dtypes(include=["object", "string"]).columns:
        uniques = df[col].dropna().astype(str).unique()
        samples = uniques if unlimited else uniques[:int(scan_rows)]
        kinds = set()
        for value in samples:
            try:
                results = engine.analyze(text=value, language=language)
            except Exception:
                continue
            for r in results:
                if r.score < score_threshold:
                    continue
                kind = _ENTITY_KIND.get(r.entity_type)
                if kind:
                    kinds.add(kind)
        if kinds:
            hits[col] = sorted(kinds)
    return hits
