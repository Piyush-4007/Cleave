"""Small shared helpers for collectors. Normalise only — never judge."""
from __future__ import annotations
import json
from urllib.parse import unquote


def as_doc(value):
    """IAM policy documents come back as a dict (boto3-decoded) or a URL-encoded
    JSON string depending on the call. Return a dict either way, or None."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    try:
        return json.loads(unquote(value))
    except (ValueError, TypeError):
        return {"_raw": str(value)}
