"""Mask redactable findings (secrets, PII) in place, leaving the rest intact."""
from __future__ import annotations

from typing import List

from .types import Finding


def redact(text: str, findings: List[Finding]) -> str:
    """Replace every redactable finding's span with a ``[REDACTED:...]`` tag.

    Spans are applied right-to-left so earlier offsets stay valid as the string
    length changes. Overlapping spans are skipped -- the detectors already
    de-duplicate, but this keeps the function safe for arbitrary input.
    """
    spans = sorted(
        (f.span[0], f.span[1], f.category.upper())
        for f in findings
        if f.redactable and f.span is not None
    )
    result = text
    last_start = len(text) + 1
    for start, end, label in reversed(spans):
        if end > last_start:  # overlaps a span we already replaced
            continue
        result = result[:start] + f"[REDACTED:{label}]" + result[end:]
        last_start = start
    return result
