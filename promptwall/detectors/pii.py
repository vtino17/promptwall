"""PII detector: emails, payment cards, phone numbers, and national IDs.

Payment-card matches are validated with the Luhn checksum so a random 16-digit
order number is not mistaken for a credit card. Findings are redactable.
"""
from __future__ import annotations

import re
from typing import List

from .base import Detector
from ..normalize import ScanContext
from ..types import Finding, Severity

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE = re.compile(
    r"(?<![\w.])\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?![\w.])")


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum used by real payment-card numbers."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PIIDetector(Detector):
    name = "pii"

    def scan(self, ctx: ScanContext) -> List[Finding]:
        text = ctx.raw
        findings: List[Finding] = []
        claimed: List[tuple] = []

        def add(label, span, evidence, severity=Severity.MEDIUM):
            if any(span[0] < e and s < span[1] for s, e in claimed):
                return
            claimed.append(span)
            findings.append(Finding(
                detector=self.name, category="pii", severity=severity,
                message=f"{label} present in text", evidence=evidence,
                span=span, redactable=True,
            ))

        for m in _EMAIL.finditer(text):
            add("email address", m.span(), m.group(0))
        for m in _CARD.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                add("payment card number", m.span(),
                    digits[:4] + "***" + digits[-2:], Severity.HIGH)
        for m in _SSN.finditer(text):
            add("national ID (SSN pattern)", m.span(), "***-**-****", Severity.HIGH)
        for m in _PHONE.finditer(text):
            raw_match = m.group(0)
            # A dotted number with no space/paren/plus is an IP or version
            # string, not a phone number -- don't flag 192.168.1.1 as PII.
            if "." in raw_match and not any(c in raw_match for c in " ()+-"):
                continue
            digits = re.sub(r"\D", "", raw_match)
            if 8 <= len(digits) <= 15:  # avoid catching plain long numbers
                add("phone number", m.span(), raw_match)
        return findings
