"""Obfuscation detector: signals that text is trying to hide from filters.

This detector rarely fires alone -- its value is corroborating. Invisible tag
characters or a base64 blob that decodes to an instruction are strong evidence
that an accompanying injection was deliberate rather than incidental.
"""
from __future__ import annotations

from typing import List

from .base import Detector
from ..normalize import (
    ScanContext,
    has_invisibles,
    has_tag_chars,
    homoglyph_chars,
)
from ..types import Finding, Severity


class ObfuscationDetector(Detector):
    name = "obfuscation"

    def scan(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        raw = ctx.raw

        if has_tag_chars(raw):
            findings.append(Finding(
                detector=self.name, category="obfuscation",
                severity=Severity.HIGH,
                message="invisible Unicode tag characters used to hide content",
            ))
        elif has_invisibles(raw):
            findings.append(Finding(
                detector=self.name, category="obfuscation",
                severity=Severity.MEDIUM,
                message="zero-width characters splitting up text",
            ))

        glyphs = homoglyph_chars(raw)
        if glyphs:
            sample = "".join(dict.fromkeys(glyphs))[:10]
            findings.append(Finding(
                detector=self.name, category="obfuscation",
                severity=Severity.MEDIUM,
                message="homoglyph look-alike characters mixed into text",
                evidence=sample,
            ))

        if ctx.decoded:
            findings.append(Finding(
                detector=self.name, category="obfuscation",
                severity=Severity.LOW,
                message="encoded payload decodes to readable text",
                evidence=ctx.decoded[0][:80],
            ))
        return findings
