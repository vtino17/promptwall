"""Detector base class and a small registry.

A detector is any object with a ``name`` and a ``scan(ctx) -> list[Finding]``
method. Keeping the interface this small makes third-party detectors trivial to
add: subclass, implement ``scan``, done.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import List

from ..normalize import ScanContext
from ..types import Finding, Severity


class Detector(ABC):
    #: stable identifier used in findings and when enabling/disabling detectors
    name: str = "detector"

    @abstractmethod
    def scan(self, ctx: ScanContext) -> List[Finding]:
        """Return every finding this detector sees in ``ctx`` (possibly empty)."""
        raise NotImplementedError


class KeywordDetector(Detector):
    """Base for detectors that fire on a list of regular expressions.

    Subclasses supply ``patterns`` (each a ``(regex, message)`` pair). Matching
    runs against the folded text *and* every decoded payload, so an instruction
    hidden inside a base64 blob is reported one severity step higher than the
    same instruction sent in the clear.
    """

    category: str = "generic"
    severity: Severity = Severity.MEDIUM
    patterns: Iterable = ()

    def __init__(self):
        self._compiled = [
            (re.compile(p, re.IGNORECASE), msg) for p, msg in self.patterns
        ]

    def _bump(self, severity: Severity) -> Severity:
        one_up = min(int(severity) + 1, int(Severity.CRITICAL))
        return Severity(one_up)

    def scan(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        haystacks = ctx.searchable()
        for index, hay in enumerate(haystacks):
            hidden = index > 0  # anything past the first view came from a payload
            for regex, message in self._compiled:
                match = regex.search(hay)
                if not match:
                    continue
                severity = self._bump(self.severity) if hidden else self.severity
                note = message + (" (hidden in encoded payload)" if hidden else "")
                findings.append(
                    Finding(
                        detector=self.name,
                        category=self.category,
                        severity=severity,
                        message=note,
                        evidence=match.group(0)[:120],
                    )
                )
                break  # one finding per view is enough; avoid duplicate noise
        return findings
