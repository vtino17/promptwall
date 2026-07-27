"""Secret detector: credentials and keys that must never reach an LLM or a log.

Unlike the keyword detectors, this one runs on the raw text and reports exact
``span`` offsets, so the policy can *redact* the secret in place rather than
dropping the whole message.
"""
from __future__ import annotations

import re
from typing import List

from .base import Detector
from ..normalize import ScanContext
from ..types import Finding, Severity

# (label, compiled pattern). Order matters only for readability; every pattern
# is tried. Patterns are deliberately specific to keep false positives low.
_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe secret key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    ("private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("generic credential assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\b"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*._-]{8,})['\"]?")),
]


class SecretDetector(Detector):
    name = "secrets"

    def scan(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        claimed: List[tuple] = []  # spans already reported, to avoid overlaps
        for label, regex in _PATTERNS:
            for match in regex.finditer(ctx.raw):
                # For the generic assignment pattern the secret is group 1;
                # redact only the value, not the "password=" label.
                span = match.span(1) if match.lastindex else match.span(0)
                if any(span[0] < e and s < span[1] for s, e in claimed):
                    continue  # a more specific pattern already covered this
                claimed.append(span)
                findings.append(
                    Finding(
                        detector=self.name,
                        category="secret",
                        severity=Severity.CRITICAL,
                        message=f"{label} present in text",
                        evidence=_mask(match.group(0)),
                        span=span,
                        redactable=True,
                    )
                )
        return findings


def _mask(value: str) -> str:
    """Show only the first few characters of a secret in evidence output."""
    value = value.splitlines()[0]
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:6] + "***" + f"({len(value)} chars)"
