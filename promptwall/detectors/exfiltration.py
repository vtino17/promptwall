"""System-prompt / context exfiltration detector.

Catches the classic "repeat the words above" family of attacks that try to make
the model leak its own system prompt or hidden context.
"""

from __future__ import annotations

from ..types import Severity
from .base import KeywordDetector


class ExfiltrationDetector(KeywordDetector):
    name = "exfiltration"
    category = "system_prompt_leak"
    severity = Severity.HIGH

    patterns = (
        (
            r"\b(?:repeat|print|output|show|display|reveal|give\s+me)\b.{0,40}"
            r"\b(?:system\s+prompt|initial\s+instructions?|the\s+words?\s+above|"
            r"everything\s+above|text\s+above|your\s+instructions?|your\s+prompt)",
            "request to reveal the system prompt",
        ),
        (
            r"\bwhat\s+(?:is|are|was|were)\s+(?:your|the)\s+"
            r"(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|"
            r"rules?|guidelines?|configuration)\b",
            "question probing for the system prompt",
        ),
        (
            r"\b(?:repeat|say)\s+(?:the\s+)?(?:words?|text|everything)\s+"
            r"(?:above|before\s+this)\b",
            "'repeat the words above' exfiltration",
        ),
        (
            r"\boutput\s+(?:the\s+)?(?:previous|preceding|prior)\s+"
            r"(?:text|messages?|content)\s+verbatim\b",
            "request to dump prior context verbatim",
        ),
        (
            r"\b(?:ignore\s+that\s+and\s+)?(?:tell|show)\s+me\s+your\s+"
            r"(?:prompt|instructions?|rules?|guidelines?)\b",
            "request to disclose internal instructions",
        ),
        (
            r"\bbegin\s+your\s+(?:reply|response|answer)\s+with\b.{0,40}"
            r"(?:you\s+are|system|instructions?)",
            "prefix-injection to leak boilerplate instructions",
        ),
        # --- Indonesian ---
        (
            r"\bulangi\s+(?:instruksi|system\s+prompt|prompt\s+sistem|"
            r"kata-kata\s+di\s+atas|teks\s+di\s+atas)",
            "'repeat the words above' exfiltration (id)",
        ),
        (
            r"\bapa\s+(?:instruksi|prompt|aturan)\s+(?:awal|sistem|asli|sebenarnya)"
            r"\s+kamu\b",
            "question probing for the system prompt (id)",
        ),
        (
            r"\b(?:tampilkan|tunjukkan|beritahu(?:kan)?)\s+(?:instruksi|prompt|aturan)"
            r"\s+(?:sistem\s+)?kamu\b",
            "request to reveal the system prompt (id)",
        ),
    )
