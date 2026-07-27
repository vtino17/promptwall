"""Prompt-injection detector: attempts to override the system's instructions."""
from __future__ import annotations

from .base import KeywordDetector
from ..types import Severity


class InjectionDetector(KeywordDetector):
    name = "injection"
    category = "prompt_injection"
    severity = Severity.HIGH

    patterns = (
        (r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|"
         r"earlier|preceding|foregoing)\s+(?:instructions?|prompts?|"
         r"directions?|rules?|context|messages?)",
         "instruction to ignore prior instructions"),
        (r"\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|"
         r"earlier|system)\b",
         "instruction to disregard prior context"),
        (r"\bforget\s+(?:everything|all|your|the|previous|prior)\b.{0,30}"
         r"(?:instructions?|rules?|said|above|training)?",
         "instruction to forget prior context"),
        (r"\boverride\s+(?:the\s+|your\s+|all\s+)?(?:system\s+)?"
         r"(?:instructions?|prompt|settings?|rules?)",
         "instruction to override system settings"),
        (r"\byou\s+are\s+no\s+longer\s+(?:bound|restricted|required|obligated)\b",
         "attempt to lift the system's constraints"),
        (r"\b(?:new|updated|revised)\s+(?:instructions?|system\s+prompt|rules?)\s*:",
         "injected replacement instructions"),
        (r"\bsystem\s*(?:prompt|message)?\s*(?:override|:)\s*",
         "forged system-prompt marker"),
        (r"\binstead\s*,?\s+(?:you\s+(?:should|must|will)|(?:please\s+)?"
         r"(?:respond|reply|output|say|do|answer))\b",
         "redirection to attacker-chosen behaviour"),
        (r"\bfrom\s+now\s+on\b.{0,40}\b(?:you\s+(?:will|must|are)|respond|ignore)",
         "attempt to redefine behaviour going forward"),
        (r"\bdo\s+not\s+(?:follow|obey|comply\s+with)\b.{0,30}"
         r"(?:instructions?|rules?|guidelines?|system)",
         "instruction to stop following the rules"),
    )
