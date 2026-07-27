"""Jailbreak detector: attempts to unlock unrestricted / persona-based modes."""
from __future__ import annotations

from .base import KeywordDetector
from ..types import Severity


class JailbreakDetector(KeywordDetector):
    name = "jailbreak"
    category = "jailbreak"
    severity = Severity.HIGH

    patterns = (
        (r"\bdo\s+anything\s+now\b|\bdan\s+mode\b|\byou\s+are\s+dan\b",
         "'DAN' jailbreak persona"),
        (r"\bdeveloper\s+mode\b(?:\s+enabled)?",
         "'developer mode' jailbreak"),
        (r"\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|uncensored|amoral|"
         r"unfiltered|jailbroken|evil)\b",
         "request to become an unrestricted persona"),
        (r"\bpretend\s+(?:you\s+are|to\s+be)\b.{0,40}\b(?:no|without|free\s+of|"
         r"ignore)\b.{0,20}(?:restrictions?|rules?|filters?|guidelines?|limits?)",
         "roleplay framed to drop safety rules"),
        (r"\b(?:act|roleplay|role-play)\s+as\b.{0,40}\b(?:unrestricted|uncensored|"
         r"evil|amoral|without\s+(?:restrictions?|filters?))",
         "roleplay as an unrestricted character"),
        (r"\bjailbreak(?:ing|en)?\b",
         "explicit mention of jailbreaking"),
        (r"\bignore\s+(?:your\s+)?(?:safety|content|ethical)\s+"
         r"(?:guidelines?|policy|policies|filters?|programming)",
         "request to bypass the safety policy"),
        (r"\bthere\s+(?:are|is)\s+no\s+(?:rules?|restrictions?|limits?|"
         r"guidelines?|filters?)\b",
         "assertion that no rules apply"),
        (r"\byou\s+(?:can|must|will)\s+not?\s+refuse\b|\bnever\s+refuse\b",
         "attempt to forbid refusals"),
        (r"\b(?:stan|aim|dude|kevin|mongo\s*tom)\s+(?:mode|persona)\b",
         "named jailbreak persona"),
        (r"\bhypothetical(?:ly)?\b.{0,40}\bno\s+(?:rules?|restrictions?|"
         r"consequences?|filter)",
         "'hypothetical with no rules' framing"),

        # --- Indonesian ---
        (r"\bkamu\s+sekarang\s+(?:adalah\s+)?(?:tanpa\s+batasan|tidak\s+dibatasi|"
         r"bebas\s+tanpa\s+aturan|tidak\s+difilter|tanpa\s+filter)",
         "request to become an unrestricted persona (id)"),
        (r"\babaikan\s+(?:aturan|panduan|pedoman|kebijakan)\s+keamanan",
         "request to bypass the safety policy (id)"),
        (r"\btidak\s+ada\s+(?:aturan|batasan|larangan|filter)\b",
         "assertion that no rules apply (id)"),
        (r"\bmode\s+pengembang\b",
         "'developer mode' jailbreak (id)"),
        (r"\b(?:kamu\s+tidak\s+(?:boleh|bisa)\s+menolak|jangan\s+pernah\s+menolak)\b",
         "attempt to forbid refusals (id)"),
    )
