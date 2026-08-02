"""Core value types shared across PromptWall.

Everything here is a plain dataclass / enum with no third-party dependencies so
the whole detection pipeline stays importable in the smallest environment.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Tuple


class Severity(enum.IntEnum):
    """How dangerous a single finding is.

    Ordered so thresholds can be expressed as ``severity >= Severity.HIGH``.
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # nicer CLI/JSON output than "Severity.HIGH"
        return self.name.lower()


class Direction(enum.Enum):
    """Which side of the model a piece of text came from.

    INPUT is user/tool text heading *into* the model; OUTPUT is text the model
    produced. Some detectors only make sense in one direction.
    """

    INPUT = "input"
    OUTPUT = "output"

    def __str__(self) -> str:
        return self.value


class Action(enum.Enum):
    """What the policy decided should happen to the text."""

    ALLOW = "allow"
    FLAG = "flag"
    REDACT = "redact"
    BLOCK = "block"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Finding:
    """A single thing a detector noticed.

    ``span`` is a ``(start, end)`` offset into the *original* text when the
    detector can point at exact characters (secrets, PII); it is ``None`` for
    detectors that reason over normalised text where offsets no longer line up.
    ``redactable`` marks findings whose ``span`` can be masked in place instead
    of blocking the whole message.
    """

    detector: str
    category: str
    severity: Severity
    message: str
    evidence: str = ""
    span: Optional[Tuple[int, int]] = None
    redactable: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


@dataclass
class ScanResult:
    """The verdict for one scanned string."""

    text: str
    direction: Direction
    findings: List[Finding] = field(default_factory=list)
    action: Action = Action.ALLOW
    redacted_text: Optional[str] = None

    @property
    def severity(self) -> Severity:
        """Highest severity among the findings (``NONE`` when clean)."""
        if not self.findings:
            return Severity.NONE
        return max(f.severity for f in self.findings)

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    @property
    def safe_text(self) -> str:
        """Text safe to forward: redacted copy when redacting, else the original."""
        if self.action is Action.REDACT and self.redacted_text is not None:
            return self.redacted_text
        return self.text

    def categories(self) -> List[str]:
        seen = []
        for f in self.findings:
            if f.category not in seen:
                seen.append(f.category)
        return seen

    def to_dict(self) -> dict:
        return {
            "direction": str(self.direction),
            "action": str(self.action),
            "severity": str(self.severity),
            "categories": self.categories(),
            "findings": [f.to_dict() for f in self.findings],
            "redacted_text": self.redacted_text,
        }
