"""Policy: turn a list of findings into a single action.

The policy is intentionally simple and explainable -- an operator can read the
thresholds and predict exactly what will happen. There is no scoring black box.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .types import Action, Finding, Severity


@dataclass
class Policy:
    """Maps findings to an :class:`~promptwall.types.Action`.

    * ``block_at`` -- a non-redactable finding at or above this severity blocks
      the message outright (default: HIGH, i.e. injections and jailbreaks).
    * ``flag_at`` -- anything at or above this severity that did not block or
      redact is reported as a flag (default: LOW).
    * ``redact`` -- when True, redactable findings (secrets, PII) cause the
      message to be redacted rather than blocked, so useful text still flows.
      When False, a redactable finding at ``block_at`` blocks instead.
    """

    block_at: int = Severity.HIGH
    flag_at: int = Severity.LOW
    redact: bool = True

    def decide(self, findings: List[Finding]) -> Action:
        if not findings:
            return Action.ALLOW

        # A hard block wins over everything: any non-redactable finding at the
        # block threshold, or -- when redaction is off -- any such finding.
        for f in findings:
            if f.severity >= self.block_at and not (f.redactable and self.redact):
                return Action.BLOCK

        if self.redact and any(f.redactable for f in findings):
            return Action.REDACT

        if any(f.severity >= self.flag_at for f in findings):
            return Action.FLAG

        return Action.ALLOW


#: Sensible default used by :class:`~promptwall.firewall.Firewall`.
DEFAULT_POLICY = Policy()

#: Never redact -- block anything that trips a detector at HIGH+. Useful when a
#: partial/redacted message is worse than no message.
STRICT_POLICY = Policy(block_at=Severity.MEDIUM, flag_at=Severity.LOW, redact=False)

#: Observe-only: never block, only flag. ``block_at`` sits above CRITICAL so no
#: finding can ever reach it. Good for a shadow/monitoring rollout.
AUDIT_POLICY = Policy(block_at=int(Severity.CRITICAL) + 1,
                      flag_at=Severity.LOW, redact=False)
