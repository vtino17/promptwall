from promptwall.policy import AUDIT_POLICY, DEFAULT_POLICY, STRICT_POLICY, Policy
from promptwall.types import Action, Finding, Severity


def finding(sev, redactable=False):
    return Finding(detector="t", category="c", severity=sev,
                   message="m", redactable=redactable)


class TestDefaultPolicy:
    p = DEFAULT_POLICY

    def test_no_findings_allows(self):
        assert self.p.decide([]) is Action.ALLOW

    def test_high_non_redactable_blocks(self):
        assert self.p.decide([finding(Severity.HIGH)]) is Action.BLOCK

    def test_critical_non_redactable_blocks(self):
        assert self.p.decide([finding(Severity.CRITICAL)]) is Action.BLOCK

    def test_redactable_secret_is_redacted_not_blocked(self):
        assert self.p.decide([finding(Severity.CRITICAL, redactable=True)]) is Action.REDACT

    def test_medium_pii_is_redacted(self):
        assert self.p.decide([finding(Severity.MEDIUM, redactable=True)]) is Action.REDACT

    def test_low_only_is_flagged(self):
        assert self.p.decide([finding(Severity.LOW)]) is Action.FLAG

    def test_block_wins_over_redact(self):
        decided = self.p.decide([
            finding(Severity.HIGH),                       # injection -> block
            finding(Severity.CRITICAL, redactable=True),  # secret -> redact
        ])
        assert decided is Action.BLOCK


class TestStrictPolicy:
    p = STRICT_POLICY

    def test_redaction_disabled_blocks_secrets(self):
        assert self.p.decide([finding(Severity.CRITICAL, redactable=True)]) is Action.BLOCK

    def test_medium_blocks(self):
        assert self.p.decide([finding(Severity.MEDIUM)]) is Action.BLOCK


class TestAuditPolicy:
    p = AUDIT_POLICY

    def test_never_blocks_even_critical(self):
        assert self.p.decide([finding(Severity.CRITICAL)]) is Action.FLAG

    def test_still_flags(self):
        assert self.p.decide([finding(Severity.LOW)]) is Action.FLAG


class TestCustomPolicy:
    def test_thresholds_are_configurable(self):
        p = Policy(block_at=Severity.CRITICAL, flag_at=Severity.MEDIUM, redact=False)
        assert p.decide([finding(Severity.HIGH)]) is Action.FLAG
        assert p.decide([finding(Severity.CRITICAL)]) is Action.BLOCK
        assert p.decide([finding(Severity.LOW)]) is Action.ALLOW
