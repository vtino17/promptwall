import pytest

from promptwall.detectors import PIIDetector, SecretDetector
from promptwall.normalize import ScanContext
from promptwall.types import Severity


def scan(detector, text):
    return detector.scan(ScanContext.build(text))


class TestSecrets:
    det = SecretDetector()

    @pytest.mark.parametrize(
        "text,label",
        [
            ("key: sk-abcdef0123456789ABCDEFghij", "OpenAI"),
            ("AKIAIOSFODNN7EXAMPLE is the id", "AWS"),
            ("token ghp_" + "a" * 36, "GitHub"),
            ("AIza" + "b" * 35, "Google"),
            ("-----BEGIN RSA PRIVATE KEY-----", "private key"),
        ],
    )
    def test_detects_credentials(self, text, label):
        f = scan(self.det, text)
        assert f, f"expected a finding for {label}"
        assert all(x.severity == Severity.CRITICAL for x in f)
        assert all(x.redactable and x.span is not None for x in f)

    def test_generic_assignment_redacts_only_the_value(self):
        text = "database password = hunter2secret here"
        f = scan(self.det, text)
        assert f
        start, end = f[0].span
        assert text[start:end] == "hunter2secret"

    def test_evidence_is_masked(self):
        f = scan(self.det, "sk-abcdefghijklmnop0123456789")
        assert "***" in f[0].evidence
        assert "abcdefghijklmnop" not in f[0].evidence

    def test_clean_text_has_no_secrets(self):
        assert scan(self.det, "the meeting is at 3pm tomorrow") == []

    def test_overlapping_patterns_are_deduplicated(self):
        # An OpenAI key also loosely matches the generic assignment pattern.
        f = scan(self.det, "api_key = sk-abcdefghij0123456789ABCD")
        spans = [x.span for x in f]
        assert len(spans) == len(set(spans))  # no duplicate spans


class TestPII:
    det = PIIDetector()

    def test_detects_email(self):
        f = scan(self.det, "reach me at jane.doe@example.com anytime")
        assert any(x.message.startswith("email") for x in f)

    def test_detects_valid_credit_card(self):
        f = scan(self.det, "card 4111 1111 1111 1111 on file")
        assert any("payment card" in x.message for x in f)

    def test_rejects_invalid_card_number(self):
        # 16 digits that fail the Luhn checksum -> not a card.
        f = scan(self.det, "order number 1234567890123456 shipped")
        assert not any("payment card" in x.message for x in f)

    def test_detects_ssn_pattern(self):
        f = scan(self.det, "SSN 123-45-6789 on record")
        assert any("national id" in x.message.lower() for x in f)

    def test_detects_phone(self):
        f = scan(self.det, "call me at +1 415 555 2671 tonight")
        assert any("phone" in x.message for x in f)

    def test_ipv4_is_not_a_phone(self):
        f = scan(self.det, "the server is at 192.168.1.1 on the lan")
        assert not any("phone" in x.message for x in f)

    def test_clean_text_has_no_pii(self):
        assert scan(self.det, "the quick brown fox") == []
