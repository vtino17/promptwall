"""Additional provider credential patterns."""

import pytest

from promptwall.detectors import SecretDetector
from promptwall.normalize import ScanContext
from promptwall.types import Severity


def scan(text):
    return SecretDetector().scan(ScanContext.build(text))


@pytest.mark.parametrize(
    "text,label",
    [
        ("token github_pat_" + "A" * 22 + "_" + "b" * 20, "GitHub fine-grained"),
        ("npm_" + "a" * 36, "npm"),
        ("key SG." + "a" * 20 + "." + "b" * 25, "SendGrid"),
        (
            "https://hooks.slack.com/services/T00000000/B11111111/aBcDeFgHiJkLmNoPqR",
            "Slack webhook",
        ),
    ],
)
def test_new_provider_secrets_are_detected(text, label):
    f = scan(text)
    assert f, f"expected a finding for {label}"
    assert all(x.severity == Severity.CRITICAL for x in f)
    assert all(x.redactable and x.span is not None for x in f)


def test_github_fine_grained_not_confused_with_classic():
    # github_pat_ must be caught even though it starts with "gh".
    f = scan("github_pat_" + "X" * 30)
    assert any("fine-grained" in x.message for x in f)


def test_plain_prose_has_no_new_false_positives():
    assert scan("the package manager npm installed the module") == []
