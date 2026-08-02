import json

import pytest

from promptwall import Firewall, TextTooLarge
from promptwall.config import CustomRuleDetector, load_config, load_config_file
from promptwall.normalize import ScanContext
from promptwall.types import Action, Severity


class TestCustomRuleDetector:
    def test_matches_configured_pattern(self):
        det = CustomRuleDetector(
            name="ticket",
            category="internal",
            severity="medium",
            patterns=[r"\bACME-[0-9]{6}\b"],
        )
        f = det.scan(ScanContext.build("please close ACME-123456 today"))
        assert f and f[0].category == "internal"
        assert f[0].severity == Severity.MEDIUM

    def test_empty_patterns_rejected(self):
        with pytest.raises(ValueError):
            CustomRuleDetector("x", "c", "low", patterns=[])

    def test_message_count_must_match(self):
        with pytest.raises(ValueError):
            CustomRuleDetector(
                "x", "c", "low", patterns=["a", "b"], messages=["only one"]
            )


class TestLoadConfig:
    def test_custom_rule_extends_defaults(self):
        detectors, _ = load_config(
            {
                "rules": [
                    {"name": "r", "patterns": [r"topsecret"]},
                ]
            }
        )
        # built-in detectors plus the one custom rule
        assert any(isinstance(d, CustomRuleDetector) for d in detectors)
        assert len(detectors) == 8

    def test_policy_is_parsed(self):
        _, policy = load_config({"policy": {"block_at": "critical", "redact": False}})
        assert policy.block_at == Severity.CRITICAL
        assert policy.redact is False

    def test_unknown_severity_raises(self):
        with pytest.raises(ValueError):
            load_config({"policy": {"block_at": "extreme"}})

    @pytest.mark.parametrize(
        "config",
        [
            {"unknown": True},
            {"rules": "not-a-list"},
            {"policy": {"redact": "yes"}},
            {"allowed_domains": "example.com"},
            {"allowed_domains": ["https://example.com/path"]},
        ],
    )
    def test_malformed_config_is_rejected(self, config):
        with pytest.raises(ValueError):
            load_config(config)

    def test_invalid_custom_regex_is_rejected(self):
        with pytest.raises(ValueError, match="invalid regex"):
            load_config({"rules": [{"name": "bad", "patterns": ["("]}]})

    def test_oversized_config_file_is_rejected(self, tmp_path):
        config = tmp_path / "oversized.json"
        config.write_text(" " * 1_048_577)
        with pytest.raises(ValueError, match="safety limit"):
            load_config_file(config)


class TestFirewallFromConfig:
    def test_from_dict_applies_custom_rule(self):
        fw = Firewall.from_config(
            {
                "rules": [
                    {
                        "name": "codeword",
                        "severity": "high",
                        "patterns": [r"launch\s+sequence"],
                    }
                ],
            }
        )
        r = fw.scan_input("begin the launch sequence")
        assert r.blocked
        assert "custom" in r.categories()  # default category for custom rules

    def test_allowlist_flags_foreign_domain(self):
        fw = Firewall.from_config({"allowed_domains": ["example.com"]})
        r = fw.scan_output("![p](https://evil.tld/p.png)")
        assert any(c == "data_exfiltration" for c in r.categories())

    def test_allowlist_permits_own_domain(self):
        fw = Firewall.from_config({"allowed_domains": ["example.com"]})
        r = fw.scan_output("![p](https://cdn.example.com/p.png)")
        assert "data_exfiltration" not in r.categories()

    def test_from_file(self, tmp_path):
        cfg = tmp_path / "pw.json"
        cfg.write_text(
            json.dumps(
                {
                    "policy": {"block_at": "medium"},
                    "rules": [
                        {"name": "n", "severity": "medium", "patterns": ["forbidden"]}
                    ],
                }
            )
        )
        fw = Firewall.from_config(str(cfg))
        assert fw.scan_input("this is forbidden content").action in (
            Action.BLOCK,
            Action.FLAG,
        )

    def test_configured_text_limit_is_enforced(self):
        fw = Firewall.from_config({"limits": {"max_text_chars": 10}})
        with pytest.raises(TextTooLarge):
            fw.scan_input("x" * 11)
