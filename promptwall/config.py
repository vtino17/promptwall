"""Load a Firewall from JSON config: custom rules, policy, and an allowlist.

Config schema (every key optional)::

    {
      "policy": {"block_at": "high", "flag_at": "low", "redact": true},
      "allowed_domains": ["example.com"],
      "rules": [
        {
          "name": "internal_ticket",
          "category": "custom",
          "severity": "medium",
          "patterns": ["\\bACME-[0-9]{6}\\b"],
          "messages": ["internal ticket id present"]
        }
      ]
    }

Custom rules are appended to the built-in detectors, so a config only ever adds
coverage. This keeps the format small enough to hand to a non-Python operator.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from typing import List, Tuple, Union

from .detectors import (
    DataExfiltrationDetector,
    Detector,
    KeywordDetector,
    default_detectors,
)
from .policy import Policy
from .types import Severity

_SEVERITIES = {s.name.lower(): s for s in Severity}
_MAX_CONFIG_BYTES = 1_048_576
_MAX_RULES = 128
_MAX_PATTERNS_PER_RULE = 32
_MAX_PATTERN_CHARS = 512
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_DOMAIN = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _severity(value, default=Severity.MEDIUM) -> Severity:
    if value is None:
        return default
    if isinstance(value, Severity):
        return value
    try:
        return _SEVERITIES[str(value).lower()]
    except KeyError:
        raise ValueError(
            f"unknown severity {value!r}; expected one of {sorted(_SEVERITIES)}"
        ) from None


class CustomRuleDetector(KeywordDetector):
    """A :class:`KeywordDetector` configured entirely at construction time."""

    def __init__(self, name, category, severity, patterns, messages=None):
        if not patterns:
            raise ValueError(f"custom rule {name!r} has no patterns")
        self.name = name
        self.category = category
        self.severity = _severity(severity)
        messages = messages or [f"matched custom rule '{name}'"] * len(patterns)
        if len(messages) != len(patterns):
            raise ValueError(
                f"custom rule {name!r}: {len(messages)} messages for "
                f"{len(patterns)} patterns"
            )
        self.patterns = tuple(zip(patterns, messages))
        try:
            super().__init__()
        except re.error as exc:
            raise ValueError(f"custom rule {name!r} has invalid regex: {exc}") from None


def _require_mapping(value, name: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _parse_domains(value) -> List[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("allowed_domains must be a non-empty list of hostnames")
    if len(value) > 128:
        raise ValueError("allowed_domains contains more than 128 entries")
    domains = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("allowed_domains entries must be strings")
        domain = item.strip().lower().rstrip(".").lstrip(".")
        if not domain or len(domain) > 253 or not _DOMAIN.fullmatch(domain):
            raise ValueError(f"invalid allowed domain {item!r}; use a hostname only")
        domains.append(domain)
    return domains


def _parse_rule(rule, index: int) -> CustomRuleDetector:
    rule = _require_mapping(rule, f"rules[{index}]")
    name = rule.get("name")
    category = rule.get("category", "custom")
    if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
        raise ValueError(f"rules[{index}].name must be a bounded identifier")
    if not isinstance(category, str) or not _IDENTIFIER.fullmatch(category):
        raise ValueError(f"rules[{index}].category must be a bounded identifier")
    patterns = rule.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        raise ValueError(f"custom rule {name!r} has no patterns")
    if len(patterns) > _MAX_PATTERNS_PER_RULE:
        raise ValueError(f"custom rule {name!r} has too many patterns")
    if any(
        not isinstance(p, str) or not p or len(p) > _MAX_PATTERN_CHARS for p in patterns
    ):
        raise ValueError(
            f"custom rule {name!r} patterns must be non-empty strings of at most "
            f"{_MAX_PATTERN_CHARS} characters"
        )
    messages = rule.get("messages")
    if messages is not None and (
        not isinstance(messages, list)
        or any(not isinstance(message, str) for message in messages)
    ):
        raise ValueError(f"custom rule {name!r} messages must be a list of strings")
    return CustomRuleDetector(
        name=name,
        category=category,
        severity=rule.get("severity", "medium"),
        patterns=patterns,
        messages=messages,
    )


def _parse_config(data: dict):
    data = _require_mapping(data, "config")
    unknown = set(data) - {"policy", "allowed_domains", "rules", "limits"}
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")

    allowed = data.get("allowed_domains")
    if allowed is not None:
        allowed = _parse_domains(allowed)

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")
    if len(rules) > _MAX_RULES:
        raise ValueError(f"rules contains more than {_MAX_RULES} entries")
    detectors: List[Detector] = []
    for det in default_detectors():
        # Swap in an allowlist-aware exfiltration detector when one is configured.
        if allowed and isinstance(det, DataExfiltrationDetector):
            detectors.append(DataExfiltrationDetector(allowed_domains=allowed))
        else:
            detectors.append(det)

    for index, rule in enumerate(rules):
        detectors.append(_parse_rule(rule, index))

    pol = _require_mapping(data.get("policy", {}), "policy")
    unknown_policy = set(pol) - {"block_at", "flag_at", "redact"}
    if unknown_policy:
        raise ValueError(f"unknown policy keys: {sorted(unknown_policy)}")
    redact_value = pol.get("redact", True)
    if not isinstance(redact_value, bool):
        raise ValueError("policy.redact must be a boolean")
    policy = Policy(
        block_at=_severity(pol.get("block_at"), Severity.HIGH),
        flag_at=_severity(pol.get("flag_at"), Severity.LOW),
        redact=redact_value,
    )

    limits = _require_mapping(data.get("limits", {}), "limits")
    unknown_limits = set(limits) - {"max_text_chars"}
    if unknown_limits:
        raise ValueError(f"unknown limit keys: {sorted(unknown_limits)}")
    max_text_chars = limits.get("max_text_chars", 1_000_000)
    if isinstance(max_text_chars, bool) or not isinstance(max_text_chars, int):
        raise ValueError("limits.max_text_chars must be an integer")
    return detectors, policy, {"max_text_chars": max_text_chars}


def load_config(data: dict) -> Tuple[List[Detector], Policy]:
    """Return ``(detectors, policy)`` built from a validated config dict."""
    detectors, policy, _ = _parse_config(data)
    return detectors, policy


def load_config_with_limits(data: dict):
    """Return validated detectors, policy, and Firewall resource limits."""
    return _parse_config(data)


def _read_config_file(path: Union[str, os.PathLike]):
    size = os.stat(path).st_size
    if size > _MAX_CONFIG_BYTES:
        raise ValueError(
            f"config file exceeds the {_MAX_CONFIG_BYTES}-byte safety limit"
        )
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data


def load_config_file(path: Union[str, os.PathLike]) -> Tuple[List[Detector], Policy]:
    return load_config(_read_config_file(path))


def load_config_file_with_limits(path: Union[str, os.PathLike]):
    return load_config_with_limits(_read_config_file(path))
