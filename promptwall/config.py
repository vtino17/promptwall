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
        super().__init__()


def load_config(data: dict) -> Tuple[List[Detector], Policy]:
    """Return ``(detectors, policy)`` built from a config dict."""
    allowed = data.get("allowed_domains")

    detectors: List[Detector] = []
    for det in default_detectors():
        # Swap in an allowlist-aware exfiltration detector when one is configured.
        if allowed and isinstance(det, DataExfiltrationDetector):
            detectors.append(DataExfiltrationDetector(allowed_domains=allowed))
        else:
            detectors.append(det)

    for rule in data.get("rules", []):
        detectors.append(CustomRuleDetector(
            name=rule["name"],
            category=rule.get("category", "custom"),
            severity=rule.get("severity", "medium"),
            patterns=rule["patterns"],
            messages=rule.get("messages"),
        ))

    pol = data.get("policy", {})
    policy = Policy(
        block_at=_severity(pol.get("block_at"), Severity.HIGH),
        flag_at=_severity(pol.get("flag_at"), Severity.LOW),
        redact=pol.get("redact", True),
    )
    return detectors, policy


def load_config_file(path: Union[str, os.PathLike]) -> Tuple[List[Detector], Policy]:
    with open(path, "r", encoding="utf-8") as fh:
        return load_config(json.load(fh))
