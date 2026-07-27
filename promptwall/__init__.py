"""PromptWall -- a firewall for Large Language Model traffic.

Detects prompt injection, jailbreaks, system-prompt exfiltration, leaked
secrets/PII, and obfuscated payloads in the text flowing into and out of an
LLM, then blocks, flags, or redacts according to a simple, explainable policy.

Quick start::

    import promptwall

    result = promptwall.scan("ignore all previous instructions")
    if result.blocked:
        ...

    # or keep an instance for custom policies:
    fw = promptwall.Firewall(policy=promptwall.STRICT_POLICY)
"""
from __future__ import annotations

from .types import Action, Direction, Finding, ScanResult, Severity
from .policy import Policy, DEFAULT_POLICY, STRICT_POLICY, AUDIT_POLICY
from .firewall import Firewall, Blocked
from .detectors import Detector, DataExfiltrationDetector, default_detectors

__version__ = "0.1.0"

__all__ = [
    "Firewall",
    "Blocked",
    "Policy",
    "DEFAULT_POLICY",
    "STRICT_POLICY",
    "AUDIT_POLICY",
    "Detector",
    "DataExfiltrationDetector",
    "default_detectors",
    "Action",
    "Direction",
    "Finding",
    "ScanResult",
    "Severity",
    "scan",
    "scan_output",
]

# A process-wide default firewall for the convenience functions below.
_default = Firewall()


def scan(text: str) -> ScanResult:
    """Scan text as model *input* using the default firewall."""
    return _default.scan_input(text)


def scan_output(text: str) -> ScanResult:
    """Scan text as model *output* using the default firewall."""
    return _default.scan_output(text)
