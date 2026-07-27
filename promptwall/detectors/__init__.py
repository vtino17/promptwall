"""Built-in detectors and the default detector set."""
from __future__ import annotations

from typing import List

from .base import Detector, KeywordDetector
from .injection import InjectionDetector
from .jailbreak import JailbreakDetector
from .exfiltration import ExfiltrationDetector
from .secrets import SecretDetector
from .pii import PIIDetector
from .obfuscation import ObfuscationDetector
from .exfil_channel import DataExfiltrationDetector

__all__ = [
    "Detector",
    "KeywordDetector",
    "InjectionDetector",
    "JailbreakDetector",
    "ExfiltrationDetector",
    "SecretDetector",
    "PIIDetector",
    "ObfuscationDetector",
    "DataExfiltrationDetector",
    "default_detectors",
]


def default_detectors() -> List[Detector]:
    """The detector set used by a :class:`~promptwall.firewall.Firewall`."""
    return [
        InjectionDetector(),
        JailbreakDetector(),
        ExfiltrationDetector(),
        SecretDetector(),
        PIIDetector(),
        ObfuscationDetector(),
        DataExfiltrationDetector(),
    ]
