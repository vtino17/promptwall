"""Command-line interface: ``promptwall scan``.

Reads text from an argument or stdin, prints a human or JSON report, and exits
non-zero when the text is blocked so it can gate a shell pipeline.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .firewall import Firewall
from .policy import AUDIT_POLICY, DEFAULT_POLICY, STRICT_POLICY
from .types import Action, Direction

_POLICIES = {"default": DEFAULT_POLICY, "strict": STRICT_POLICY, "audit": AUDIT_POLICY}

# Exit codes double as a signal for scripts: 0 clean, 1 blocked, 2 flagged/redacted.
_EXIT = {Action.ALLOW: 0, Action.BLOCK: 1, Action.FLAG: 2, Action.REDACT: 2}

_COLORS = {
    Action.ALLOW: "\033[32m", Action.FLAG: "\033[33m",
    Action.REDACT: "\033[36m", Action.BLOCK: "\033[31m",
}
_RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptwall",
        description="A firewall for LLM traffic: detect prompt injection, "
                    "jailbreaks, secret/PII leaks, and obfuscated payloads.",
    )
    parser.add_argument("--version", action="version",
                        version=f"promptwall {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan text for threats")
    scan.add_argument("text", nargs="?",
                      help="Text to scan (reads stdin when omitted)")
    scan.add_argument("-d", "--direction", choices=["input", "output"],
                      default="input", help="Whether the text is model input or output")
    scan.add_argument("-p", "--policy", choices=list(_POLICIES),
                      default="default", help="Policy to apply")
    scan.add_argument("-c", "--config", metavar="FILE",
                      help="JSON config with custom rules, policy, and allowlist "
                           "(overrides --policy)")
    scan.add_argument("--json", action="store_true", help="Emit a JSON report")
    scan.add_argument("-q", "--quiet", action="store_true",
                      help="Print nothing; communicate only via exit code")
    return parser


def _read_text(arg: Optional[str]) -> str:
    if arg is not None:
        return arg
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def _format_human(result, color: bool) -> str:
    tint = _COLORS[result.action] if color else ""
    reset = _RESET if color else ""
    lines = [f"{tint}{str(result.action).upper()}{reset}  "
             f"[{result.direction}] severity={result.severity}"]
    for f in result.findings:
        where = f" @{f.span[0]}-{f.span[1]}" if f.span else ""
        ev = f"  ({f.evidence})" if f.evidence else ""
        lines.append(f"  - {f.severity:<8} {f.detector}: {f.message}{where}{ev}")
    if result.action is Action.REDACT and result.redacted_text is not None:
        lines.append(f"\nredacted:\n{result.redacted_text}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 0

    text = _read_text(args.text)
    if not text:
        parser.error("no text provided (pass an argument or pipe via stdin)")

    if args.config:
        try:
            firewall = Firewall.from_config(args.config)
        except (OSError, ValueError, KeyError) as exc:
            parser.error(f"could not load config {args.config!r}: {exc}")
    else:
        firewall = Firewall(policy=_POLICIES[args.policy])
    result = firewall.scan(text, Direction(args.direction))

    if not args.quiet:
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(_format_human(result, color=sys.stdout.isatty()))

    return _EXIT[result.action]


if __name__ == "__main__":
    sys.exit(main())
