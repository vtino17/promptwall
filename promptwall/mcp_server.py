"""Model Context Protocol server exposing PromptWall to AI assistants.

Run with ``python -m promptwall.mcp_server`` (or the ``promptwall-mcp`` script).
The :mod:`mcp` package is an optional dependency; importing this module without
it succeeds, and only :func:`main` raises a helpful error. That keeps the core
library dependency-free while still shipping the integration.

Tools exposed:
    * ``scan_prompt``   -- scan text about to be sent to a model
    * ``scan_response`` -- scan text a model produced
"""

from __future__ import annotations

import json

from .firewall import Firewall
from .types import Direction

_firewall = Firewall()


def _scan(text: str, direction: Direction) -> str:
    result = _firewall.scan(text, direction)
    payload = result.to_dict()
    payload["safe_text"] = result.safe_text
    return json.dumps(payload, indent=2)


def build_server():  # pragma: no cover - exercised only when mcp is installed
    """Construct the FastMCP server, importing :mod:`mcp` lazily."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "The 'mcp' package is required for the MCP server.\n"
            "Install it with:  pip install 'promptwall[mcp]'"
        ) from exc

    server = FastMCP("promptwall")

    @server.tool()
    def scan_prompt(text: str) -> str:
        """Scan text that is about to be sent to a language model."""
        return _scan(text, Direction.INPUT)

    @server.tool()
    def scan_response(text: str) -> str:
        """Scan text that a language model produced."""
        return _scan(text, Direction.OUTPUT)

    return server


def main() -> None:  # pragma: no cover
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
