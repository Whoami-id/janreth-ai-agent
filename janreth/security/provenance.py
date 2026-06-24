"""ToolProvenance - record where each tool came from; restrict MCP to trusted servers.

The supply chain of an agent's tools (local code vs an MCP server vs an A2A peer)
is part of its attack surface. ToolProvenance records each tool's origin and lets
a policy restrict MCP tool discovery to a trusted-server allow-list. Best-effort -
an [advisory estimate].

Maps to: T17 Supply Chain Compromise - MAESTRO Agent Ecosystem - ASI04 Agentic
Supply Chain Vulnerabilities - STRIDE Tampering - KC5.
"""

from __future__ import annotations

from janreth.security.taxonomy import ControlSpec, register

SPEC = register(
    ControlSpec(
        key="tool_provenance",
        name="ToolProvenance",
        summary="Record tool origin and restrict MCP discovery to a trusted-server allow-list.",
        seam="tool registration + tools/mcp.py",
        tcodes=("T17",),
        maestro=("Agent Ecosystem",),
        asi=("ASI04",),
        stride=("Tampering",),
        kc=("KC5",),
    )
)


def is_trusted_mcp(server: str, trusted: set[str]) -> bool:
    """True if an MCP server command/URL is on the trusted allow-list."""
    return server in trusted


def assert_trusted_mcp(server: str, trusted: set[str]) -> None:
    """Raise if an MCP server is not on the trusted allow-list (use before load_mcp_tools)."""
    if not is_trusted_mcp(server, trusted):
        raise PermissionError(
            f"MCP server {server!r} is not on the trusted allow-list (ToolProvenance)"
        )


def tool_origins(tools) -> dict[str, str]:
    """Best-effort origin label per tool name (advisory estimate).

    MCP-wrapped tools carry the server's verbatim inputSchema; everything else is
    treated as locally defined. A richer origin tag can be attached at
    registration time.
    """
    origins: dict[str, str] = {}
    for tool in tools:
        origins[tool.name] = getattr(tool, "origin", "local")
    return origins
