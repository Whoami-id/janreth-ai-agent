"""Load tools from an MCP (Model Context Protocol) server.

Supports three transports via the ``transport`` argument:

- ``"stdio"`` (default): launch a local subprocess server; ``connection`` is
  ``{"command": ..., "args": [...], "env": {...}}``.
- ``"sse"``: connect to a running HTTP server over Server-Sent Events;
  ``connection`` is ``{"url": ..., "headers": {...}}``.
- ``"streamable_http"``: the modern streamable-HTTP transport; same
  ``{"url": ..., "headers": {...}}`` shape.
"""

from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from janreth.tools.base import BaseTool, FunctionTool
from janreth.tools.helpers import format_tool_definition


def _extract_text_content(result) -> str:
    """Extract plain text from an MCP CallToolResult."""
    parts = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
    return "\n".join(parts)


@asynccontextmanager
async def _mcp_session(connection: dict, transport: str = "stdio"):
    """Open an initialized MCP ClientSession over the chosen transport."""
    if transport == "stdio":
        client_cm = stdio_client(StdioServerParameters(**connection))
    elif transport == "sse":
        from mcp.client.sse import sse_client

        client_cm = sse_client(connection["url"], headers=connection.get("headers"))
    elif transport in ("streamable_http", "http"):
        from mcp.client.streamable_http import streamablehttp_client

        client_cm = streamablehttp_client(
            connection["url"], headers=connection.get("headers")
        )
    else:
        raise ValueError(
            f"unknown MCP transport {transport!r}; "
            "use 'stdio', 'sse', or 'streamable_http'"
        )

    async with client_cm as streams:
        # stdio/sse yield (read, write); streamable_http yields a 3rd session-id item.
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def _create_mcp_tool(mcp_tool, connection: dict, transport: str = "stdio") -> FunctionTool:
    """Create a FunctionTool that wraps an MCP tool."""

    async def call_mcp(**kwargs):
        async with _mcp_session(connection, transport) as session:
            result = await session.call_tool(mcp_tool.name, kwargs)
            return _extract_text_content(result)

    tool_definition = {
        "type": "function",
        "function": {
            "name": mcp_tool.name,
            "description": mcp_tool.description,
            "parameters": mcp_tool.inputSchema,
        },
    }

    return FunctionTool(
        func=call_mcp,
        name=mcp_tool.name,
        description=mcp_tool.description,
        tool_definition=tool_definition,
    )


async def load_mcp_tools(connection: dict, transport: str = "stdio") -> list[BaseTool]:
    """Load tools from an MCP server and convert them to FunctionTools.

    Each MCP tool becomes a FunctionTool that re-establishes the connection on
    each invocation. ``transport`` is ``"stdio"`` (default), ``"sse"``, or
    ``"streamable_http"`` — see the module docstring for the ``connection`` shape.
    """
    tools: list[BaseTool] = []

    async with _mcp_session(connection, transport) as session:
        mcp_tools = await session.list_tools()
        for mcp_tool in mcp_tools.tools:
            tools.append(_create_mcp_tool(mcp_tool, connection, transport))

    return tools


def mcp_tools_to_openai_format(mcp_tools) -> list[dict]:
    """Convert MCP tool definitions to OpenAI tool format."""
    return [
        format_tool_definition(
            name=tool.name,
            description=tool.description,
            parameters=tool.inputSchema,
        )
        for tool in mcp_tools.tools
    ]


@asynccontextmanager
async def mcp_connection(connection: dict, transport: str = "stdio"):
    """Context manager for a live MCP server session over the chosen transport.

    Usage::

        async with mcp_connection({"command": "npx", "args": [...]}) as session:
            tools = await session.list_tools()
            result = await session.call_tool("tool_name", arguments={...})

        async with mcp_connection({"url": "http://localhost:3000/mcp"},
                                  transport="streamable_http") as session:
            ...
    """
    async with _mcp_session(connection, transport) as session:
        yield session
