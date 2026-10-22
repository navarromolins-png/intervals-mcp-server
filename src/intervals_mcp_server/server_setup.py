"""
Server setup and initialization for Intervals.icu MCP Server.

This module handles transport configuration and server startup logic.
"""

import os
import logging

import fastmcp
from fastmcp import FastMCP

from intervals_mcp_server.utils.types import TransportAliases

logger = logging.getLogger("intervals_icu_mcp_server")


def setup_transport() -> TransportAliases:
    """
    Setup and validate the MCP transport configuration.

    Reads MCP_TRANSPORT environment variable and validates it against
    supported transport types.

    Returns:
        TransportAliases: The selected transport type.

    Raises:
        ValueError: If the transport type is not supported.
    """
    transport_env = os.getenv("MCP_TRANSPORT", TransportAliases.STDIO.value).lower()
    try:
        transport_alias = TransportAliases(transport_env)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in TransportAliases)
        raise ValueError(f"Unsupported MCP_TRANSPORT value. Use one of: {allowed}.") from exc

    # Map SSE and HTTP aliases to STREAMABLE_HTTP
    selected_transport = (
        TransportAliases.STREAMABLE_HTTP
        if transport_alias in (TransportAliases.HTTP, TransportAliases.SSE)
        else transport_alias
    )

    return selected_transport


def start_server(mcp_instance: FastMCP, transport: TransportAliases) -> None:
    """
    Start the MCP server with the specified transport.

    Args:
        mcp_instance (FastMCP): The FastMCP server instance to start.
        transport (TransportAliases): The transport type to use.
    """
    if transport == TransportAliases.STDIO:
        logger.info("Starting MCP server with stdio transport.")
        mcp_instance.run()
    else:  # STREAMABLE_HTTP
        # fastmcp reads host/port from its own global settings (FASTMCP_HOST/
        # FASTMCP_PORT) only once, at process start, so read them fresh here
        # rather than relying on that cached default.
        host = os.getenv("FASTMCP_HOST", "127.0.0.1")
        port = int(os.getenv("FASTMCP_PORT", "8000"))
        logger.info(
            "Starting MCP server with Streamable HTTP transport at http://%s:%s%s.",
            host,
            port,
            fastmcp.settings.streamable_http_path,
        )
        secret = os.getenv("MCP_CLIENT_SECRET", "")
        if not secret:
            mcp_instance.run(transport="streamable-http", host=host, port=port)
            return
        import uvicorn

        app = _KeyAuthShim(mcp_instance.http_app(transport="streamable-http"), secret)
        uvicorn.run(app, host=host, port=port, proxy_headers=True, forwarded_allow_ips="*")


class _KeyAuthShim:
    """Lets clients authenticate without OAuth.

    Accepts the access token (MCP_CLIENT_SECRET) as a ``?key=`` query
    parameter, and tidies the Authorization header (extra spaces, a doubled
    "Bearer " prefix) before the regular bearer-token check runs.
    """

    def __init__(self, app, secret: str):  # type: ignore[no-untyped-def]
        self.app = app
        self.secret = secret

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] == "http" and scope.get("path", "").startswith("/mcp"):
            from urllib.parse import parse_qs

            auth = dict(scope["headers"]).get(b"authorization", b"").decode("latin-1").strip()
            token = None
            if auth.lower().startswith("bearer "):
                token = auth
                while token.lower().startswith("bearer "):
                    token = token[7:].strip()
            key = parse_qs(scope.get("query_string", b"").decode()).get("key", [""])[0].strip()
            if key:
                token = key
            if token is not None:
                if token != self.secret:
                    logger.info(
                        "Bearer token mismatch (len=%d, expected len=%d)", len(token), len(self.secret)
                    )
                headers = [(k, v) for k, v in scope["headers"] if k != b"authorization"]
                headers.append((b"authorization", f"Bearer {token}".encode("latin-1")))
                scope = dict(scope, headers=headers)
        await self.app(scope, receive, send)
