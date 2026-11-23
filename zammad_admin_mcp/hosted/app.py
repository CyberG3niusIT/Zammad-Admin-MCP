from __future__ import annotations

import asyncio
import os
import sys
from contextlib import asynccontextmanager

import uvicorn
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from . import repository
from .auth import HostedTokenVerifier
from .egress import RestrictedEgressProxy, validate_issuer_url, validate_public_mcp_url
from .tools import register_tools


def create_app():
    public_url = validate_public_mcp_url(os.environ["MCP_PUBLIC_URL"])
    issuer = validate_issuer_url(os.environ["MCP_OAUTH_ISSUER"])
    verifier = HostedTokenVerifier(public_url, issuer)

    @asynccontextmanager
    async def lifespan(_server):
        proxy = RestrictedEgressProxy()
        await proxy.start()
        repository.set_egress_proxy(proxy.url)
        try:
            await repository.open_pool()
            yield
        finally:
            await repository.pool.close()
            repository.set_egress_proxy(None)
            await proxy.close()

    server = FastMCP(
        name="zammad-admin",
        instructions="Customer-scoped Zammad administration. Only the authenticated tenant's connection is accessible.",
        token_verifier=verifier,
        auth=AuthSettings(issuer_url=issuer, resource_server_url=public_url, validate_token_resource=True),
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        lifespan=lifespan,
    )
    register_tools(server)
    return server.streamable_http_app()


def main() -> None:
    app = create_app()
    config = uvicorn.Config(app, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8000")))
    server = uvicorn.Server(config)
    if sys.platform == "win32":
        with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
            runner.run(server.serve())
    else:
        uvicorn.run(app, host=config.host, port=config.port)


if __name__ == "__main__":
    main()
