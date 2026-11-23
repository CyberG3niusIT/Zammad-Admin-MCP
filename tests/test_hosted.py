import asyncio
import base64
import os
import unittest
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken

from zammad_admin_mcp.hosted.auth import HostedTokenVerifier
from zammad_admin_mcp.hosted.egress import RestrictedEgressProxy, public_addresses, validate_issuer_url, validate_public_mcp_url
from zammad_admin_mcp.hosted.repository import token_digest

class HostedTests(unittest.TestCase):
    def test_public_url_requires_canonical_mcp_https(self):
        self.assertEqual(validate_public_mcp_url("https://mcp.example.test/mcp"), "https://mcp.example.test/mcp")
        self.assertEqual(validate_issuer_url("https://tenant.example.test/"), "https://tenant.example.test/")
        with self.assertRaises(ValueError):
            validate_issuer_url("http://tenant.example.test/")
        for url in ("http://mcp.example.test/mcp", "https://user@mcp.example.test/mcp", "https://mcp.example.test/other", "https://mcp.example.test:8443/mcp"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_public_mcp_url(url)

    def test_proxy_rejects_private_reserved_and_mixed_dns_answers(self):
        self.assertEqual(str(next(iter(public_addresses(["8.8.8.8"])))), "8.8.8.8")
        for values in (["127.0.0.1"], ["169.254.169.254"], ["8.8.8.8", "10.0.0.5"]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                public_addresses(values)

    def test_proxy_denies_loopback_destination(self):
        async def check():
            proxy = RestrictedEgressProxy()
            await proxy.start()
            try:
                address = proxy._server.sockets[0].getsockname()
                reader, writer = await asyncio.open_connection(address[0], address[1])
                proxy_url = urlsplit(proxy.url)
                credentials = base64.b64encode(f"{proxy_url.username}:{proxy_url.password}".encode())
                request = b"CONNECT 127.0.0.1:443 HTTP/1.1" + bytes([13, 10])
                request += b"Host: 127.0.0.1:443" + bytes([13, 10])
                request += b"Proxy-Authorization: Basic " + credentials + bytes([13, 10, 13, 10])
                writer.write(request)
                await writer.drain()
                response = await reader.readline()
                writer.close()
                await writer.wait_closed()
                self.assertIn(b"403", response)
            finally:
                await proxy.close()
        asyncio.run(check())
    def test_real_mcp_client_discovers_hosted_tools_over_asgi(self):
        async def check():
            with patch.dict(os.environ, {"MCP_PUBLIC_URL": "https://mcp.example.test/mcp", "MCP_OAUTH_ISSUER": "https://tenant.example.test/", "MCP_OAUTH_ALLOWED_CLIENT_IDS": "test-client"}):
                from zammad_admin_mcp.hosted.app import create_app
                app = create_app()
            async def verify(self, token):
                return AccessToken(token=token, client_id="test-client", scopes=["mcp:read"], subject="synthetic", claims={"issuer": "https://tenant.example.test/", "subject": "synthetic", "tenant_id": "test"}, resource="https://mcp.example.test/mcp")
            with patch.object(HostedTokenVerifier, "verify_token", verify), patch("zammad_admin_mcp.hosted.repository.open_pool", new=AsyncMock()), patch("zammad_admin_mcp.hosted.repository.pool.close", new=AsyncMock()):
                def client_factory(headers=None, timeout=None, auth=None):
                    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), headers=headers, timeout=timeout, auth=auth)
                async with app.router.lifespan_context(app):
                    async with streamable_http_client("https://mcp.example.test/mcp", headers={"Authorization": "Bearer synthetic"}, httpx_client_factory=client_factory) as (read_stream, write_stream, _):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            names = {tool.name for tool in tools.tools}
                            self.assertEqual(names, {"zammad_server_version", "zammad_list_groups", "zammad_prepare_group_note", "zammad_apply_group_note"})
            asyncio.run(check())
    def test_personal_token_digest_requires_external_pepper(self):
        with patch.dict(os.environ, {"MCP_TOKEN_PEPPER": "x" * 32}):
            first = token_digest("zammcp_synthetic")
            self.assertEqual(first, token_digest("zammcp_synthetic"))
            self.assertNotEqual(first, token_digest("zammcp_other"))
        with patch.dict(os.environ, {"MCP_TOKEN_PEPPER": "short"}):
            with self.assertRaises(RuntimeError):
                token_digest("zammcp_synthetic")

    def test_http_app_registers_hosted_tools(self):
        with patch.dict(os.environ, {"MCP_PUBLIC_URL": "https://mcp.example.test/mcp", "MCP_OAUTH_ISSUER": "https://tenant.example.test/", "MCP_OAUTH_ALLOWED_CLIENT_IDS": "test-client"}):
            from zammad_admin_mcp.hosted.app import create_app
            app = create_app()
            self.assertTrue(any(getattr(route, "path", "").endswith("/mcp") for route in app.routes))


if __name__ == "__main__":
    unittest.main()
