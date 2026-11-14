"""Synthetic alpha regressions: no network, production data, or credentials."""
import asyncio
import base64
import json
import os
import time
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from zammad_admin_mcp import api_transport as transport, security, server


class SecurityTests(unittest.TestCase):
    def test_nested_secrets_redacted(self):
        raw = {"password": "synthetic-pass", "nested": [{"apiKey": "synthetic-key", "name": "visible"}]}
        result = security._scrub(raw)
        self.assertNotIn("synthetic-pass", json.dumps(result))
        self.assertNotIn("synthetic-key", json.dumps(result))
        self.assertEqual(result["nested"][0]["name"], "visible")

    def test_inline_secret_rejected(self):
        with self.assertRaises(ValueError):
            security._materialize_secret_values({"password": "synthetic-pass"})

    def test_env_secret_only_materialized_for_secret_fields(self):
        with patch.dict(os.environ, {"MCP_SECRET_TEST": "synthetic-pass"}):
            resolved, preview = security._materialize_secret_values({"password": {"$secret_env": "MCP_SECRET_TEST"}})
            self.assertEqual(resolved["password"], "synthetic-pass")
            self.assertNotIn("synthetic-pass", json.dumps(preview))
            with self.assertRaises(ValueError):
                security._materialize_secret_values({"name": {"$secret_env": "MCP_SECRET_TEST"}})

    def test_exact_secret_echo_redacted(self):
        self.assertEqual(security._redact_exact_secrets({"message": "echo synthetic-pass"}, ["synthetic-pass"]), {"message": "echo [REDACTED]"})

    def test_sensitive_settings_value_redacted(self):
        result = security._project_settings({"name": "auth_client_secret", "state_current": {"value": "synthetic-pass"}})
        self.assertNotIn("synthetic-pass", json.dumps(result))

    def test_ids_reject_bool_zero_negative_and_string(self):
        for value in (True, 0, -1, "1", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                server._validate_id(value)

    def test_unknown_resource_rejected(self):
        with self.assertRaises(ValueError):
            server._resource("../../users")


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env = patch.dict(os.environ, {"ZAMMAD_URL": "https://zammad.invalid", "ZAMMAD_HTTP_TOKEN": "synthetic-token"}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    async def call(self, handler, **kwargs):
        original = httpx.AsyncClient
        def factory(**options):
            return original(**options, transport=httpx.MockTransport(handler))
        with patch.object(transport.httpx, "AsyncClient", side_effect=factory):
            return await transport.request("GET", "/version", **kwargs)

    async def test_request_path_and_auth(self):
        def handler(request):
            self.assertEqual(str(request.url), "https://zammad.invalid/api/v1/version")
            self.assertEqual(request.headers["Authorization"], "Token token=synthetic-token")
            return httpx.Response(200, json={"version": "synthetic"})
        self.assertEqual(await self.call(handler), {"version": "synthetic"})

    async def test_status_errors_hide_response_body(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status), self.assertRaises(RuntimeError) as caught:
                await self.call(lambda request: httpx.Response(status, text="synthetic-sensitive-body"))
            self.assertNotIn("synthetic-sensitive-body", str(caught.exception))

    async def test_redirect_rejected(self):
        with self.assertRaises(RuntimeError):
            await self.call(lambda request: httpx.Response(302, headers={"location": "https://other.invalid"}))

    async def test_non_json_rejected(self):
        with self.assertRaises(RuntimeError):
            await self.call(lambda request: httpx.Response(200, text="not json"))

    async def test_response_size_limit(self):
        with self.assertRaisesRegex(RuntimeError, "size limit"):
            await self.call(lambda request: httpx.Response(200, content=b'"too long"'), max_response_bytes=3)

    async def test_timeout_propagates(self):
        def handler(request):
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        with self.assertRaises(httpx.ReadTimeout):
            await self.call(handler)

    async def test_invalid_configuration(self):
        for url in ("http://remote.invalid", "https://user:pass@zammad.invalid", "https://zammad.invalid?token=x", "not-a-url"):
            with self.subTest(url=url), patch.dict(os.environ, {"ZAMMAD_URL": url}), self.assertRaises(ValueError):
                transport._api_root()

    async def test_missing_credentials(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            transport._api_root()

    async def test_basic_headers(self):
        with patch.dict(os.environ, {"ZAMMAD_HTTP_USERNAME": "synthetic-user", "ZAMMAD_HTTP_PASSWORD": "synthetic-password"}, clear=True):
            authorization = transport._headers()["Authorization"]
            self.assertTrue(authorization.startswith("Basic "))
            self.assertEqual(base64.b64decode(authorization[6:]).decode("utf-8"), "synthetic-user:synthetic-password")

    async def test_token_takes_precedence_over_basic(self):
        with patch.dict(os.environ, {"ZAMMAD_HTTP_USERNAME": "synthetic-user", "ZAMMAD_HTTP_PASSWORD": "synthetic-password"}):
            self.assertEqual(transport._headers()["Authorization"], "Token token=synthetic-token")

    async def test_incomplete_basic_credentials_rejected(self):
        for credentials in ({"ZAMMAD_HTTP_USERNAME": "synthetic-user"}, {"ZAMMAD_HTTP_PASSWORD": "synthetic-password"}, {"ZAMMAD_HTTP_USERNAME": " ", "ZAMMAD_HTTP_PASSWORD": "synthetic-password"}):
            with self.subTest(credentials=list(credentials)), patch.dict(os.environ, credentials, clear=True), self.assertRaises(ValueError):
                transport._headers()

    async def test_basic_username_colon_rejected(self):
        with patch.dict(os.environ, {"ZAMMAD_HTTP_USERNAME": "synthetic:user", "ZAMMAD_HTTP_PASSWORD": "synthetic-password"}, clear=True), self.assertRaises(ValueError):
            transport._headers()

    async def test_basic_password_whitespace_preserved(self):
        with patch.dict(os.environ, {"ZAMMAD_HTTP_USERNAME": "synthetic-user", "ZAMMAD_HTTP_PASSWORD": " synthetic-password "}, clear=True):
            authorization = transport._headers()["Authorization"]
            self.assertEqual(base64.b64decode(authorization[6:]).decode("utf-8"), "synthetic-user: synthetic-password ")

    async def test_basic_request_path_and_header(self):
        def handler(request):
            self.assertEqual(str(request.url), "https://zammad.invalid/api/v1/version")
            self.assertEqual(base64.b64decode(request.headers["Authorization"][6:]).decode("utf-8"), "synthetic-user:synthetic-password")
            return httpx.Response(200, json={"version": "synthetic"})
        with patch.dict(os.environ, {"ZAMMAD_URL": "https://zammad.invalid", "ZAMMAD_HTTP_USERNAME": "synthetic-user", "ZAMMAD_HTTP_PASSWORD": "synthetic-password"}, clear=True):
            self.assertEqual(await self.call(handler), {"version": "synthetic"})


class PlanTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        server._PLANS.clear()
        server._PLAN_LOCK = asyncio.Lock()
        server._WRITE_LOCK = asyncio.Lock()
        self.request = AsyncMock(return_value={"id": 1, "name": "new"})
        self.snapshot = AsyncMock(return_value={"id": 1, "name": "old"})
        self.patches = [patch.object(server, "_request", self.request), patch.object(server, "_snapshot", self.snapshot)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(server._PLANS.clear)

    def plan(self, **overrides):
        result = {"resource": "groups", "operation": "update", "object_id": 1, "data": {"name": "new"}, "before": {"id": 1, "name": "old"}, "fingerprint": server._snapshot_fingerprint("groups", {"id": 1, "name": "old"}), "expires_at": time.time() + 300, "high_impact": False, "dependencies": []}
        result.update(overrides)
        server._PLANS["synthetic-plan"] = result

    async def test_missing_invalid_and_used_plan_rejected(self):
        for plan_id in ("", "missing", None):
            with self.subTest(plan_id=plan_id), self.assertRaises(ValueError):
                await server.zammad_apply_admin_change(plan_id)
        self.request.assert_not_awaited()

    async def test_expired_plan_cannot_write(self):
        self.plan(expires_at=time.time() - 1)
        with self.assertRaises(ValueError):
            await server.zammad_apply_admin_change("synthetic-plan")
        self.request.assert_not_awaited()
        self.snapshot.assert_not_awaited()

    async def test_high_impact_requires_acknowledgement(self):
        self.plan(high_impact=True)
        with self.assertRaises(ValueError):
            await server.zammad_apply_admin_change("synthetic-plan")
        self.request.assert_not_awaited()

    async def test_stale_resource_cannot_write(self):
        self.plan()
        self.snapshot.return_value = {"id": 1, "name": "edited elsewhere"}
        with self.assertRaisesRegex(RuntimeError, "changed after preview"):
            await server.zammad_apply_admin_change("synthetic-plan")
        self.request.assert_not_awaited()

    async def test_successful_plan_cannot_replay(self):
        self.plan()
        await server.zammad_apply_admin_change("synthetic-plan")
        self.request.assert_awaited_once_with("PUT", "/groups/1", {"name": "new"})
        with self.assertRaises(ValueError):
            await server.zammad_apply_admin_change("synthetic-plan")
        self.assertEqual(self.request.await_count, 1)

    async def test_plan_expiring_while_queued_cannot_write(self):
        self.plan(expires_at=1001)
        await server._WRITE_LOCK.acquire()
        with patch.object(server.time, "time", return_value=1000) as clock:
            task = asyncio.create_task(server.zammad_apply_admin_change("synthetic-plan"))
            await asyncio.sleep(0)
            clock.return_value = 1002
            server._WRITE_LOCK.release()
            with self.assertRaises((ValueError, RuntimeError)):
                await task
        self.request.assert_not_awaited()

    async def test_plan_expiring_during_snapshot_cannot_write(self):
        self.plan(expires_at=1001)
        with patch.object(server.time, "time", return_value=1000) as clock:
            async def delayed_snapshot(*args):
                clock.return_value = 1002
                return {"id": 1, "name": "old"}
            self.snapshot.side_effect = delayed_snapshot
            with self.assertRaises((ValueError, RuntimeError)):
                await server.zammad_apply_admin_change("synthetic-plan")
        self.snapshot.assert_awaited_once()
        self.request.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
