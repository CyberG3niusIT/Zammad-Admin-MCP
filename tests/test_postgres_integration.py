from __future__ import annotations

import asyncio
import os
import unittest
import uuid

from zammad_admin_mcp.hosted import repository


@unittest.skipUnless(os.environ.get("DATABASE_URL") and os.environ.get("MIGRATION_DATABASE_URL"), "temporary PostgreSQL is required")
class HostedPostgresTests(unittest.IsolatedAsyncioTestCase):
    loop_factory = asyncio.SelectorEventLoop

    async def asyncSetUp(self):
        await repository.migrate()
        await repository.open_pool()
        self.tenant = "test-" + uuid.uuid4().hex
        self.issuer = "https://issuer.example.test/"
        self.subject = uuid.uuid4().hex
        async with repository.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("INSERT INTO tenants(id) VALUES (%s)", (self.tenant,))
                await cursor.execute("INSERT INTO identities(issuer,subject,tenant_id) VALUES (%s,%s,%s)", (self.issuer, self.subject, self.tenant))
                await cursor.execute(
                    "INSERT INTO connections(tenant_id,api_root,auth_mode,secret_nonce,secret_ciphertext,staging) "
                    "VALUES (%s,'https://zammad.example.test/api/v1','token',%s,%s,true)",
                    (self.tenant, b"0" * 12, b"synthetic ciphertext"),
                )

    async def asyncTearDown(self):
        async with repository.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("DELETE FROM audit_events WHERE tenant_id=%s", (self.tenant,))
                await cursor.execute("DELETE FROM change_plans WHERE tenant_id=%s", (self.tenant,))
                await cursor.execute("DELETE FROM personal_tokens WHERE tenant_id=%s", (self.tenant,))
                await cursor.execute("DELETE FROM connections WHERE tenant_id=%s", (self.tenant,))
                await cursor.execute("DELETE FROM identities WHERE tenant_id=%s", (self.tenant,))
                await cursor.execute("DELETE FROM tenants WHERE id=%s", (self.tenant,))
        await repository.pool.close()

    async def test_migrations_and_plan_lease_recovery(self):
        async with repository.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("SELECT max(version) AS version FROM schema_migrations")
                self.assertEqual((await cursor.fetchone())["version"], 3)

        plan_id = await repository.create_plan(self.tenant, self.issuer, self.subject, 1, 13, "old", "new")
        self.assertTrue(await repository.approve_plan(plan_id, self.issuer, self.subject, self.tenant))
        async with repository.serialize_plan(plan_id):
            plan = await repository.claim_plan(plan_id, self.issuer, self.subject, self.tenant)
            self.assertEqual(plan["state"], "executing")
            self.assertTrue(await repository.mark_plan_sending(plan_id))
            with self.assertRaisesRegex(RuntimeError, "Another worker"):
                async with repository.serialize_plan(plan_id):
                    self.fail("second worker acquired an active plan lock")

        pending = await repository.get_unknown_plan(plan_id)
        self.assertEqual(pending["state"], "sending")
        self.assertTrue(await repository.reconcile_unknown_plan(plan_id, "failed_before_send"))
        async with repository.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("SELECT write_lease_plan FROM connections WHERE tenant_id=%s", (self.tenant,))
                self.assertIsNone((await cursor.fetchone())["write_lease_plan"])
        event_id = await repository.begin_audit(self.tenant, self.issuer, self.subject, "pat", "synthetic_tool")
        await repository.finish_audit(event_id, "success")
        async with repository.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("SELECT result,tool FROM audit_events WHERE id=%s", (event_id,))
                row = await cursor.fetchone()
        self.assertEqual(row, {"result": "success", "tool": "synthetic_tool"})


if __name__ == "__main__":
    unittest.main()
