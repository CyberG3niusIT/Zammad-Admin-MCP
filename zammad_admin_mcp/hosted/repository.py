from __future__ import annotations

import os
import secrets
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool


SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (id text PRIMARY KEY, active boolean NOT NULL DEFAULT true);
CREATE TABLE IF NOT EXISTS identities (
 issuer text NOT NULL, subject text NOT NULL, tenant_id text NOT NULL REFERENCES tenants(id),
 active boolean NOT NULL DEFAULT true, PRIMARY KEY (issuer, subject),
 UNIQUE (tenant_id, issuer, subject));
CREATE TABLE IF NOT EXISTS connections (
 tenant_id text PRIMARY KEY REFERENCES tenants(id), api_root text NOT NULL,
 auth_mode text NOT NULL CHECK (auth_mode IN ('token','basic')),
 secret_nonce bytea NOT NULL, secret_ciphertext bytea NOT NULL,
 generation bigint NOT NULL DEFAULT 1, active boolean NOT NULL DEFAULT true, staging boolean NOT NULL DEFAULT false,
 write_lease_plan text,
 updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS personal_tokens (
 id text PRIMARY KEY, token_digest bytea NOT NULL UNIQUE, tenant_id text NOT NULL REFERENCES tenants(id),
 issuer text NOT NULL, subject text NOT NULL, name text NOT NULL, scopes text[] NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 FOREIGN KEY (issuer, subject) REFERENCES identities(issuer, subject));
CREATE TABLE IF NOT EXISTS change_plans (
 id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id), issuer text NOT NULL,
 subject text NOT NULL, connection_generation bigint NOT NULL, group_id bigint NOT NULL,
 old_note text, new_note text NOT NULL, fingerprint text NOT NULL,
 state text NOT NULL CHECK (state IN ('prepared','approved','executing','sending','succeeded','failed_before_send','unknown','canceled','expired')),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY (issuer, subject) REFERENCES identities(issuer, subject));
CREATE UNIQUE INDEX IF NOT EXISTS one_active_group_plan ON change_plans(tenant_id, group_id)
 WHERE state IN ('approved','executing','sending','unknown');
CREATE TABLE IF NOT EXISTS audit_events (
 id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), tenant_id text,
 issuer text, subject text, auth_method text, tool text NOT NULL, result text NOT NULL,
 correlation_id text NOT NULL);
"""


def _pepper() -> bytes:
    value = os.environ.get("MCP_TOKEN_PEPPER", "").encode()
    if len(value) < 32:
        raise RuntimeError("MCP_TOKEN_PEPPER must contain at least 32 bytes")
    return value


def token_digest(token: str) -> bytes:
    import hmac
    import hashlib

    return hmac.new(_pepper(), token.encode(), hashlib.sha256).digest()


def encrypt_secret(secret: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = os.environ.get("MCP_SECRET_ENCRYPTION_KEY", "")
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError as exc:
        raise RuntimeError("MCP_SECRET_ENCRYPTION_KEY must be a 32-byte hex value") from exc
    if len(key_bytes) != 32:
        raise RuntimeError("MCP_SECRET_ENCRYPTION_KEY must be a 32-byte hex value")
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key_bytes).encrypt(nonce, secret, associated_data)


def decrypt_secret(nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes.fromhex(os.environ["MCP_SECRET_ENCRYPTION_KEY"])
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


pool = AsyncConnectionPool(conninfo=os.environ.get("DATABASE_URL", ""), open=False, kwargs={"row_factory": dict_row})
egress_proxy_url: str | None = None


def set_egress_proxy(url: str | None) -> None:
    global egress_proxy_url
    egress_proxy_url = url


async def open_pool() -> None:
    if not pool.conninfo:
        raise RuntimeError("DATABASE_URL must be configured for hosted mode")
    await pool.open()
    try:
        async with pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")
                row = await cursor.fetchone()
                if not row or row["version"] != 3:
                    raise RuntimeError("Hosted database schema is not at version 3; run zammad-mcp-admin migrate")
    except Exception:
        await pool.close()
        raise


async def migrate() -> None:
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not migration_url:
        raise RuntimeError("MIGRATION_DATABASE_URL must use the separate schema-migration database role")
    migration_pool = AsyncConnectionPool(conninfo=migration_url, open=False, kwargs={"row_factory": dict_row})
    await migration_pool.open()
    try:
        async with migration_pool.connection() as connection:
            async with connection.transaction():
                async with connection.cursor() as cursor:
                    await cursor.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
                    await cursor.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")
                    row = await cursor.fetchone()
                    if not row:
                        await cursor.execute(SCHEMA)
                        await cursor.execute("INSERT INTO schema_migrations(version) VALUES (1)")
                        version = 1
                    else:
                        version = row["version"]
                    if version < 2:
                        await cursor.execute("ALTER TABLE connections ADD COLUMN IF NOT EXISTS write_lease_plan text")
                        await cursor.execute("INSERT INTO schema_migrations(version) VALUES (2)")
                        version = 2
                    if version < 3:
                        await cursor.execute("ALTER TABLE change_plans DROP CONSTRAINT IF EXISTS change_plans_state_check")
                        await cursor.execute("ALTER TABLE change_plans ADD CONSTRAINT change_plans_state_check CHECK (state IN ('prepared','approved','executing','sending','succeeded','failed_before_send','unknown','canceled','expired'))")
                        await cursor.execute("DROP INDEX IF EXISTS one_active_group_plan")
                        await cursor.execute("CREATE UNIQUE INDEX one_active_group_plan ON change_plans(tenant_id, group_id) WHERE state IN ('approved','executing','sending','unknown')")
                        await cursor.execute("INSERT INTO schema_migrations(version) VALUES (3)")
    finally:
        await migration_pool.close()


async def resolve_personal_token(token: str) -> dict | None:
    digest = token_digest(token)
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "SELECT p.*, i.active AS identity_active, t.active AS tenant_active "
                "FROM personal_tokens p JOIN identities i ON i.issuer=p.issuer AND i.subject=p.subject AND i.tenant_id=p.tenant_id "
                "JOIN tenants t ON t.id=p.tenant_id WHERE p.token_digest=%s",
                (digest,),
            )
            row = await cursor.fetchone()
    if not row or row["revoked_at"] or row["expires_at"] <= datetime.now(timezone.utc):
        return None
    if not row["identity_active"] or not row["tenant_active"]:
        return None
    return row


async def resolve_identity(issuer: str, subject: str) -> dict | None:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "SELECT i.issuer,i.subject,i.tenant_id,t.active AS tenant_active "
                "FROM identities i JOIN tenants t ON t.id=i.tenant_id "
                "WHERE i.issuer=%s AND i.subject=%s AND i.active", (issuer, subject),
            )
            row = await cursor.fetchone()
    return row if row and row["tenant_active"] else None


async def connection_for(tenant_id: str) -> tuple[int, object] | None:
    if not egress_proxy_url:
        raise RuntimeError("The restricted hosted egress proxy is not running")
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "SELECT api_root,auth_mode,secret_nonce,secret_ciphertext,generation,staging "
                "FROM connections WHERE tenant_id=%s AND active", (tenant_id,),
            )
            row = await cursor.fetchone()
    if not row:
        return None
    from zammad_admin_mcp.api_transport import ConnectionConfig

    secret = decrypt_secret(row["secret_nonce"], row["secret_ciphertext"], tenant_id.encode()).decode()
    if row["auth_mode"] == "token":
        config = ConnectionConfig(url=row["api_root"], token=secret, trust_env=False, proxy=egress_proxy_url)
    else:
        username, password = secret.split("\0", 1)
        config = ConnectionConfig(url=row["api_root"], username=username, password=password, trust_env=False, proxy=egress_proxy_url)
    return row["generation"], config, row["staging"]


def state_fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


async def create_plan(tenant_id: str, issuer: str, subject: str, generation: int, group_id: int, old_note: str | None, new_note: str) -> str:
    plan_id = secrets.token_urlsafe(32)
    fingerprint = state_fingerprint({"id": group_id, "note": old_note})
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "INSERT INTO change_plans (id,tenant_id,issuer,subject,connection_generation,group_id,old_note,new_note,fingerprint,state,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared',now()+interval '5 minutes')",
                (plan_id, tenant_id, issuer, subject, generation, group_id, old_note, new_note, fingerprint),
            )
    return plan_id


async def get_plan(plan_id: str, issuer: str, subject: str, tenant_id: str) -> dict | None:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "SELECT * FROM change_plans WHERE id=%s AND issuer=%s AND subject=%s AND tenant_id=%s",
                (plan_id, issuer, subject, tenant_id),
            )
            return await cursor.fetchone()


async def get_unknown_plan(plan_id: str) -> dict | None:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute("SELECT * FROM change_plans WHERE id=%s AND state IN ('unknown','executing','sending')", (plan_id,))
            return await cursor.fetchone()


@asynccontextmanager
async def serialize_plan(plan_id: str):
    async with pool.connection() as connection:
        acquired = False
        try:
            async with connection.cursor() as cursor:
                await cursor.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0)) AS locked", (plan_id,))
                acquired = (await cursor.fetchone())["locked"]
            if not acquired:
                raise RuntimeError("Another worker is processing this plan")
            await connection.commit()
            yield
        finally:
            if acquired:
                try:
                    async with connection.cursor() as cursor:
                        await cursor.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0)) AS unlocked", (plan_id,))
                        unlocked = (await cursor.fetchone())["unlocked"]
                    await connection.commit()
                    if not unlocked:
                        await connection.close()
                except Exception:
                    await connection.close()
                    raise


async def reconcile_unknown_plan(plan_id: str, state: str) -> bool:
    if state not in {"succeeded", "failed_before_send"}:
        raise ValueError("Invalid reconciliation state")
    async with pool.connection() as connection:
        async with connection.transaction():
            async with connection.cursor() as cursor:
                await cursor.execute("UPDATE change_plans SET state=%s WHERE id=%s AND state IN ('unknown','executing','sending') RETURNING tenant_id", (state, plan_id))
                row = await cursor.fetchone()
                if row:
                    await cursor.execute("UPDATE connections SET write_lease_plan=NULL WHERE tenant_id=%s AND write_lease_plan=%s", (row["tenant_id"], plan_id))
                return row is not None


async def begin_audit(tenant_id: str | None, issuer: str | None, subject: str | None, auth_method: str | None, tool: str) -> int:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "INSERT INTO audit_events (tenant_id,issuer,subject,auth_method,tool,result,correlation_id) "
                "VALUES (%s,%s,%s,%s,%s,'started',%s) RETURNING id",
                (tenant_id, issuer, subject, auth_method, tool, secrets.token_hex(16)),
            )
            row = await cursor.fetchone()
            return row["id"]


async def finish_audit(event_id: int, result: str) -> None:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute("UPDATE audit_events SET result=%s WHERE id=%s AND result='started'", (result, event_id))


async def record_operator_audit(tool: str, tenant_id: str | None, issuer: str | None, subject: str | None) -> None:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "INSERT INTO audit_events (tenant_id,issuer,subject,auth_method,tool,result,correlation_id) "
                "VALUES (%s,%s,%s,'operator-cli',%s,'success',%s)",
                (tenant_id, issuer, subject, tool, secrets.token_hex(16)),
            )


async def approve_plan(plan_id: str, issuer: str, subject: str, tenant_id: str) -> bool:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute(
                "UPDATE change_plans SET state='approved' WHERE id=%s AND issuer=%s AND subject=%s "
                "AND tenant_id=%s AND state='prepared' AND expires_at>now()",
                (plan_id, issuer, subject, tenant_id),
            )
            return cursor.rowcount == 1


async def claim_plan(plan_id: str, issuer: str, subject: str, tenant_id: str) -> dict | None:
    async with pool.connection() as connection:
        async with connection.transaction():
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "UPDATE change_plans SET state='expired' WHERE id=%s AND issuer=%s AND subject=%s "
                    "AND tenant_id=%s AND state IN ('prepared','approved') AND expires_at<=now()",
                    (plan_id, issuer, subject, tenant_id),
                )
                await cursor.execute(
                    "UPDATE connections c SET write_lease_plan=p.id FROM change_plans p "
                    "WHERE p.id=%s AND p.tenant_id=c.tenant_id AND p.connection_generation=c.generation "
                    "AND c.active AND c.staging AND c.write_lease_plan IS NULL "
                    "AND p.issuer=%s AND p.subject=%s AND p.tenant_id=%s "
                    "AND p.state='approved' AND p.expires_at>now()",
                    (plan_id, issuer, subject, tenant_id),
                )
                if cursor.rowcount != 1:
                    return None
                await cursor.execute(
                    "UPDATE change_plans SET state='executing' WHERE id=%s AND issuer=%s AND subject=%s "
                    "AND tenant_id=%s AND state='approved' AND expires_at>now() RETURNING *",
                    (plan_id, issuer, subject, tenant_id),
                )
                plan = await cursor.fetchone()
                if not plan:
                    await cursor.execute("UPDATE connections SET write_lease_plan=NULL WHERE tenant_id=%s AND write_lease_plan=%s", (tenant_id, plan_id))
                return plan


async def finish_plan(plan_id: str, state: str) -> None:
    async with pool.connection() as connection:
        async with connection.transaction():
            async with connection.cursor() as cursor:
                await cursor.execute("UPDATE change_plans SET state=%s WHERE id=%s AND state IN ('executing','sending') RETURNING tenant_id", (state, plan_id))
                row = await cursor.fetchone()
                if row and state != "unknown":
                    await cursor.execute("UPDATE connections SET write_lease_plan=NULL WHERE tenant_id=%s AND write_lease_plan=%s", (row["tenant_id"], plan_id))


async def mark_plan_sending(plan_id: str) -> bool:
    async with pool.connection() as connection:
        async with connection.cursor() as cursor:
            await cursor.execute("UPDATE change_plans SET state='sending' WHERE id=%s AND state='executing'", (plan_id,))
            return cursor.rowcount == 1
