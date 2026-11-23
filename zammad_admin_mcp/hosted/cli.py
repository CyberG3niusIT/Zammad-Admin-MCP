from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import secrets
import sys
import httpx
import uuid
from datetime import datetime, timedelta, timezone

from zammad_admin_mcp.api_transport import ConnectionConfig, _api_root, request

from . import repository
from .egress import RestrictedEgressProxy


async def _reconcile(plan_id: str, confirm_not_applied: bool) -> tuple[str, str, str, str]:
    async with repository.serialize_plan(plan_id):
        plan = await repository.get_unknown_plan(plan_id)
        if not plan:
            raise ValueError("No unresolved plan exists for this ID, or its worker is still active")
        proxy = RestrictedEgressProxy()
        await proxy.start()
        repository.set_egress_proxy(proxy.url)
        try:
            resolved = await repository.connection_for(plan["tenant_id"])
            if not resolved:
                raise RuntimeError("The connection needed to reconcile this plan is unavailable")
            _, config, _ = resolved
            current = await request("GET", f"/groups/{plan['group_id']}", connection=config, max_response_bytes=512 * 1024)
        finally:
            repository.set_egress_proxy(None)
            await proxy.close()
        if not isinstance(current, dict) or current.get("id") != plan["group_id"]:
            raise RuntimeError("Zammad returned an unsupported group record; plan remains locked")
        if current.get("note") == plan["new_note"]:
            outcome = "succeeded"
        elif current.get("note") == plan["old_note"]:
            if plan["state"] in {"sending", "unknown"} and not confirm_not_applied:
                raise RuntimeError("The write may still complete after a timeout; inspect Zammad logs and repeat with --confirm-not-applied only after confirming it did not apply")
            outcome = "failed_before_send"
        else:
            raise RuntimeError("The note differs from both preview values; plan remains locked for manual investigation")
        if not await repository.reconcile_unknown_plan(plan_id, outcome):
            raise RuntimeError("Plan state changed during reconciliation")
        return outcome, plan["tenant_id"], plan["issuer"], plan["subject"]


async def _run(args: argparse.Namespace) -> None:
    if args.command == "migrate":
        await repository.migrate()
        print("Hosted database schema is at version 3")
        return
    await repository.open_pool()
    audit_tenant = getattr(args, "tenant_id", None)
    audit_issuer = getattr(args, "issuer", None)
    audit_subject = getattr(args, "subject", None)
    try:
        if args.command == "tenant":
            async with repository.pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute("INSERT INTO tenants (id) VALUES (%s) ON CONFLICT (id) DO NOTHING", (args.tenant_id,))
            print(f"Tenant ready: {args.tenant_id}")
        elif args.command == "member":
            async with repository.pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute("SELECT 1 FROM tenants WHERE id=%s AND active", (args.tenant_id,))
                    if not await cursor.fetchone():
                        raise ValueError("Tenant does not exist or is disabled")
                    await cursor.execute(
                        "INSERT INTO identities (issuer,subject,tenant_id) VALUES (%s,%s,%s) "
                        "ON CONFLICT (issuer,subject) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,active=true",
                        (args.issuer, args.subject, args.tenant_id),
                    )
            print("Identity assigned")
        elif args.command == "connection":
            api_root = _api_root(args.url)
            async with repository.pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute("SELECT generation FROM connections WHERE tenant_id=%s", (args.tenant_id,))
                    current_connection = await cursor.fetchone()
                    expected_generation = current_connection["generation"] if current_connection else 0
            if args.auth == "token":
                secret = getpass.getpass("Zammad API token: ")
                encrypted_secret = secret.encode()
            else:
                username = input("Zammad username: ").strip()
                password = getpass.getpass("Zammad password: ")
                encrypted_secret = f"{username}\0{password}".encode()
            proxy = RestrictedEgressProxy()
            await proxy.start()
            try:
                if args.auth == "token":
                    config = ConnectionConfig(url=api_root, token=secret, trust_env=False, proxy=proxy.url)
                else:
                    config = ConnectionConfig(url=api_root, username=username, password=password, trust_env=False, proxy=proxy.url)
                await request("GET", "/users/me", connection=config, max_response_bytes=1024 * 1024)
                await request("GET", "/groups", connection=config, params={"page": 1, "per_page": 1}, max_response_bytes=1024 * 1024)
            finally:
                await proxy.close()
            nonce, ciphertext = repository.encrypt_secret(encrypted_secret, args.tenant_id.encode())
            async with repository.pool.connection() as connection:
                async with connection.transaction():
                    async with connection.cursor() as cursor:
                        await cursor.execute(
                            "INSERT INTO connections (tenant_id,api_root,auth_mode,secret_nonce,secret_ciphertext,staging) "
                            "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (tenant_id) DO UPDATE SET "
                            "api_root=EXCLUDED.api_root,auth_mode=EXCLUDED.auth_mode,secret_nonce=EXCLUDED.secret_nonce,"
                            "secret_ciphertext=EXCLUDED.secret_ciphertext,staging=EXCLUDED.staging,generation=connections.generation+1,active=true,updated_at=now() "
                            "WHERE connections.generation=%s AND connections.write_lease_plan IS NULL",
                            (args.tenant_id, api_root, args.auth, nonce, ciphertext, args.staging, expected_generation),
                        )
                        if cursor.rowcount != 1:
                            raise RuntimeError("Connection has an unresolved group-note write; reconcile the plan before rotating credentials")
            print("Staging connection validated and activated" if args.staging else "Connection validated and activated")
        elif args.command == "token":
            value = "zammcp_" + secrets.token_urlsafe(32)
            scopes = args.scopes.split(",")
            expires = datetime.now(timezone.utc) + timedelta(days=args.days)
            token_id = str(uuid.uuid4())
            async with repository.pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute(
                        "INSERT INTO personal_tokens (id,token_digest,tenant_id,issuer,subject,name,scopes,expires_at) "
                        "SELECT %s,%s,i.tenant_id,%s,%s,%s,%s,%s FROM identities i JOIN tenants t ON t.id=i.tenant_id "
                        "WHERE i.issuer=%s AND i.subject=%s AND i.tenant_id=%s AND i.active AND t.active",
                        (token_id, repository.token_digest(value), args.issuer, args.subject, args.name, scopes, expires,
                         args.issuer, args.subject, args.tenant_id),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("Active identity not found in tenant")
            print("Copy this token now. It will not be shown again:\n" + value)
        elif args.command == "token-revoke":
            async with repository.pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute("UPDATE personal_tokens SET revoked_at=now() WHERE id=%s RETURNING tenant_id,issuer,subject", (args.token_id,))
                    revoked = await cursor.fetchone()
                    if not revoked:
                        raise ValueError("Token not found")
                    audit_tenant, audit_issuer, audit_subject = revoked["tenant_id"], revoked["issuer"], revoked["subject"]
            print("Token revoked")
        elif args.command == "plan" and args.action == "reconcile":
            outcome, audit_tenant, audit_issuer, audit_subject = await _reconcile(args.plan_id, args.confirm_not_applied)
            print(f"Plan reconciled as {outcome} after verifying the live group")
        elif args.command == "plan" and args.action == "approve":
            client_id = os.environ.get("MCP_OAUTH_CLIENT_ID", "")
            if not client_id:
                raise RuntimeError("MCP_OAUTH_CLIENT_ID must be configured for CLI device authorization")
            issuer_url = args.issuer_url.rstrip("/")
            async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
                device = await client.post(issuer_url + "/oauth/device/code", data={"client_id": client_id, "audience": args.resource_url, "scope": "openid profile mcp:write:group-note"})
                device.raise_for_status()
                challenge = device.json()
                print(f"Open {challenge['verification_uri']} and enter code {challenge['user_code']}")
                deadline = asyncio.get_running_loop().time() + int(challenge.get("expires_in", 600))
                interval = max(1, int(challenge.get("interval", 5)))
                token = None
                while asyncio.get_running_loop().time() < deadline:
                    await asyncio.sleep(interval)
                    response = await client.post(issuer_url + "/oauth/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": challenge["device_code"], "client_id": client_id})
                    if response.status_code == 200:
                        token = response.json().get("access_token")
                        break
                    error = response.json().get("error")
                    if error == "slow_down":
                        interval += 5
                    elif error != "authorization_pending":
                        raise RuntimeError("OAuth device authorization was denied or expired")
                if not token:
                    raise TimeoutError("OAuth device authorization expired")
            from .auth import HostedTokenVerifier
            verifier = HostedTokenVerifier(args.resource_url, issuer_url, {client_id})
            access = await verifier.verify_token(token)
            if not access or "mcp:write:group-note" not in access.scopes:
                raise PermissionError("An active OAuth identity with group-note write permission is required")
            issuer = access.claims["issuer"]
            subject = access.claims["subject"]
            plan = await repository.get_plan(args.plan_id, issuer, subject, access.claims["tenant_id"])
            if not plan:
                raise ValueError("Plan does not belong to this identity")
            if not await repository.approve_plan(args.plan_id, issuer, subject, plan["tenant_id"]):
                raise ValueError("Plan is expired or no longer awaiting approval")
            audit_tenant, audit_issuer, audit_subject = plan["tenant_id"], issuer, subject
            print(f"Approved plan for group {plan['group_id']}: {plan['old_note']!r} -> {plan['new_note']!r}")
        await repository.record_operator_audit(args.command if args.command != "plan" else f"plan:{args.action}", audit_tenant, audit_issuer, audit_subject)
    finally:
        await repository.pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="zammad-mcp-admin")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="apply versioned hosted database migrations")
    tenant = commands.add_parser("tenant")
    tenant.add_argument("tenant_id")
    member = commands.add_parser("member")
    member.add_argument("tenant_id")
    member.add_argument("issuer")
    member.add_argument("subject")
    connection = commands.add_parser("connection")
    connection.add_argument("tenant_id")
    connection.add_argument("url")
    connection.add_argument("--auth", choices=("token", "basic"), default="token")
    connection.add_argument("--staging", action="store_true", help="mark this connection as an isolated staging instance")
    token = commands.add_parser("token")
    token.add_argument("tenant_id")
    token.add_argument("issuer")
    token.add_argument("subject")
    token.add_argument("name")
    token.add_argument("--days", type=int, default=30)
    token.add_argument("--scopes", default="mcp:read")
    revoke = commands.add_parser("token-revoke")
    revoke.add_argument("token_id")
    plan = commands.add_parser("plan")
    plan_commands = plan.add_subparsers(dest="action", required=True)
    reconcile = plan_commands.add_parser("reconcile")
    reconcile.add_argument("plan_id")
    reconcile.add_argument("--confirm-not-applied", action="store_true", help="confirm after reviewing Zammad logs that a timed-out write will not still apply")
    approve = plan_commands.add_parser("approve")
    approve.add_argument("plan_id")
    approve.add_argument("--resource-url", required=True)
    approve.add_argument("--issuer-url", default=None)
    args = parser.parse_args()
    if args.command == "token" and not 1 <= args.days <= 365:
        parser.error("--days must be between 1 and 365")
    if args.command == "token" and not set(args.scopes.split(",")) <= {"mcp:read", "mcp:write:group-note"}:
        parser.error("--scopes can contain only mcp:read and mcp:write:group-note")
    if args.command == "plan" and args.issuer_url is None:
        args.issuer_url = os.environ.get("MCP_OAUTH_ISSUER", "")
    if args.command == "plan" and args.action == "approve":
        if not args.issuer_url:
            parser.error("plan approval requires MCP_OAUTH_ISSUER or --issuer-url")
        from .egress import validate_issuer_url, validate_public_mcp_url
        try:
            args.resource_url = validate_public_mcp_url(args.resource_url)
            args.issuer_url = validate_issuer_url(args.issuer_url)
        except ValueError as exc:
            parser.error(str(exc))
    try:
        asyncio.run(_run(args))
    except Exception as exc:
        print(f"Operation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
