from __future__ import annotations

from functools import wraps
import logging
from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import Context, FastMCP

from zammad_admin_mcp.api_transport import ConnectionConfig, request

from . import repository

logger = logging.getLogger(__name__)


def _audited(name: str):
    def decorate(function):
        @wraps(function)
        async def invoke(ctx: Context, *args, **kwargs):
            auth = ctx.request_context.request.auth
            claims = auth.claims if auth else {}
            event_id = await repository.begin_audit(
                claims.get("tenant_id"), claims.get("issuer"), claims.get("subject"),
                claims.get("auth_method"), name,
            )
            try:
                result = await function(ctx, *args, **kwargs)
            except Exception as exc:
                try:
                    await repository.finish_audit(event_id, f"error:{type(exc).__name__}")
                except Exception:
                    logger.exception("Unable to finalize MCP audit event %s", event_id)
                raise
            try:
                await repository.finish_audit(event_id, "success")
            except Exception:
                logger.exception("Unable to finalize MCP audit event %s", event_id)
            return result
        return invoke
    return decorate


def _serialized_plan(function):
    @wraps(function)
    async def invoke(ctx: Context, plan_id: str):
        async with repository.serialize_plan(plan_id):
            return await function(ctx, plan_id)
    return invoke


def _principal(ctx: Context, scope: str) -> dict[str, str]:
    auth = ctx.request_context.request.auth
    if auth is None or scope not in auth.scopes or not auth.claims:
        raise PermissionError("MCP authentication and the required permission are required")
    issuer = auth.claims.get("issuer")
    subject = auth.claims.get("subject")
    tenant_id = auth.claims.get("tenant_id")
    if not all(isinstance(value, str) and value for value in (issuer, subject, tenant_id)):
        raise PermissionError("The authenticated identity is not assigned to an active customer")
    return {"issuer": issuer, "subject": subject, "tenant_id": tenant_id, "auth_method": str(auth.claims.get("auth_method", "unknown"))}


def register_tools(server: FastMCP) -> None:
    @server.tool()
    @_audited("zammad_server_version")
    async def zammad_server_version(ctx: Context) -> dict[str, Any]:
        """Return the version of the Zammad instance assigned to the authenticated customer."""
        principal = _principal(ctx, "mcp:read")
        resolved = await repository.connection_for(principal["tenant_id"])
        if not resolved:
            raise RuntimeError("No active Zammad connection is configured for this customer")
        _, config, _ = resolved
        return await request("GET", "/version", connection=config, max_response_bytes=256 * 1024)

    @server.tool()
    @_audited("zammad_list_groups")
    async def zammad_list_groups(ctx: Context, page: int = 1, per_page: int = 50) -> list[dict[str, Any]]:
        """List a bounded page of Zammad groups, returning only ID, name and active status."""
        principal = _principal(ctx, "mcp:read")
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ValueError("page must be a positive integer")
        if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= 50:
            raise ValueError("per_page must be between 1 and 50")
        resolved = await repository.connection_for(principal["tenant_id"])
        if not resolved:
            raise RuntimeError("No active Zammad connection is configured for this customer")
        _, config, _ = resolved
        groups = await request("GET", "/groups", params={"page": page, "per_page": per_page}, max_response_bytes=2 * 1024 * 1024, connection=config)
        if not isinstance(groups, list):
            raise RuntimeError("Zammad returned an unsupported group collection")
        if len(groups) > per_page:
            raise RuntimeError("Zammad ignored the requested page size; refusing to return ambiguous results")
        projected = []
        for group in groups:
            if (
                not isinstance(group, dict)
                or isinstance(group.get("id"), bool) or not isinstance(group.get("id"), int)
                or not isinstance(group.get("name"), str)
                or not isinstance(group.get("active"), bool)
            ):
                raise RuntimeError("Zammad returned an unsupported group record")
            projected.append({key: group[key] for key in ("id", "name", "active")})
        return projected

    @server.tool()
    @_audited("zammad_prepare_group_note")
    async def zammad_prepare_group_note(ctx: Context, group_id: int, note: str) -> dict[str, Any]:
        """Prepare a five-minute preview for changing only a test group's note."""
        principal = _principal(ctx, "mcp:write:group-note")
        if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id < 1:
            raise ValueError("group_id must be a positive integer")
        if not isinstance(note, str) or len(note) > 5000:
            raise ValueError("note must be a string of at most 5000 characters")
        resolved = await repository.connection_for(principal["tenant_id"])
        if not resolved:
            raise RuntimeError("No active Zammad connection is configured for this customer")
        generation, config, staging = resolved
        if not staging:
            raise PermissionError("Group note changes are enabled only for explicitly marked staging connections")
        before = await request("GET", f"/groups/{group_id}", connection=config, max_response_bytes=512 * 1024)
        if not isinstance(before, dict) or before.get("id") != group_id or not isinstance(before.get("note"), (str, type(None))):
            raise RuntimeError("Zammad returned an unsupported group record")
        plan_id = await repository.create_plan(principal["tenant_id"], principal["issuer"], principal["subject"], generation, group_id, before["note"], note)
        return {"plan_id": plan_id, "group_id": group_id, "old_note": before["note"], "new_note": note, "expires_in_seconds": 300, "approval": "Confirm this exact change with zammad-mcp-admin plan approve"}

    @server.tool()
    @_audited("zammad_apply_group_note")
    @_serialized_plan
    async def zammad_apply_group_note(ctx: Context, plan_id: str) -> dict[str, Any]:
        """Apply a group-note preview after the same authenticated person approved it in the CLI."""
        principal = _principal(ctx, "mcp:write:group-note")
        plan = await repository.claim_plan(plan_id, principal["issuer"], principal["subject"], principal["tenant_id"])
        if not plan:
            raise ValueError("Plan is unknown, expired, not approved, or already used")
        try:
            resolved = await repository.connection_for(principal["tenant_id"])
        except Exception:
            await repository.finish_plan(plan_id, "failed_before_send")
            raise
        if not resolved:
            await repository.finish_plan(plan_id, "failed_before_send")
            raise RuntimeError("No active Zammad connection is configured for this customer")
        generation, config, staging = resolved
        if not staging or generation != plan["connection_generation"]:
            await repository.finish_plan(plan_id, "failed_before_send")
            raise RuntimeError("The staging connection changed after preview")
        try:
            before = await request("GET", f"/groups/{plan['group_id']}", connection=config, max_response_bytes=512 * 1024)
            if not isinstance(before, dict) or repository.state_fingerprint({"id": plan["group_id"], "note": before.get("note")}) != plan["fingerprint"]:
                await repository.finish_plan(plan_id, "failed_before_send")
                raise RuntimeError("The group note changed after preview; prepare a new plan")
        except Exception as exc:
            await repository.finish_plan(plan_id, "failed_before_send")
            if isinstance(exc, RuntimeError):
                raise
            raise RuntimeError("Unable to verify the current group before sending the change") from None
        if not await repository.mark_plan_sending(plan_id):
            await repository.finish_plan(plan_id, "failed_before_send")
            raise RuntimeError("The plan could not be reserved for sending")
        try:
            await request("PUT", f"/groups/{plan['group_id']}", payload={"note": plan["new_note"]}, connection=config, max_response_bytes=512 * 1024)
            after = await request("GET", f"/groups/{plan['group_id']}", connection=config, max_response_bytes=512 * 1024)
        except Exception:
            await repository.finish_plan(plan_id, "unknown")
            raise RuntimeError("Zammad write outcome is uncertain. Reconcile the current group before retrying") from None
        if not isinstance(after, dict) or after.get("note") != plan["new_note"]:
            await repository.finish_plan(plan_id, "unknown")
            raise RuntimeError("Zammad did not confirm the requested note. Reconcile before retrying")
        await repository.finish_plan(plan_id, "succeeded")
        return {"group_id": plan["group_id"], "note_updated": True, "group": {key: after[key] for key in ("id", "name", "active", "note") if key in after}}
