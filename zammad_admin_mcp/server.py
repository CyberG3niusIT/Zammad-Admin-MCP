"""Zammad administrative MCP with allowlisted reads and staged writes."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from zammad_admin_mcp.api_transport import request as _send_api_request
from zammad_admin_mcp.security import _collect_secret_literals
from zammad_admin_mcp.security import _is_sensitive_setting_name
from zammad_admin_mcp.security import _materialize_secret_values
from zammad_admin_mcp.security import _project_settings
from zammad_admin_mcp.security import _redact_exact_secrets
from zammad_admin_mcp.security import _scrub
from zammad_admin_mcp.security import _store_generated_token
from zammad_admin_mcp.security import _validate_setting_secret_reference
from zammad_admin_mcp.security import _validate_token_create_payload
from zammad_admin_mcp.admin_schemas.chats import validate_payload as validate_chat_payload
from zammad_admin_mcp.admin_schemas.facebook_channels import validate_payload as validate_facebook_channel_payload
from zammad_admin_mcp.admin_schemas.external_credentials import materialize_payload as materialize_external_credentials
from zammad_admin_mcp.admin_schemas.external_credentials import validate_payload as validate_external_credentials_payload
from zammad_admin_mcp.admin_schemas.jobs import validate_payload as validate_job_payload
from zammad_admin_mcp.admin_schemas.ldap_actions import materialize_payload as materialize_ldap_action
from zammad_admin_mcp.admin_schemas.ldap_actions import retain_source_values as retain_ldap_action_values
from zammad_admin_mcp.admin_schemas.ldap_actions import validate_payload as validate_ldap_action_payload
from zammad_admin_mcp.admin_schemas.ldap_sources import materialize_payload as materialize_ldap_source
from zammad_admin_mcp.admin_schemas.ldap_sources import role_ids as ldap_role_ids
from zammad_admin_mcp.admin_schemas.ldap_sources import retain_existing_secret as retain_ldap_secret
from zammad_admin_mcp.admin_schemas.ldap_sources import validate_payload as validate_ldap_source_payload
from zammad_admin_mcp.admin_schemas.postmaster_filters import validate_payload as validate_postmaster_filter_payload
from zammad_admin_mcp.admin_schemas.public_links import validate_payload as validate_public_link_payload

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

@dataclass(frozen=True)
class Resource:
    path: str
    operations: frozenset[str] = frozenset({"create", "update", "delete"})
    risk: str = "Configuration change; inspect the preview before approval."
    high_impact: bool = False
    item: bool = True


_RESOURCES: dict[str, Resource] = {
    "groups": Resource("/groups", risk="Changes ticket routing and group access.", high_impact=True),
    "roles": Resource("/roles", risk="Changes user permissions and may remove administrative access.", high_impact=True),
    "calendars": Resource("/calendars", risk="Changes working hours used by SLAs.", high_impact=True),
    "slas": Resource("/slas", risk="Changes ticket escalation and response targets.", high_impact=True),
    "triggers": Resource("/triggers", risk="May send email or invoke webhooks for future ticket events.", high_impact=True),
    "ticket_states": Resource("/ticket_states", risk="Changes the ticket state model.", high_impact=True),
    "ticket_priorities": Resource("/ticket_priorities", risk="Changes the ticket priority model.", high_impact=True),
    "macros": Resource("/macros"),
    "overviews": Resource("/overviews"),
    "templates": Resource("/templates"),
    "text_modules": Resource("/text_modules"),
    "core_workflows": Resource("/core_workflows", risk="Changes fields and values presented in ticket forms.", high_impact=True),
    "signatures": Resource("/signatures", risk="Changes message signatures available to agents."),
    "sms_channels": Resource(
        "/channels_sms", operations=frozenset({"create", "update", "delete", "enable", "disable", "test"}),
        risk="Configures SMS delivery or inbound handling; test sends a real SMS and may incur provider charges.", high_impact=True,
    ),
    "telegram_channels": Resource(
        "/channels_telegram", operations=frozenset({"create", "update", "delete", "enable", "disable"}), item=False,
        risk="Creates or changes a Telegram bot integration and can set a webhook with Telegram.", high_impact=True,
    ),
    "whatsapp_channels": Resource(
        "/channels/admin/whatsapp", operations=frozenset({"create", "update", "delete", "enable", "disable", "preload"}), item=False,
        risk="Changes a WhatsApp Business integration or calls Meta to verify/preload phone numbers.", high_impact=True,
    ),
    "facebook_channels": Resource(
        "/channels_facebook", operations=frozenset({"update", "delete", "enable", "disable"}),
        risk="Changes or removes an existing Facebook page integration.",
        high_impact=True, item=False,
    ),
    "report_profiles": Resource("/report_profiles"),
    "webhooks": Resource("/webhooks", risk="May call an external system when referenced by a trigger.", high_impact=True),
    "email_addresses": Resource("/email_addresses", risk="Deleting an address can clear group sender settings.", high_impact=True),
    "checklist_templates": Resource("/checklist_templates", risk="Changes reusable checklists available to agents.", high_impact=True),
    "tag_list": Resource("/tag_list", risk="Renaming or deleting a tag changes how ticket data is categorized.", high_impact=True),
    "organizations": Resource("/organizations", risk="Changes or permanently deletes organization and user associations.", high_impact=True),
    "users": Resource("/users", risk="Changes user identity, roles, and access; deleting a user can affect related records.", high_impact=True),
    "object_manager_attributes": Resource("/object_manager_attributes", operations=frozenset({"create", "update"}), risk="Schema changes can affect stored data and require a separate migration/restart workflow.", high_impact=True),
    "user_access_tokens": Resource(
        "/user_access_token",
        operations=frozenset({"create", "delete"}),
        risk="Creates a one-time API secret or revokes a token; either action can lock out integrations.",
        high_impact=True,
    ),
    "email_channels": Resource(
        "/channels_email",
        operations=frozenset({"enable", "disable", "delete", "reassign"}),
        risk="Changes or stops an inbound mailbox; email polling and ticket creation may be affected.",
        high_impact=True,
        item=False,
    ),
    "settings": Resource("/settings", operations=frozenset({"update"}), risk="May change authentication, integrations, security, or service behavior.", high_impact=True),
    "jobs": Resource("/jobs", risk="Scheduled jobs can change tickets, users, or organizations when they run.", high_impact=True),
    "public_links": Resource("/public_links", risk="Changes public login, signup, or password-reset links; inspect destination and screen before approval.", high_impact=True),
    "postmaster_filters": Resource("/postmaster_filters", risk="Changes inbound email processing, ticket routing, and actions.", high_impact=True),
    "ldap_sources": Resource("/ldap_sources", risk="LDAP settings affect authentication and user synchronization; bind passwords are set only from process environment references.", high_impact=True),
    "chats": Resource("/chats", risk="Chat configuration changes availability; deletion also removes chat sessions.", high_impact=True),
    "external_credentials": Resource("/external_credentials", risk="Replaces connected provider settings or secrets and may affect external integrations.", high_impact=True),
}

_SPECIAL_CHANNEL = "email_notification"
_SPECIAL_PATH = "/channels_email_notification"
_SPECIAL_READ_PATH = "/channels_email"
_MESSAGING_CHANNELS_RESOURCE = "messaging_channels"
_EMAIL_ACCOUNT_RESOURCE = "email_account"
_EMAIL_ACCOUNT_VERIFY_PATH = "/channels_email_verify"
_EMAIL_CHANNEL_ENABLE_PATH = "/channels_email_enable"
_EMAIL_CHANNEL_DISABLE_PATH = "/channels_email_disable"
_EMAIL_CHANNEL_GROUP_PATH = "/channels_email_group"
_MESSAGE_CHANNEL_RESOURCES = {"sms_channels", "telegram_channels", "whatsapp_channels"}
_PLAN_TTL_SECONDS = 300
_MAX_PLANS = 100
_PLANS: dict[str, dict[str, Any]] = {}
_PLAN_LOCK = asyncio.Lock()
_WRITE_LOCK = asyncio.Lock()
_PLAN_CLEANER: asyncio.Task[None] | None = None

mcp = FastMCP("zammad-admin")


def _validate_id(object_id: int | None) -> int:
    if isinstance(object_id, bool) or not isinstance(object_id, int) or object_id <= 0:
        raise ValueError("object_id must be a positive integer")
    return object_id


def _json(value: Any) -> str:
    return json.dumps(_scrub(value), ensure_ascii=False, indent=2, sort_keys=True)


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _snapshot_fingerprint(resource: str, value: Any) -> str:
    if resource == "user_access_tokens" and isinstance(value, Mapping):
        permissions = value.get("permissions", [])
        tokens = value.get("tokens", [])
        stable = {
            "permissions": sorted(
                (item.get("name"), item.get("active"))
                for item in permissions if isinstance(item, Mapping) and isinstance(item.get("name"), str)
            ),
            "token_ids": sorted(item.get("id") for item in tokens if isinstance(item, Mapping)),
        }
        return _digest(stable)
    return _digest(value)


def _validate_channel_payload(resource: str, operation: str, data: Any) -> None:
    def text(value: Any, field: str, *, secret: bool = False) -> None:
        if isinstance(value, Mapping) and set(value) == {"$secret_env"} and secret:
            return
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")

    def keys(payload: Any, allowed: set[str], required: set[str], label: str) -> Mapping[str, Any]:
        if not isinstance(payload, Mapping) or set(payload) - allowed or not required.issubset(payload):
            raise ValueError(f"{label} accepts only {', '.join(sorted(allowed))}; required: {', '.join(sorted(required))}")
        return payload

    if operation in {"enable", "disable", "delete"}:
        if data not in (None, {}):
            raise ValueError(f"{operation} does not accept data")
        return

    if operation == "test" and resource == "sms_channels":
        payload = keys(data, {"options", "recipient", "message"}, {"options", "recipient", "message"}, "SMS test")
        options = keys(payload["options"], {"adapter", "token", "sender", "account_id", "gateway"}, {"adapter"}, "SMS test options")
        adapter = options["adapter"]
        fields = {
            "sms/message_bird": {"adapter", "token", "sender"},
            "sms/twilio": {"adapter", "account_id", "token", "sender"},
            "sms/massenversand": {"adapter", "gateway", "token", "sender"},
        }
        if adapter not in fields or set(options) - fields[adapter]:
            raise ValueError("Unsupported SMS adapter or option fields")
        if adapter == "sms/massenversand":
            raise ValueError("The Massenversand test endpoint can expose its token in provider errors; test it through Zammad's UI")
        for key in set(options) - {"adapter"}:
            text(options[key], f"options.{key}", secret=key == "token")
        text(payload["recipient"], "recipient")
        text(payload["message"], "message")
        return

    if operation == "preload" and resource == "whatsapp_channels":
        payload = keys(data, {"channel_id", "business_id", "access_token"}, set(), "WhatsApp preload")
        if "channel_id" in payload:
            _validate_id(payload["channel_id"])
            if set(payload) != {"channel_id"}:
                raise ValueError("For an existing WhatsApp channel, preload accepts only channel_id")
        elif set(payload) != {"business_id", "access_token"}:
            raise ValueError("WhatsApp preload requires channel_id or business_id and access_token")
        if "business_id" in payload:
            text(payload["business_id"], "business_id")
            text(payload["access_token"], "access_token", secret=True)
        return

    if resource == "sms_channels":
        payload = keys(data, {"area", "options", "group_id"}, {"area", "options"}, "SMS channel")
        if payload["area"] not in {"Sms::Account", "Sms::Notification"}:
            raise ValueError("SMS area must be Sms::Account or Sms::Notification")
        if payload["area"] == "Sms::Account":
            if "group_id" not in payload:
                raise ValueError("SMS account channels require group_id")
            _validate_id(payload["group_id"])
        elif "group_id" in payload:
            raise ValueError("SMS notification channels do not accept group_id")
        options = keys(payload["options"], {"adapter", "token", "sender", "account_id", "gateway"}, {"adapter"}, "SMS options")
        fields = {
            "sms/message_bird": {"adapter", "token", "sender"},
            "sms/twilio": {"adapter", "account_id", "token", "sender"},
            "sms/massenversand": {"adapter", "gateway", "token", "sender"},
        }
        adapter = options["adapter"]
        if adapter not in fields or set(options) - fields[adapter]:
            raise ValueError("Unsupported SMS adapter or option fields")
        if adapter == "sms/massenversand" and payload["area"] != "Sms::Notification":
            raise ValueError("Massenversand is supported only for notification channels")
        for key in set(options) - {"adapter"}:
            text(options[key], f"options.{key}", secret=key == "token")
        if adapter == "sms/massenversand":
            gateway = urlsplit(options["gateway"])
            try:
                address = ipaddress.ip_address(gateway.hostname or "")
            except ValueError:
                address = None
            if (
                gateway.scheme != "https" or not gateway.hostname or gateway.username or gateway.password
                or gateway.query or gateway.fragment or address is not None
                or gateway.hostname.lower() == "localhost" or "." not in gateway.hostname
            ):
                raise ValueError("Massenversand gateway must be an HTTPS hostname URL without credentials, query, or fragment")
        return

    if resource == "telegram_channels":
        payload = keys(data, {"api_token", "group_id", "welcome", "goodbye"}, {"api_token", "group_id"}, "Telegram channel")
        text(payload["api_token"], "api_token", secret=True)
        _validate_id(payload["group_id"])
        for key in {"welcome", "goodbye"} & set(payload):
            if not isinstance(payload[key], str):
                raise ValueError(f"{key} must be a string")
        return

    if resource == "whatsapp_channels":
        allowed = {"business_id", "access_token", "app_secret", "phone_number_id", "group_id", "welcome", "reminder_active", "reminder_message"}
        required = {"business_id", "access_token", "app_secret", "phone_number_id", "group_id"}
        payload = keys(data, allowed, required, "WhatsApp channel")
        for key in {"business_id", "phone_number_id"}:
            text(payload[key], key)
        for key in {"access_token", "app_secret"}:
            text(payload[key], key, secret=True)
        _validate_id(payload["group_id"])
        if "welcome" in payload and not isinstance(payload["welcome"], str):
            raise ValueError("welcome must be a string")
        if "reminder_active" in payload and not isinstance(payload["reminder_active"], bool):
            raise ValueError("reminder_active must be a boolean")
        if "reminder_message" in payload and not isinstance(payload["reminder_message"], str):
            raise ValueError("reminder_message must be a string")


def _resource(resource: str) -> Resource:
    try:
        return _RESOURCES[resource]
    except KeyError as exc:
        raise ValueError("Unsupported Zammad admin resource") from exc


async def _request(method: str, path: str, payload: Any = None, params: dict[str, Any] | None = None) -> Any:
    allowed = {
        "/version", _SPECIAL_READ_PATH, _SPECIAL_PATH, _EMAIL_ACCOUNT_VERIFY_PATH,
        _EMAIL_CHANNEL_ENABLE_PATH, _EMAIL_CHANNEL_DISABLE_PATH, "/roles?expand=true",
        "/channels_sms_enable", "/channels_sms_disable", "/channels_sms/test",
        "/channels_telegram_enable", "/channels_telegram_disable",
        "/channels_facebook_enable", "/channels_facebook_disable",
        "/channels/admin/whatsapp/preload",
        "/integration/ldap/discover", "/integration/ldap/bind",
        "/integration/ldap/job_try", "/integration/ldap/job_start",
    }
    email_group_path = bool(re.fullmatch(r"/channels_email_group/\d+", path))
    whatsapp_action_path = bool(re.fullmatch(r"/channels/admin/whatsapp/\d+/(?:enable|disable)", path))
    for item in _RESOURCES.values():
        allowed.add(item.path)
    item_path = any(
        path.startswith(spec.path + "/")
        and path[len(spec.path) + 1 :].isdigit()
        and int(path[len(spec.path) + 1 :]) > 0
        for spec in _RESOURCES.values()
    )
    knowledge_base_path = bool(re.fullmatch(r"/knowledge_bases/\d+(?:/(?:answers|categories)(?:/\d+)?|/permissions)", path))
    knowledge_base_settings_path = bool(re.fullmatch(r"/knowledge_bases/manage/\d+", path))
    if path not in allowed and not email_group_path and not whatsapp_action_path and not item_path and not knowledge_base_path and not knowledge_base_settings_path:
        raise ValueError("Unsupported Zammad API resource")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Unsupported Zammad API method")
    return await _send_api_request(method, path, payload, params)


async def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    return await _request("GET", path, params=params)


@mcp.tool()
async def zammad_server_version() -> str:
    """Read the version of the connected Zammad instance."""
    return _json(await _get("/version"))


@mcp.tool()
async def zammad_list_admin_resources() -> str:
    """List API-backed administration resource names currently allowlisted by this MCP."""
    return _json({name: {"operations": ["read", *sorted(spec.operations)], "risk": spec.risk} for name, spec in _RESOURCES.items()} | {
        _SPECIAL_CHANNEL: {"operations": ["configure"], "risk": "POST sends a real test email and saves the active notification channel."},
        _EMAIL_ACCOUNT_RESOURCE: {"operations": ["configure"], "risk": "Verifies inbound/outbound mail, sends a test message, saves the mailbox, and starts mail fetching."},
        "email_channels": {"operations": ["read", "enable", "disable", "delete", "reassign"], "risk": "Lists email metadata; writes change inbound mailbox state and can alter ticket creation."},
        _MESSAGING_CHANNELS_RESOURCE: {"operations": ["read"], "risk": "Read-only sanitized inventory of non-email messaging channels from the shared channel endpoint."},
        "knowledge_base_settings": {"operations": ["update"], "risk": "Preview/apply by knowledge_base_id; explicit confirmation required."},
        "knowledge_base_answers": {"operations": ["read", "create", "update", "delete"], "risk": "Content writes are high impact and require explicit confirmation."},
        "knowledge_base_categories": {"operations": ["read", "create", "update", "delete"], "risk": "Content writes are high impact and require explicit confirmation."},
        "ldap_connection_tests": {"operations": ["discover", "bind"], "risk": "Connects from Zammad to the configured LDAP host; bind credentials are secret-safe and every action requires approval."},
        "ldap_import_actions": {"operations": ["dry_run", "sync"], "risk": "Dry-run reads all active LDAP directories and records aggregate results; sync may create, update, or deactivate Zammad users."},
    })


@mcp.tool()
async def zammad_list_admin_resource(resource: str, page: int = 1, per_page: int = 100) -> str:
    """List one page from a fixed allowlisted Zammad admin resource."""
    if isinstance(page, bool) or page < 1:
        raise ValueError("page must be a positive integer")
    if isinstance(per_page, bool) or not 1 <= per_page <= 100:
        raise ValueError("per_page must be between 1 and 100")
    params = {"page": page, "per_page": per_page}
    if resource in {_SPECIAL_CHANNEL, "email_channels", _MESSAGING_CHANNELS_RESOURCE}:
        channel_data = await _get(_SPECIAL_READ_PATH, params)
        if resource == _MESSAGING_CHANNELS_RESOURCE:
            return _json(_project_messaging_channels(channel_data))
        return _json(_project_email_channels(channel_data))
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        return _json(_project_messaging_channels(await _get(_resource(resource).path, params)))
    if resource == "facebook_channels":
        return _json(_project_messaging_channels(await _get(_resource(resource).path, params)))
    spec = _resource(resource)
    result = await _get(spec.path, params)
    if resource == "settings":
        result = _project_settings(result)
    return _json(result)


def _register_legacy_list_tool(resource: str) -> None:
    """Keep stable names from the original read-only tool set."""
    async def list_resource() -> str:
        return _json(await _get(_resource(resource).path))

    list_resource.__name__ = f"zammad_list_{resource}"
    list_resource.__doc__ = f"List configured Zammad {resource.replace('_', ' ')}. Read-only."
    mcp.tool(name=list_resource.__name__)(list_resource)


for _legacy_resource in ("groups", "roles", "calendars", "slas", "triggers", "ticket_states"):
    _register_legacy_list_tool(_legacy_resource)


@mcp.tool()
async def zammad_list_roles_expanded() -> str:
    """List roles with related permissions expanded where supported."""
    return _json(await _get("/roles?expand=true"))


@mcp.tool()
async def zammad_get_admin_object(resource: str, object_id: int) -> str:
    """Read one object from a fixed allowlisted Zammad admin resource."""
    spec = _resource(resource)
    if not spec.item:
        raise ValueError("This resource does not support item reads")
    object_id = _validate_id(object_id)
    result = await _get(f"{spec.path}/{object_id}")
    if resource == "settings":
        result = _project_settings(result)
    return _json(result)


@mcp.tool()
async def zammad_prepare_ldap_import_action(
    action: Literal["dry_run", "sync"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an LDAP dry-run import or full synchronization without starting it."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("LDAP import actions require acknowledge_high_impact=true")
    if action not in {"dry_run", "sync"}:
        raise ValueError("Unsupported LDAP import action")
    sources = await _ldap_sources_snapshot()
    active_count = sum(source.get("active") is True for source in sources)
    if active_count == 0:
        raise ValueError("At least one active LDAP source is required")
    if await _ldap_import_pending(action):
        raise ValueError(f"An LDAP {action.replace('_', ' ')} job is already queued or running")
    dependencies: list[dict[str, str]] = []
    integration_enabled: bool | None = None
    if action == "sync":
        setting = await _ldap_integration_setting_snapshot()
        integration_enabled = True
        dependencies.append({"path": f"/settings/{setting['id']}", "fingerprint": _digest(setting)})
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__ldap_import_action__", "operation": action, "object_id": None,
        "data": {}, "fingerprint": _digest(sources),
        "before": {"active_source_count": active_count, "total_source_count": len(sources)},
        "dependencies": dependencies, "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    if action == "dry_run":
        effects = [
            f"Read all {active_count} active LDAP sources and their directories",
            "Create an ImportJob dry-run record and store aggregate import results",
            "Do not save, update, or deactivate Zammad users or roles",
        ]
    else:
        effects = [
            f"Queue a background sync across all {active_count} active LDAP sources",
            "The sync may create, update, or deactivate Zammad users and update role assignments",
        ]
    return _json({
        "plan_id": plan_id,
        "resource": "ldap_import_actions",
        "operation": action,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "before": {"active_source_count": active_count, "total_source_count": len(sources), "ldap_integration_enabled": integration_enabled},
        "after": {"action": action},
        "write_effects": effects,
        "approval_required": True,
        "note": "No import job was created. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_get_ldap_import_status(
    action: Literal["dry_run", "sync"],
    include_completed: bool = True,
) -> str:
    """Read LDAP import progress and aggregate counts without exposing payloads or directory records."""
    if action == "dry_run":
        params = {"finished": "true" if include_completed else "false"}
        job = await _get("/integration/ldap/job_try", params)
    else:
        job = await _get("/integration/ldap/job_start")
    return _json(_ldap_import_status_summary(job, action))


@mcp.tool()
async def zammad_prepare_ldap_connection_action(
    action: Literal["discover", "bind"],
    data: dict[str, Any],
    source_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an LDAP discovery or bind check without contacting the directory."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("LDAP connection actions require acknowledge_high_impact=true")
    if action not in {"discover", "bind"}:
        raise ValueError("Unsupported LDAP connection action")
    if not isinstance(data, dict):
        raise ValueError("data must be a JSON object")
    if action == "discover" and source_id is not None:
        raise ValueError("discover does not accept source_id")
    if action == "bind" and source_id is None and data.get("bind_pw") == "**********":
        raise ValueError("A masked bind password can only be reused when source_id identifies its existing LDAP source")
    if action == "bind" and source_id is not None:
        source_id = _validate_id(source_id)
        source_before = await _get(f"/ldap_sources/{source_id}")
        if not isinstance(source_before, Mapping):
            raise RuntimeError("The Zammad API did not return an LDAP source snapshot")
        data = retain_ldap_action_values(data, source_before)
    validate_ldap_action_payload(action, data)
    data, preview_data = materialize_ldap_action(data)
    before = source_before if action == "bind" and source_id is not None else None
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__ldap_connection_action__", "operation": action, "object_id": source_id,
        "data": data, "fingerprint": _digest(before) if before is not None else None,
        "before": before, "dependencies": [], "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    write_effects = ["Connect from Zammad to the LDAP host when this plan is applied"]
    if action == "bind" and isinstance(preview_data.get("bind_pw"), str) and preview_data["bind_pw"] == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]":
        write_effects.append("Use the supplied process-environment bind password without returning it")
    elif action == "bind" and preview_data.get("bind_pw") == "[EXISTING SECRET RETAINED]":
        write_effects.append("Use the existing bind password without returning it")
    return _json({
        "plan_id": plan_id,
        "resource": "ldap_connection_tests",
        "operation": action,
        "object_id": source_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Contacts the configured LDAP server and may reveal directory naming contexts, attributes, or group names.",
        "before": _scrub(before),
        "after": {"action": action, "request": preview_data},
        "write_effects": write_effects,
        "approval_required": True,
        "note": "No LDAP request was sent. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_get_knowledge_base(knowledge_base_id: int) -> str:
    """Read one Knowledge Base configuration object by its Zammad ID."""
    return _json(await _get(f"/knowledge_bases/{_validate_id(knowledge_base_id)}"))


@mcp.tool()
async def zammad_get_knowledge_base_permissions(knowledge_base_id: int) -> str:
    """Read the role permissions configured for one Knowledge Base."""
    return _json(await _get(f"/knowledge_bases/{_validate_id(knowledge_base_id)}/permissions"))


@mcp.tool()
async def zammad_get_knowledge_base_record(
    knowledge_base_id: int,
    kind: Literal["answers", "categories"],
    record_id: int,
    translation_id: int | None = None,
) -> str:
    """Read one Knowledge Base answer or category; answer content is optional by translation ID."""
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(record_id)
    path = f"/knowledge_bases/{kb_id}/{kind}/{item_id}"
    params = {"include_contents": _validate_id(translation_id)} if translation_id is not None else None
    return _json(await _get(path, params))


async def _snapshot(resource: str, operation: str, object_id: int | None) -> Any:
    if resource in {_SPECIAL_CHANNEL, _EMAIL_ACCOUNT_RESOURCE, "email_channels"}:
        return await _get(_SPECIAL_READ_PATH)
    if resource == "facebook_channels":
        collection = await _get(_resource(resource).path)
        assets = collection.get("assets", {}) if isinstance(collection, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        channel = channel_assets.get(str(_validate_id(object_id))) if isinstance(channel_assets, Mapping) else None
        return {"assets": {"Channel": {str(object_id): channel}}} if isinstance(channel, Mapping) else {"assets": {"Channel": {}}}
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        return await _get(_resource(resource).path)
    if resource == "__knowledge_base_settings__":
        return await _get(f"/knowledge_bases/{_validate_id(object_id)}")
    spec = _resource(resource)
    if operation == "create":
        return await _get(spec.path)
    return await _get(f"{spec.path}/{_validate_id(object_id)}")


async def _ldap_sources_snapshot() -> list[Mapping[str, Any]]:
    sources: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        rows = await _get("/ldap_sources", {"page": page, "per_page": 100})
        if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
            raise RuntimeError("Zammad did not return an LDAP source list")
        sources.extend(rows)
        if len(rows) < 100:
            return sources
    raise RuntimeError("LDAP source inventory exceeds the supported snapshot size")


async def _ldap_integration_setting_snapshot() -> Mapping[str, Any]:
    settings = await _get("/settings")
    if not isinstance(settings, list):
        raise RuntimeError("Zammad did not return the settings list")
    candidates = [item for item in settings if isinstance(item, Mapping) and item.get("name") == "ldap_integration"]
    if len(candidates) != 1:
        raise RuntimeError("The LDAP integration setting is missing or ambiguous")
    setting_id = _validate_id(candidates[0].get("id"))
    setting = await _get(f"/settings/{setting_id}")
    if not isinstance(setting, Mapping) or setting.get("name") != "ldap_integration":
        raise RuntimeError("Zammad did not return the LDAP integration setting")
    state = setting.get("state_current")
    if not isinstance(state, Mapping) or state.get("value") is not True:
        raise ValueError("LDAP integration must be enabled before starting a sync")
    return setting


async def _ldap_import_pending(action: str) -> bool:
    if action == "dry_run":
        job = await _get("/integration/ldap/job_try", {"finished": "false"})
    else:
        job = await _get("/integration/ldap/job_start")
    return isinstance(job, Mapping) and bool(job) and job.get("finished_at") is None


def _ldap_import_status_summary(job: Any, action: str) -> dict[str, Any]:
    if not isinstance(job, Mapping) or not job:
        return {"action": action, "status": "not_found"}
    result = job.get("result") if isinstance(job.get("result"), Mapping) else {}
    counts = {
        key: result[key]
        for key in ("sum", "total", "created", "updated", "unchanged", "skipped", "failed", "deactivated")
        if isinstance(result.get(key), int) and not isinstance(result.get(key), bool) and result[key] >= 0
    }
    finished = bool(job.get("finished_at"))
    status = "failed" if result.get("error") else "finished" if finished else "running" if job.get("started_at") else "queued"
    return {
        "action": action,
        "status": status,
        "job_id": job.get("id") if isinstance(job.get("id"), int) else None,
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "counts": counts,
        "has_error_detail": bool(result.get("error")),
        "has_info_detail": bool(result.get("info")),
    }


@mcp.tool()
async def zammad_prepare_knowledge_base_settings_change(
    knowledge_base_id: int,
    data: dict[str, Any],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an allowlisted Knowledge Base settings update without writing it."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    allowed_fields = {
        "iconset", "color_highlight", "color_header", "color_header_link",
        "homepage_layout", "category_layout", "active", "show_feed_icon", "custom_address",
    }
    if not isinstance(data, dict) or not data:
        raise ValueError("data must be a non-empty JSON object")
    unknown = sorted(set(data) - allowed_fields)
    if unknown:
        raise ValueError(f"Unsupported Knowledge Base settings fields: {', '.join(unknown)}")
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base changes require acknowledge_high_impact=true")

    before = await _get(f"/knowledge_bases/{kb_id}")
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_settings__", "operation": "update", "object_id": kb_id,
        "data": data, "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda k: _PLANS[k]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_settings", "operation": "update",
        "object_id": kb_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes Knowledge Base settings and public presentation.",
        "before": before, "after": _merge_preview(before, data), "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_record_change(
    knowledge_base_id: int,
    kind: Literal["answers", "categories"],
    operation: Literal["create", "update", "delete"],
    data: dict[str, Any] | None = None,
    record_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a Knowledge Base answer/category change; no write happens until apply."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base content changes require acknowledge_high_impact=true")
    if operation in {"create", "update"} and (not isinstance(data, dict) or not data):
        raise ValueError("create and update require a non-empty JSON object in data")
    if operation == "delete" and data:
        raise ValueError("delete does not accept data")
    if operation == "create" and record_id is not None:
        raise ValueError("create does not accept record_id")
    if operation in {"update", "delete"}:
        record_id = _validate_id(record_id)

    collection_path = f"/knowledge_bases/{kb_id}/{kind}"
    if operation == "create":
        snapshot_path = f"/knowledge_bases/{kb_id}"
        write_path = collection_path
        method = "POST"
    else:
        snapshot_path = f"{collection_path}/{record_id}"
        write_path = snapshot_path
        method = "PATCH" if operation == "update" else "DELETE"
    before = await _get(snapshot_path)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_record__", "operation": operation,
        "object_id": record_id, "parent_id": kb_id, "kind": kind, "data": data,
        "snapshot_path": snapshot_path, "write_path": write_path, "write_method": method,
        "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda k: _PLANS[k]["expires_at"]), None)
        _PLANS[plan_id] = plan
    after = data if operation == "create" else (_merge_preview(before, data or {}) if operation == "update" else None)
    return _json({
        "plan_id": plan_id, "resource": f"knowledge_base_{kind}", "operation": operation,
        "parent_id": kb_id, "object_id": record_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes or deletes customer-facing Knowledge Base content.",
        "before": before, "after": after, "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


def _merge_preview(before: Any, patch: Mapping[str, Any]) -> Any:
    merged = dict(before) if isinstance(before, Mapping) else {}
    merged.update(patch)
    return merged


def _project_email_channels(value: Any) -> dict[str, Any]:
    """Expose email configuration while omitting linked people and diagnostic logs."""
    if not isinstance(value, Mapping):
        return {}
    assets = value.get("assets", {})
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    address_assets = assets.get("EmailAddress", {}) if isinstance(assets, Mapping) else {}
    channel_fields = {
        "id", "name", "area", "active", "group_id", "options", "preferences",
        "status_in", "status_out", "created_at", "updated_at",
    }
    address_fields = {
        "id", "email", "realname", "name", "channel_id", "active", "group_id",
        "preferences", "created_at", "updated_at",
    }

    def select(source: Any, fields: set[str]) -> dict[str, Any]:
        if not isinstance(source, Mapping):
            return {}
        return {
            str(key): {field: item[field] for field in fields if field in item}
            for key, item in source.items() if isinstance(item, Mapping)
        }

    fixed = value.get("accounts_fixed", [])
    return {
        "account_channel_ids": value.get("account_channel_ids", []),
        "notification_channel_ids": value.get("notification_channel_ids", []),
        "email_address_ids": value.get("email_address_ids", []),
        "not_used_email_address_ids": value.get("not_used_email_address_ids", []),
        "accounts_fixed": [
            {field: item[field] for field in address_fields if field in item}
            for item in fixed if isinstance(item, Mapping)
        ] if isinstance(fixed, list) else [],
        "assets": {
            "Channel": {
                channel_id: channel for channel_id, channel in select(channel_assets, channel_fields).items()
                if channel.get("area") in {"Email::Account", "Email::Notification"}
            },
            "EmailAddress": select(address_assets, address_fields),
        },
        "channel_driver": value.get("channel_driver", {}),
        "config": value.get("config", {}),
    }


def _project_messaging_channels(value: Any) -> dict[str, Any]:
    """Return non-email channel configuration without linked person assets or diagnostic logs."""
    projected = _project_email_channels(value)
    assets = value.get("assets", {}) if isinstance(value, Mapping) else {}
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    fields = {
        "id", "name", "area", "active", "group_id", "options", "preferences",
        "status_in", "status_out", "created_at", "updated_at",
    }

    def safe_value(item: Any, key: str | None = None) -> Any:
        if key == "gateway" and isinstance(item, str):
            parsed = urlsplit(item)
            hostname = parsed.hostname or ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = f"[{hostname}]"
            netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
            return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
        if isinstance(item, Mapping):
            return {str(nested_key): safe_value(nested_value, str(nested_key)) for nested_key, nested_value in item.items()}
        if isinstance(item, list):
            return [safe_value(nested) for nested in item]
        return item

    channels = {
        str(channel_id): {
            field: safe_value(item[field], field) if field == "options" else item[field]
            for field in fields if field in item
        }
        for channel_id, item in channel_assets.items()
        if isinstance(item, Mapping) and item.get("area") not in {"Email::Account", "Email::Notification"}
    } if isinstance(channel_assets, Mapping) else {}
    return {"channel_ids": sorted(channels, key=lambda item: int(item) if item.isdigit() else float("inf")), "channels": channels}


def _email_account_preview(before: Any, data: Mapping[str, Any]) -> dict[str, Any]:
    channel_id = data.get("channel_id")
    projected = _project_email_channels(before)
    assets = projected.get("assets", {})
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    current = None
    if channel_id is not None and isinstance(channel_assets, Mapping):
        current = channel_assets.get(str(channel_id), channel_assets.get(channel_id))
    summary = {
        "account_channel_ids": projected.get("account_channel_ids", []),
        "notification_channel_ids": projected.get("notification_channel_ids", []),
        "current_channel": current,
    }
    return {"before": summary, "after": dict(data)}


def _validate_email_account_payload(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError("email_account configure requires a JSON object")
    required = {"inbound", "outbound", "group_id"}
    allowed = required | {"channel_id", "email", "meta", "group_email_address", "group_email_address_id", "subject"}
    if not required.issubset(data) or set(data) - allowed:
        raise ValueError("email_account requires inbound, outbound, and group_id; only documented channel fields are accepted")
    _validate_id(data["group_id"])
    if data.get("channel_id") is not None:
        _validate_id(data["channel_id"])
    for direction in ("inbound", "outbound"):
        config = data[direction]
        if not isinstance(config, dict) or set(config) != {"adapter", "options"}:
            raise ValueError(f"{direction} must contain exactly adapter and options")
        if not isinstance(config.get("adapter"), str) or not config["adapter"].strip():
            raise ValueError(f"{direction}.adapter must be a non-empty string")
        if not isinstance(config.get("options"), dict):
            raise ValueError(f"{direction}.options must be a JSON object")
    meta = data.get("meta")
    if not isinstance(meta, dict) or not isinstance(meta.get("email"), str) or not isinstance(meta.get("realname"), str):
        raise ValueError("meta must include email and realname strings")
    if data.get("email", meta["email"]) != meta["email"]:
        raise ValueError("email and meta.email must match")
    if data.get("group_email_address") is not None and not isinstance(data["group_email_address"], bool):
        raise ValueError("group_email_address must be a boolean")
    if data.get("group_email_address_id") is not None:
        _validate_id(data["group_email_address_id"])
    if data.get("subject") is not None and not isinstance(data["subject"], str):
        raise ValueError("subject must be a string")


def _expire_plans(now: float) -> None:
    for key in [k for k, v in _PLANS.items() if v["expires_at"] <= now]:
        _PLANS.pop(key, None)


async def _clean_expired_plans() -> None:
    while True:
        await asyncio.sleep(30)
        async with _PLAN_LOCK:
            _expire_plans(time.time())


@mcp.tool()
async def zammad_prepare_admin_change(
    resource: str,
    operation: Literal["create", "update", "delete", "configure", "enable", "disable", "reassign", "test", "preload"],
    data: dict[str, Any] | None = None,
    object_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a Zammad admin change. This tool never writes to Zammad.

    After showing the preview, obtain explicit user approval in conversation before calling
    zammad_apply_admin_change. The MCP host must not treat the plan identifier as approval.
    Secret values must be supplied by a process environment reference, for example
    {"$secret_env": "ZAMMAD_SECRET_IMAP_PASSWORD"}; inline secret literals are rejected.
    email_account configure plans send a test message and start mailbox polling when applied.
    """
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())

    if resource == _SPECIAL_CHANNEL:
        if operation != "configure":
            raise ValueError("email_notification supports only the configure operation")
        if not isinstance(data, dict) or not {"adapter", "options"}.issubset(data):
            raise ValueError("email_notification requires adapter and options")
        spec = Resource(_SPECIAL_PATH, frozenset({"configure"}), "Sends a real test email and saves the active notification configuration.", True, False)
    elif resource == _EMAIL_ACCOUNT_RESOURCE:
        if operation != "configure":
            raise ValueError("email_account supports only the configure operation")
        if object_id is not None:
            raise ValueError("email_account uses channel_id inside data and does not accept object_id")
        _validate_email_account_payload(data)
        spec = Resource(
            _EMAIL_ACCOUNT_VERIFY_PATH,
            frozenset({"configure"}),
            "Verifies inbound/outbound mail, sends a test message, saves the mailbox, and starts mail fetching.",
            True,
            False,
        )
    elif resource == "email_channels":
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError("email_channels supports enable, disable, delete, or reassign")
        object_id = _validate_id(object_id)
        if operation == "reassign":
            if not isinstance(data, dict) or set(data) != {"group_id"}:
                raise ValueError("reassign requires exactly a group_id field")
            _validate_id(data["group_id"])
        elif data:
            raise ValueError(f"{operation} does not accept data")
    elif resource == "facebook_channels":
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError("facebook_channels supports update, enable, disable, or delete")
        object_id = _validate_id(object_id)
        if operation == "update":
            validate_facebook_channel_payload(data)
        elif data:
            raise ValueError(f"{operation} does not accept data")
    elif resource in _MESSAGE_CHANNEL_RESOURCES:
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError(f"Operation {operation!r} is not allowed for resource {resource!r}")
        if operation in {"create", "test", "preload"}:
            if object_id is not None:
                raise ValueError(f"{operation} does not accept object_id")
            if not isinstance(data, dict) or not data:
                raise ValueError(f"{operation} requires a non-empty JSON object in data")
        else:
            object_id = _validate_id(object_id)
            if operation == "update" and (not isinstance(data, dict) or not data):
                raise ValueError("update requires a non-empty JSON object in data")
            if operation != "update" and data:
                raise ValueError(f"{operation} does not accept data")
    else:
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError(f"Operation {operation!r} is not allowed for resource {resource!r}")
        if operation == "configure":
            raise ValueError("configure is only valid for email_notification")
        if operation in {"create", "update"} and (not isinstance(data, dict) or not data):
            raise ValueError("create and update require a non-empty JSON object in data")
        if resource == "settings" and operation == "update":
            if set(data) != {"name", "state_current"} or not isinstance(data.get("name"), str):
                raise ValueError("settings updates require exactly name and state_current fields")
            state_current = data.get("state_current")
            if not isinstance(state_current, dict) or set(state_current) != {"value"}:
                raise ValueError("settings state_current must contain exactly one value field")
            _validate_setting_secret_reference(data)
        if operation == "delete" and data:
            raise ValueError("delete does not accept data")
        if operation == "create" and object_id is not None:
            raise ValueError("create does not accept object_id")
        if operation in {"update", "delete"}:
            object_id = _validate_id(object_id)
        if resource == "user_access_tokens" and operation == "create":
            if object_id is not None:
                raise ValueError("Token creation does not accept object_id")
            if not isinstance(data, dict):
                raise ValueError("Token creation requires name and permission fields")
    if spec.high_impact and not acknowledge_high_impact:
        raise ValueError("This change is high impact; inspect the resource risk and set acknowledge_high_impact=true to prepare it")

    ldap_before = None
    if resource == "ldap_sources" and operation == "update" and isinstance(data, Mapping) and "preferences" in data:
        ldap_before = await _snapshot(resource, operation, object_id)
        data = retain_ldap_secret(data, ldap_before)
    if resource == "ldap_sources" and operation in {"create", "update"}:
        if operation == "create" and isinstance(data.get("preferences"), Mapping) and data["preferences"].get("bind_pw") == "**********":
            raise ValueError("A masked bind password can only be reused when updating an existing LDAP source")
        validate_ldap_source_payload(operation, data)
        data, preview_data = materialize_ldap_source(data)
    elif resource == "external_credentials" and operation in {"create", "update"}:
        validate_external_credentials_payload(operation, data)
        data, preview_data = materialize_external_credentials(data)
    else:
        data, preview_data = _materialize_secret_values(data) if data is not None else (None, None)
    if resource == "jobs" and operation in {"create", "update"}:
        validate_job_payload(operation, data)
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        _validate_channel_payload(resource, operation, data)
    if resource == "public_links" and operation in {"create", "update"}:
        validate_public_link_payload(operation, data)
    if resource == "chats" and operation in {"create", "update"}:
        validate_chat_payload(operation, data)
    if resource == "postmaster_filters" and operation in {"create", "update"}:
        validate_postmaster_filter_payload(operation, data)

    before = ldap_before if ldap_before is not None else await _snapshot(resource, operation, object_id)
    facebook_requested_pages: Mapping[str, Any] | None = None
    facebook_channel: Mapping[str, Any] | None = None
    if resource == "facebook_channels":
        assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        facebook_channel = channel_assets.get(str(object_id)) if isinstance(channel_assets, Mapping) else None
        if not isinstance(facebook_channel, Mapping) or facebook_channel.get("area") != "Facebook::Account":
            raise ValueError("object_id must identify an existing Facebook account channel")
        if operation == "update":
            requested_pages = preview_data["pages"]
            options = facebook_channel.get("options", {})
            existing_pages = options.get("pages", []) if isinstance(options, Mapping) else []
            page_ids = {
                str(page.get("id")) for page in existing_pages
                if isinstance(page, Mapping) and page.get("id") is not None
            } if isinstance(existing_pages, list) else set()
            if set(requested_pages) - page_ids:
                raise ValueError("pages must identify Facebook pages already linked to this channel")
            current_options = dict(options) if isinstance(options, Mapping) else {}
            current_sync = current_options.get("sync", {})
            sync = dict(current_sync) if isinstance(current_sync, Mapping) else {}
            current_page_settings = sync.get("pages", {})
            page_settings = dict(current_page_settings) if isinstance(current_page_settings, Mapping) else {}
            page_settings.update(requested_pages)
            sync["pages"] = page_settings
            current_options["sync"] = sync
            facebook_requested_pages = requested_pages
            data = {"id": object_id, "options": current_options}
            preview_data = {"pages": requested_pages}
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        before_preview = _project_messaging_channels(before)
        if operation in {"create", "update"}:
            after = preview_data
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        elif operation == "test":
            after = {
                "test_sms_to": preview_data["recipient"],
                "message": preview_data["message"],
                "side_effects_on_apply": ["send a real SMS; provider charges may apply"],
            }
        elif operation == "preload":
            after = {
                "provider_request": "retrieve WhatsApp phone-number options from Meta",
                "input": preview_data,
                "side_effects_on_apply": ["make an external request to Meta"],
            }
        else:
            after = None
    elif resource == "facebook_channels":
        before_preview = _project_messaging_channels(before)
        if operation == "update":
            after = {"id": object_id, "page_group_assignments": preview_data["pages"]}
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        else:
            after = None
    elif resource == "user_access_tokens" and operation == "create":
        _validate_token_create_payload(data, before)
    dependencies: list[dict[str, str]] = []
    group_id = None
    if resource == _EMAIL_ACCOUNT_RESOURCE:
        group_id = data["group_id"]
    elif resource == "email_channels" and operation == "reassign":
        group_id = data["group_id"]
    elif resource in _MESSAGE_CHANNEL_RESOURCES and operation in {"create", "update"} and isinstance(data, Mapping):
        group_id = data.get("group_id")
    if group_id is not None:
        group_before = await _get(f"/groups/{_validate_id(group_id)}")
        dependencies.append({"path": f"/groups/{group_id}", "fingerprint": _digest(group_before)})
    if resource == "ldap_sources" and operation in {"create", "update"}:
        for role_id in sorted(ldap_role_ids(data)):
            role_before = await _get(f"/roles/{role_id}")
            if not isinstance(role_before, Mapping) or role_before.get("active") is not True:
                raise ValueError(f"group_role_map role {role_id} must identify an active role")
            dependencies.append({"path": f"/roles/{role_id}", "fingerprint": _digest(role_before)})
    if resource == "facebook_channels" and operation == "update" and facebook_requested_pages is not None:
        for assignment in facebook_requested_pages.values():
            group_id = assignment.get("group_id") if isinstance(assignment, Mapping) else None
            if group_id in (None, ""):
                continue
            group_before = await _get(f"/groups/{_validate_id(group_id)}")
            if not isinstance(group_before, Mapping) or group_before.get("active") is not True:
                raise ValueError(f"Facebook page group_id {group_id} must identify an active group")
            dependencies.append({"path": f"/groups/{group_id}", "fingerprint": _digest(group_before)})
    if resource == _EMAIL_ACCOUNT_RESOURCE and data.get("channel_id") is not None:
        current_ids = before.get("account_channel_ids", []) if isinstance(before, Mapping) else []
        if data["channel_id"] not in current_ids:
            raise ValueError("channel_id must identify an existing inbound email channel")
    if resource == _EMAIL_ACCOUNT_RESOURCE and data.get("group_email_address_id") is not None:
        email_ids = before.get("email_address_ids", []) if isinstance(before, Mapping) else []
        if data["group_email_address_id"] not in email_ids:
            raise ValueError("group_email_address_id must identify an existing sender address")
    if resource == "email_channels":
        current_ids = before.get("account_channel_ids", []) if isinstance(before, Mapping) else []
        if object_id not in current_ids:
            raise ValueError("object_id must identify an existing inbound email channel")
    if resource in _MESSAGE_CHANNEL_RESOURCES and operation in {"update", "delete", "enable", "disable"}:
        assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        channel_ids = {int(value) for value in channel_assets if str(value).isdigit()} if isinstance(channel_assets, Mapping) else set()
        if object_id not in channel_ids:
            raise ValueError("object_id must identify an existing messaging channel")
    if operation in {"update", "delete"} and not isinstance(before, Mapping):
        raise RuntimeError("The Zammad API did not return an object snapshot")
    if resource == "settings" and data.get("name") != before.get("name"):
        raise ValueError("settings name must match the selected setting ID")
    if resource == "user_access_tokens" and operation == "create":
        available_permissions = [
            item["name"] for item in before.get("permissions", [])
            if isinstance(item, Mapping) and item.get("active") is True and isinstance(item.get("name"), str)
        ] if isinstance(before, Mapping) else []
        before_preview = {
            "active_permission_count": len(available_permissions),
            "requested_permissions_are_active": True,
        }
        after = preview_data
    elif resource == "facebook_channels":
        before_preview = _project_messaging_channels(before)
        if operation == "update":
            after = {"id": object_id, "page_group_assignments": preview_data["pages"]}
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        else:
            after = None
    elif operation == "create":
        after = preview_data
    elif resource == _EMAIL_ACCOUNT_RESOURCE:
        preview = _email_account_preview(before, preview_data)
        before_preview = preview["before"]
        after = preview["after"]
    elif resource == "email_channels":
        preview = _email_account_preview(before, {"channel_id": object_id})
        before_preview = preview["before"]
        if operation == "enable":
            after = {"id": object_id, "active": True}
        elif operation == "disable":
            after = {"id": object_id, "active": False}
        elif operation == "reassign":
            after = {"id": object_id, "group_id": preview_data["group_id"]}
        else:
            after = None
    elif resource == _SPECIAL_CHANNEL:
        before_preview = _project_email_channels(before)
        after = {
            "requested_configuration": preview_data,
            "side_effects_on_apply": ["send a real SMTP test email", "save the notification channel on success"],
        }
    elif operation in {"update", "configure"}:
        after = _merge_preview(before, preview_data or {})
    else:
        after = None
    if resource not in {_SPECIAL_CHANNEL, _EMAIL_ACCOUNT_RESOURCE, "email_channels", "facebook_channels", *_MESSAGE_CHANNEL_RESOURCES} and not (
        resource == "user_access_tokens" and operation == "create"
    ):
        before_preview = before
    if resource == "settings":
        before_preview = _project_settings(before_preview)
        after = _project_settings(after)

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": resource, "operation": operation, "object_id": object_id,
        "data": data, "fingerprint": _snapshot_fingerprint(resource, before), "before": before,
        "dependencies": dependencies,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": spec.high_impact,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            oldest = min(_PLANS, key=lambda k: _PLANS[k]["expires_at"])
            _PLANS.pop(oldest, None)
        _PLANS[plan_id] = plan

    write_effects: list[str] = []
    if resource == "external_credentials" and operation in {"create", "update"} and isinstance(preview_data, Mapping):
        credentials_preview = preview_data.get("credentials")
        if isinstance(credentials_preview, Mapping) and credentials_preview.get("client_secret") == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]":
            write_effects.append("Set the external provider client secret from a process environment reference")
    if resource == "ldap_sources" and operation in {"create", "update"} and isinstance(preview_data, Mapping):
        preferences_preview = preview_data.get("preferences")
        if isinstance(preferences_preview, Mapping):
            bind_password_preview = preferences_preview.get("bind_pw")
            if bind_password_preview == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]":
                write_effects.append("Set the LDAP bind password from a process environment reference")
            elif bind_password_preview == "[EXISTING SECRET RETAINED]":
                write_effects.append("Retain the existing LDAP bind password")
            elif bind_password_preview in (None, ""):
                write_effects.append("Store no LDAP bind password")
    preview_response = {
        "plan_id": plan_id,
        "resource": resource,
        "operation": operation,
        "object_id": object_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": spec.risk,
        "before": before_preview,
        "after": after,
        "approval_required": True,
        "note": "No write was performed. A fresh read-before-write check runs during apply; use apply only after explicit user approval.",
    }
    if write_effects:
        preview_response["write_effects"] = write_effects
    return _json(preview_response)


@mcp.tool()
async def zammad_apply_admin_change(plan_id: str, acknowledge_high_impact: bool = False) -> str:
    """Apply a prepared change after explicit user approval; stale plans are rejected."""
    if not isinstance(plan_id, str) or not plan_id:
        raise ValueError("plan_id is required")
    async with _PLAN_LOCK:
        _expire_plans(time.time())
        plan = _PLANS.pop(plan_id, None)
    if plan is None:
        raise ValueError("Unknown, expired, or already used plan_id")
    if plan["high_impact"] and not acknowledge_high_impact:
        raise ValueError("This change is high impact; acknowledge_high_impact=true is required")

    async with _WRITE_LOCK:
        snapshot_path = plan.get("snapshot_path")
        if plan["resource"] == "__ldap_connection_action__":
            current = await _get(f"/ldap_sources/{plan['object_id']}") if plan["object_id"] is not None else None
            current_fingerprint = _digest(current) if plan["fingerprint"] is not None else None
        elif plan["resource"] == "__ldap_import_action__":
            current = await _ldap_sources_snapshot()
            current_fingerprint = _digest(current)
        else:
            current = await _get(snapshot_path) if snapshot_path else await _snapshot(plan["resource"], plan["operation"], plan["object_id"])
            current_fingerprint = _snapshot_fingerprint(plan["resource"], current)
        if current_fingerprint != plan["fingerprint"]:
            raise RuntimeError("The resource changed after preview; prepare a new plan")
        for dependency in plan.get("dependencies", []):
            dependency_current = await _get(dependency["path"])
            if _digest(dependency_current) != dependency["fingerprint"]:
                raise RuntimeError("A related resource changed after preview; prepare a new plan")
        resource = plan["resource"]
        operation = plan["operation"]
        data = plan["data"]
        if resource == "__ldap_connection_action__":
            path = "/integration/ldap/discover" if operation == "discover" else "/integration/ldap/bind"
            payload = dict(data)
            if operation == "bind" and plan["object_id"] is not None:
                payload["ldap_source_id"] = plan["object_id"]
            result = await _request("POST", path, payload)
        elif resource == "__ldap_import_action__":
            if await _ldap_import_pending(operation):
                raise RuntimeError("An LDAP import job was queued or started after preview; prepare a new plan")
            path = "/integration/ldap/job_try" if operation == "dry_run" else "/integration/ldap/job_start"
            result = await _request("POST", path, {})
        elif resource == _SPECIAL_CHANNEL:
            result = await _request("POST", _SPECIAL_PATH, data)
        elif resource == _EMAIL_ACCOUNT_RESOURCE:
            result = await _request("POST", _EMAIL_ACCOUNT_VERIFY_PATH, data)
        elif resource == "email_channels":
            channel_id = plan["object_id"]
            if operation == "enable":
                result = await _request("POST", _EMAIL_CHANNEL_ENABLE_PATH, {"id": channel_id})
            elif operation == "disable":
                result = await _request("POST", _EMAIL_CHANNEL_DISABLE_PATH, {"id": channel_id})
            elif operation == "delete":
                result = await _request("DELETE", _SPECIAL_READ_PATH, {"id": channel_id})
            elif operation == "reassign":
                result = await _request("POST", f"{_EMAIL_CHANNEL_GROUP_PATH}/{channel_id}", data)
            else:
                raise ValueError("Unsupported email channel operation")
        elif resource == "facebook_channels":
            channel_id = plan["object_id"]
            if operation == "update":
                result = await _request("POST", f"/channels_facebook/{channel_id}", data)
            elif operation in {"enable", "disable"}:
                result = await _request("POST", f"/channels_facebook_{operation}", {"id": channel_id})
            elif operation == "delete":
                result = await _request("DELETE", "/channels_facebook", {"id": channel_id})
            else:
                raise ValueError("Unsupported Facebook channel operation")
        elif resource in _MESSAGE_CHANNEL_RESOURCES:
            spec = _resource(resource)
            if operation == "create":
                result = await _request("POST", spec.path, data)
            elif operation == "update":
                result = await _request("PUT", f"{spec.path}/{plan['object_id']}", data)
            elif operation == "delete":
                if resource == "telegram_channels":
                    result = await _request("DELETE", spec.path, {"id": plan["object_id"]})
                else:
                    result = await _request("DELETE", f"{spec.path}/{plan['object_id']}")
            elif operation in {"enable", "disable"}:
                active = operation == "enable"
                if resource == "whatsapp_channels":
                    action = "enable" if active else "disable"
                    result = await _request("POST", f"{spec.path}/{plan['object_id']}/{action}")
                else:
                    action_path = f"/{'channels_sms' if resource == 'sms_channels' else 'channels_telegram'}_{operation}"
                    result = await _request("POST", action_path, {"id": plan["object_id"]})
            elif operation == "test" and resource == "sms_channels":
                test_result = await _request("POST", "/channels_sms/test", data)
                result = {
                    "success": isinstance(test_result, Mapping) and test_result.get("success") is True,
                    "diagnostics_returned": False,
                }
            elif operation == "preload" and resource == "whatsapp_channels":
                result = await _request("POST", f"{spec.path}/preload", data)
            else:
                raise ValueError("Unsupported messaging channel operation")
        elif resource == "user_access_tokens" and operation == "create":
            token_response = await _request("POST", "/user_access_token", data)
            token_value = token_response.get("token") if isinstance(token_response, Mapping) else None
            if not isinstance(token_value, str) or not token_value:
                raise RuntimeError("Zammad accepted token creation without returning a retrievable token; inspect token metadata and revoke if needed")
            metadata = {key: data[key] for key in ("name", "permission", "expires_at") if key in data}
            stored_path = _store_generated_token(token_value, metadata)
            result = {
                "name": data["name"],
                "permission": data["permission"],
                "expires_at": data.get("expires_at"),
                "secret_file": str(stored_path),
                "file_mode": "0600",
                "token_value_returned": False,
            }
        elif resource == "__knowledge_base_settings__":
            result = await _request("PATCH", f"/knowledge_bases/manage/{plan['object_id']}", data)
        elif resource == "__knowledge_base_record__":
            result = await _request(plan["write_method"], plan["write_path"], data)
        else:
            spec = _resource(resource)
            if operation == "create":
                result = await _request("POST", spec.path, data)
            elif operation == "update":
                result = await _request("PUT", f"{spec.path}/{plan['object_id']}", data)
            elif operation == "delete":
                result = await _request("DELETE", f"{spec.path}/{plan['object_id']}")
            else:
                raise ValueError("Unsupported operation")
    if resource == "settings" and _is_sensitive_setting_name(plan.get("data", {}).get("name")):
        result = {"updated": True, "sensitive_value_returned": False}
    response_resource = {
        "__ldap_connection_action__": "ldap_connection_tests",
        "__ldap_import_action__": "ldap_import_actions",
    }.get(resource, resource)
    if resource == "__ldap_connection_action__":
        response_note = "Plan consumed. No LDAP configuration was saved. If the request timed out, check its status before retrying."
    elif resource == "__ldap_import_action__" and operation == "dry_run":
        response_note = "Plan consumed. A dry-run ImportJob was submitted; it does not save user or role changes. Read status before starting another dry run."
    elif resource == "__ldap_import_action__":
        response_note = "Plan consumed. A background LDAP sync was queued and may change users and roles. Read status before retrying."
    else:
        response_note = "Plan consumed. If the request timed out or returned an error, inspect Zammad before retrying."
    response = {"resource": response_resource, "operation": operation, "result": result, "note": response_note}
    return _json(_redact_exact_secrets(response, _collect_secret_literals(plan.get("data"))))


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
