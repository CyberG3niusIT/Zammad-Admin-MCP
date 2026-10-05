"""Zammad administrative MCP with allowlisted reads and staged writes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

@dataclass(frozen=True)
class Resource:
    path: str
    operations: frozenset[str] = frozenset({"create", "update", "delete"})
    risk: str = "Configuration change; inspect the preview before approval."
    high_impact: bool = False
    item: bool = True


# Paths and methods are server-owned. There is deliberately no arbitrary API tool.
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
    # Zammad's admin UI uses the Settings REST controller for configuration forms.
    # Restrict writes to a setting's current value; do not expose an arbitrary route.
    "settings": Resource("/settings", operations=frozenset({"update"}), risk="May change authentication, integrations, security, or service behavior.", high_impact=True),
}

# This endpoint is intentionally special: its POST sends a real test email and saves settings.
_SPECIAL_CHANNEL = "email_notification"
_SPECIAL_PATH = "/channels_email_notification"
_SPECIAL_READ_PATH = "/channels_email"
_EMAIL_ACCOUNT_RESOURCE = "email_account"
_EMAIL_ACCOUNT_VERIFY_PATH = "/channels_email_verify"
_EMAIL_CHANNEL_ENABLE_PATH = "/channels_email_enable"
_EMAIL_CHANNEL_DISABLE_PATH = "/channels_email_disable"
_EMAIL_CHANNEL_GROUP_PATH = "/channels_email_group"
_SECRET_WORDS = {"password", "pass", "pw", "secret", "token", "credential", "authorization"}
_PLAN_TTL_SECONDS = 300
_MAX_PLANS = 100
_PLANS: dict[str, dict[str, Any]] = {}
_PLAN_LOCK = asyncio.Lock()
_WRITE_LOCK = asyncio.Lock()
_PLAN_CLEANER: asyncio.Task[None] | None = None

mcp = FastMCP("zammad-admin")


def _api_root() -> str:
    raw_url = os.environ.get("ZAMMAD_URL", "").strip()
    token = os.environ.get("ZAMMAD_HTTP_TOKEN", "").strip()
    if not raw_url or not token:
        raise ValueError("ZAMMAD_URL and ZAMMAD_HTTP_TOKEN must be configured")
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ZAMMAD_URL must be an absolute HTTP or HTTPS URL")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("ZAMMAD_URL must use HTTPS unless it targets a loopback address")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("ZAMMAD_URL must not contain credentials, a query, or a fragment")
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v1"):
        path = f"{path}/api/v1" if path else "/api/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _headers() -> dict[str, str]:
    token = os.environ.get("ZAMMAD_HTTP_TOKEN", "").strip()
    if not token:
        raise ValueError("ZAMMAD_HTTP_TOKEN must be configured")
    return {"Authorization": f"Token token={token}", "Accept": "application/json"}


def _validate_id(object_id: int | None) -> int:
    if isinstance(object_id, bool) or not isinstance(object_id, int) or object_id <= 0:
        raise ValueError("object_id must be a positive integer")
    return object_id


def _is_secret_field(key: str, value: Any) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower()
    if normalized in {"user_access_tokens", "access_tokens", "tokens"} and isinstance(value, (Mapping, list)):
        return False
    words = set(re.findall(r"[a-z0-9]+", normalized))
    return (
        bool(words & _SECRET_WORDS)
        or normalized.endswith(("_pw", "_pass"))
        or "private_key" in normalized
        or ("api" in words and "key" in words)
    )


def _scrub(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if _is_secret_field(str(k), v) and v not in (None, "", False) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _materialize_secret_values(value: Any) -> tuple[Any, Any]:
    """Resolve explicit process-environment references without putting secrets in tool arguments."""
    if isinstance(value, Mapping) and set(value) == {"$secret_env"}:
        env_name = value["$secret_env"]
        if not isinstance(env_name, str) or not re.fullmatch(r"(?:ZAMMAD|MCP)_SECRET_[A-Z0-9_]+", env_name):
            raise ValueError("Secret references must name a ZAMMAD_SECRET_* or MCP_SECRET_* environment variable")
        secret = os.environ.get(env_name)
        if not secret:
            raise ValueError(f"The referenced secret environment variable {env_name} is not configured")
        return secret, "[SECRET PROVIDED BY PROCESS ENVIRONMENT]"
    if isinstance(value, Mapping):
        resolved: dict[str, Any] = {}
        preview: dict[str, Any] = {}
        for key, item in value.items():
            resolved_item, preview_item = _materialize_secret_values(item)
            if (
                _is_secret_field(str(key), item)
                and item not in (None, "", False)
                and not isinstance(item, Mapping)
            ):
                raise ValueError(f"Secret field {key!r} must use a secure environment reference, not an inline value")
            resolved[str(key)] = resolved_item
            preview[str(key)] = preview_item
        return resolved, preview
    if isinstance(value, list):
        pairs = [_materialize_secret_values(item) for item in value]
        return [x[0] for x in pairs], [x[1] for x in pairs]
    return value, value


def _validate_setting_secret_reference(data: Mapping[str, Any]) -> None:
    setting_name = data.get("name")
    value = data.get("state_current", {}).get("value") if isinstance(data.get("state_current"), Mapping) else None
    if isinstance(setting_name, str) and _is_secret_field(setting_name, value) and not isinstance(value, Mapping):
        if value not in (None, ""):
            raise ValueError("Secret settings must use a secure environment reference, not an inline value")


def _store_generated_token(token: str, metadata: Mapping[str, Any]) -> Path:
    """Write a one-time token using directory-relative, no-follow file operations."""
    raw_directory = os.environ.get("ZAMMAD_TOKEN_STORE_DIR", "").strip()
    directory = Path(raw_directory).expanduser() if raw_directory else Path.home() / ".config" / "zammad-admin-mcp" / "tokens"
    if not directory.is_absolute():
        raise RuntimeError("Token store directory must be absolute")
    directory = Path(os.path.abspath(directory))
    project_root = Path(__file__).resolve().parents[1]
    if directory == project_root or project_root in directory.parents:
        raise RuntimeError("Token store must be outside the project directory")
    root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    current_fd = root_fd
    try:
        parts = directory.parts[1:]
        for index, part in enumerate(parts):
            try:
                os.mkdir(part, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current_fd)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
            if index == len(parts) - 1:
                directory_info = os.fstat(current_fd)
                if directory_info.st_uid != os.getuid() or stat.S_IMODE(directory_info.st_mode) != 0o700:
                    raise RuntimeError("Token store directory must be owned by the MCP user with mode 0700")
        if not parts:
            raise RuntimeError("Token store directory must not be the filesystem root")
        label = re.sub(r"[^A-Za-z0-9._-]+", "-", str(metadata.get("name", "token"))).strip("-._")[:32] or "token"
        filename = f"{label}-{secrets.token_urlsafe(12)}.json"
        descriptor = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=current_fd,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump({**dict(metadata), "token": token}, output, ensure_ascii=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            file_info = os.stat(filename, dir_fd=current_fd, follow_symlinks=False)
            if not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.getuid() or stat.S_IMODE(file_info.st_mode) != 0o600:
                raise RuntimeError("Token file permissions are not owner-only")
            os.fsync(current_fd)
        except Exception:
            try:
                os.unlink(filename, dir_fd=current_fd)
                os.fsync(current_fd)
            except OSError:
                pass
            raise
        return directory / filename
    except Exception as exc:
        if isinstance(exc, RuntimeError) and str(exc).startswith("Token store directory"):
            raise
        raise RuntimeError("Zammad created a token but secure local storage failed; inspect token metadata and revoke it if needed") from None
    finally:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)


def _json(value: Any) -> str:
    return json.dumps(_scrub(value), ensure_ascii=False, indent=2, sort_keys=True)


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _snapshot_fingerprint(resource: str, value: Any) -> str:
    # Token last_used_at/updated_at changes merely by reading the token endpoint.
    # Fingerprint its permission catalog and existing IDs so ordinary MCP reads do not stale a plan.
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


def _validate_token_create_payload(data: Any, snapshot: Any) -> None:
    if not isinstance(data, dict) or set(data) - {"name", "permission", "expires_at"}:
        raise ValueError("Token creation accepts only name, permission, and optional expires_at")
    name = data.get("name")
    permissions = data.get("permission")
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        raise ValueError("Token name must be a non-empty string of at most 100 characters")
    if not isinstance(permissions, list) or not permissions or any(not isinstance(item, str) for item in permissions):
        raise ValueError("permission must be a non-empty array of permission names")
    allowed = {
        item["name"] for item in snapshot.get("permissions", [])
        if isinstance(item, Mapping) and item.get("active") is True and isinstance(item.get("name"), str)
    } if isinstance(snapshot, Mapping) else set()
    unknown = sorted(set(permissions) - allowed)
    if unknown:
        raise ValueError("Unknown or inactive token permissions: " + ", ".join(unknown))
    if len(set(permissions)) != len(permissions):
        raise ValueError("permission must not contain duplicates")
    expiry = data.get("expires_at")
    if expiry is not None:
        if not isinstance(expiry, str):
            raise ValueError("expires_at must be an ISO date (YYYY-MM-DD)")
        try:
            date.fromisoformat(expiry)
        except ValueError as exc:
            raise ValueError("expires_at must be a valid ISO date (YYYY-MM-DD)") from exc


def _resource(resource: str) -> Resource:
    try:
        return _RESOURCES[resource]
    except KeyError as exc:
        raise ValueError("Unsupported Zammad admin resource") from exc


async def _request(method: str, path: str, payload: Any = None, params: dict[str, int] | None = None) -> Any:
    # Defense in depth: only fixed registered collection/item routes are accepted.
    allowed = {
        "/version", _SPECIAL_READ_PATH, _SPECIAL_PATH, _EMAIL_ACCOUNT_VERIFY_PATH,
        _EMAIL_CHANNEL_ENABLE_PATH, _EMAIL_CHANNEL_DISABLE_PATH, "/roles?expand=true",
    }
    email_group_path = bool(re.fullmatch(r"/channels_email_group/\d+", path))
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
    if path not in allowed and not email_group_path and not item_path and not knowledge_base_path and not knowledge_base_settings_path:
        raise ValueError("Unsupported Zammad API resource")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Unsupported Zammad API method")
    async with httpx.AsyncClient(
        base_url=_api_root(), headers={**_headers(), "Content-Type": "application/json"},
        timeout=httpx.Timeout(30.0), follow_redirects=False,
    ) as client:
        response = await client.request(method, path.lstrip("/"), json=payload, params=params)
    if response.is_redirect:
        raise RuntimeError("Zammad redirected an API request; check ZAMMAD_URL")
    if response.status_code >= 400:
        raise RuntimeError(f"Zammad API request failed with HTTP {response.status_code}; check endpoint, payload, and token permissions")
    if not response.content:
        return {}
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError("Zammad returned a non-JSON API response") from exc


async def _get(path: str, params: dict[str, int] | None = None) -> Any:
    return await _request("GET", path, params=params)


@mcp.tool()
async def zammad_server_version() -> str:
    """Read the version of the connected Zammad instance."""
    return _json(await _get("/version"))


@mcp.tool()
async def zammad_list_admin_resources() -> str:
    """List API-backed administration resource names currently allowlisted by this MCP."""
    return _json({name: {"operations": sorted(spec.operations), "risk": spec.risk} for name, spec in _RESOURCES.items()} | {
        _SPECIAL_CHANNEL: {"operations": ["configure"], "risk": "POST sends a real test email and saves the active notification channel."},
        _EMAIL_ACCOUNT_RESOURCE: {"operations": ["configure"], "risk": "Verifies inbound/outbound mail, sends a test message, saves the mailbox, and starts mail fetching."},
        "email_channels": {"operations": ["read", "enable", "disable", "delete", "reassign"], "risk": "Lists metadata; writes change inbound mailbox state and can alter ticket creation."},
        "knowledge_base_settings": {"operations": ["update"], "risk": "Preview/apply by knowledge_base_id; explicit confirmation required."},
        "knowledge_base_answers": {"operations": ["read", "create", "update", "delete"], "risk": "Content writes are high impact and require explicit confirmation."},
        "knowledge_base_categories": {"operations": ["read", "create", "update", "delete"], "risk": "Content writes are high impact and require explicit confirmation."},
    })


@mcp.tool()
async def zammad_list_admin_resource(resource: str, page: int = 1, per_page: int = 100) -> str:
    """List one page from a fixed allowlisted Zammad admin resource."""
    if isinstance(page, bool) or page < 1:
        raise ValueError("page must be a positive integer")
    if isinstance(per_page, bool) or not 1 <= per_page <= 100:
        raise ValueError("per_page must be between 1 and 100")
    params = {"page": page, "per_page": per_page}
    if resource in {_SPECIAL_CHANNEL, "email_channels"}:
        return _json(await _get(_SPECIAL_READ_PATH, params))
    spec = _resource(resource)
    return _json(await _get(spec.path, params))


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
    return _json(await _get(f"{spec.path}/{object_id}"))


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
    if resource == "__knowledge_base_settings__":
        return await _get(f"/knowledge_bases/{_validate_id(object_id)}")
    spec = _resource(resource)
    if operation == "create":
        return await _get(spec.path)
    return await _get(f"{spec.path}/{_validate_id(object_id)}")


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


def _email_account_preview(before: Any, data: Mapping[str, Any]) -> dict[str, Any]:
    channel_id = data.get("channel_id")
    assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    current = None
    if channel_id is not None and isinstance(channel_assets, Mapping):
        current = channel_assets.get(str(channel_id), channel_assets.get(channel_id))
    summary = {
        "account_channel_ids": before.get("account_channel_ids", []) if isinstance(before, Mapping) else [],
        "notification_channel_ids": before.get("notification_channel_ids", []) if isinstance(before, Mapping) else [],
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
    operation: Literal["create", "update", "delete", "configure", "enable", "disable", "reassign"],
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

    data, preview_data = _materialize_secret_values(data) if data is not None else (None, None)

    before = await _snapshot(resource, operation, object_id)
    if resource == "user_access_tokens" and operation == "create":
        _validate_token_create_payload(data, before)
    dependencies: list[dict[str, str]] = []
    group_id = None
    if resource == _EMAIL_ACCOUNT_RESOURCE:
        group_id = data["group_id"]
    elif resource == "email_channels" and operation == "reassign":
        group_id = data["group_id"]
    if group_id is not None:
        group_before = await _get(f"/groups/{_validate_id(group_id)}")
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
    if operation in {"update", "delete"} and not isinstance(before, Mapping):
        raise RuntimeError("The Zammad API did not return an object snapshot")
    if resource == "settings" and data.get("name") != before.get("name"):
        raise ValueError("settings name must match the selected setting ID")
    if operation == "create":
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
    elif operation in {"update", "configure"}:
        after = _merge_preview(before, preview_data or {})
    else:
        after = None
    if resource not in {_EMAIL_ACCOUNT_RESOURCE, "email_channels"}:
        before_preview = before

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

    return _json({
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
    })


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
        current = await _get(snapshot_path) if snapshot_path else await _snapshot(plan["resource"], plan["operation"], plan["object_id"])
        if _snapshot_fingerprint(plan["resource"], current) != plan["fingerprint"]:
            raise RuntimeError("The resource changed after preview; prepare a new plan")
        for dependency in plan.get("dependencies", []):
            dependency_current = await _get(dependency["path"])
            if _digest(dependency_current) != dependency["fingerprint"]:
                raise RuntimeError("A related resource changed after preview; prepare a new plan")
        resource = plan["resource"]
        operation = plan["operation"]
        data = plan["data"]
        if resource == _SPECIAL_CHANNEL:
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
    return _json({"resource": resource, "operation": operation, "result": result, "note": "Plan consumed. If the request timed out or returned an error, inspect Zammad before retrying."})


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
