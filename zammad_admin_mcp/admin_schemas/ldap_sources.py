"""Validated LDAP source configuration for staged Zammad changes."""

import math
import os
import re
from collections.abc import Mapping
from typing import Any


_SOURCE_FIELDS = {"name", "active", "prio", "preferences"}
_PREFERENCE_FIELDS = {
    "host", "ssl", "ssl_verify", "base_dn", "bind_user", "bind_pw", "user_uid",
    "user_filter", "group_uid", "group_filter", "user_attributes", "group_role_map",
    "group_role_recursive", "unassigned_users", "disallow_bind_anon", "options", "option",
}
_SECRET_MASK = "**********"
_SECRET_ENV = re.compile(r"(?:ZAMMAD|MCP)_SECRET_[A-Z0-9_]+$")


def _json_value(value: Any, path: str, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError(f"{path} is nested too deeply")
    if isinstance(value, str):
        if len(value) > 100_000:
            raise ValueError(f"{path} is too long")
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must contain finite JSON numbers")
        return
    if isinstance(value, list):
        if len(value) > 500:
            raise ValueError(f"{path} has too many list entries")
        for index, item in enumerate(value):
            _json_value(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping) and len(value) <= 500 and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _json_value(item, f"{path}.{key}", depth + 1)
        return
    raise ValueError(f"{path} must contain bounded JSON-compatible values")


def _role_id(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("group_role_map values must contain positive role IDs")
    if isinstance(value, int):
        role_id = value
    elif isinstance(value, str) and value.isdigit():
        role_id = int(value)
    else:
        raise ValueError("group_role_map values must contain positive role IDs")
    if role_id <= 0:
        raise ValueError("group_role_map values must contain positive role IDs")
    return role_id


def role_ids(data: Mapping[str, Any]) -> set[int]:
    preferences = data.get("preferences")
    group_role_map = preferences.get("group_role_map") if isinstance(preferences, Mapping) else None
    if not isinstance(group_role_map, Mapping):
        return set()
    return {_role_id(role_id) for role_ids in group_role_map.values() for role_id in role_ids}


def validate_payload(operation: str, data: Any) -> None:
    if not isinstance(data, Mapping) or not data or set(data) - _SOURCE_FIELDS:
        raise ValueError("ldap_sources accepts name, active, prio, and preferences")
    if operation == "create" and not {"name", "preferences"}.issubset(data):
        raise ValueError("creating an LDAP source requires name and preferences")
    if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip() or len(data["name"]) > 100):
        raise ValueError("name must be a non-empty string of at most 100 characters")
    if "active" in data and not isinstance(data["active"], bool):
        raise ValueError("active must be a boolean")
    if "prio" in data and (isinstance(data["prio"], bool) or not isinstance(data["prio"], int) or data["prio"] < 0):
        raise ValueError("prio must be a non-negative integer")
    if "preferences" not in data:
        return
    preferences = data["preferences"]
    if not isinstance(preferences, Mapping) or set(preferences) - _PREFERENCE_FIELDS:
        raise ValueError("preferences contains unsupported LDAP configuration fields")
    required = {"host", "ssl", "ssl_verify", "base_dn", "bind_user", "bind_pw", "user_uid", "user_filter", "group_uid", "group_filter", "user_attributes", "group_role_map", "group_role_recursive", "unassigned_users"}
    if not required.issubset(preferences):
        raise ValueError("preferences replacement requires the complete LDAP source configuration")
    host = preferences["host"]
    if not isinstance(host, str) or not host.strip() or len(host) > 255 or any(char.isspace() for char in host) or any(char in host for char in "/@?#") or "://" in host:
        raise ValueError("host must be a hostname or address without a URL scheme or path")
    if not isinstance(preferences["ssl"], str) or preferences["ssl"] not in {"off", "ssl", "starttls"}:
        raise ValueError("ssl must be off, ssl, or starttls")
    if not isinstance(preferences["ssl_verify"], bool):
        raise ValueError("ssl_verify must be a boolean")
    if not isinstance(preferences["base_dn"], str):
        raise ValueError("base_dn must be a string")
    for key in ("user_uid", "group_uid"):
        if not isinstance(preferences[key], str) or not preferences[key].strip():
            raise ValueError(f"{key} must be a non-empty string")
    for key in ("bind_user", "user_filter", "group_filter"):
        if not isinstance(preferences[key], str):
            raise ValueError(f"{key} must be a string")
    bind_pw = preferences["bind_pw"]
    if bind_pw not in (None, "", _SECRET_MASK):
        if not isinstance(bind_pw, Mapping) or set(bind_pw) != {"$secret_env"}:
            raise ValueError("bind_pw must be empty or use a process environment reference")
        env_name = bind_pw["$secret_env"]
        if not isinstance(env_name, str) or not _SECRET_ENV.fullmatch(env_name) or not os.environ.get(env_name):
            raise ValueError("bind_pw must reference a configured ZAMMAD_SECRET_* or MCP_SECRET_* environment variable")
    if not isinstance(preferences["user_attributes"], Mapping) or not preferences["user_attributes"]:
        raise ValueError("user_attributes must map LDAP attributes to Zammad user fields")
    if any(not isinstance(source, str) or not source.strip() or not isinstance(target, str) or not target.strip() for source, target in preferences["user_attributes"].items()):
        raise ValueError("user_attributes keys and values must be non-empty strings")
    if "login" not in preferences["user_attributes"].values():
        raise ValueError("user_attributes must map at least one LDAP attribute to login")
    role_map = preferences["group_role_map"]
    recursive_map = preferences["group_role_recursive"]
    if not isinstance(role_map, Mapping) or not isinstance(recursive_map, Mapping):
        raise ValueError("group_role_map and group_role_recursive must be objects")
    if any(not isinstance(group, str) or not group.strip() or not isinstance(ids, list) or not ids for group, ids in role_map.items()):
        raise ValueError("group_role_map must map LDAP group names to non-empty role ID lists")
    for ids in role_map.values():
        for role_id in ids:
            _role_id(role_id)
    if set(recursive_map) != set(role_map) or any(not isinstance(value, bool) for value in recursive_map.values()):
        raise ValueError("group_role_recursive must contain one boolean for each mapped LDAP group")
    if not isinstance(preferences["unassigned_users"], str) or preferences["unassigned_users"] not in {"sigup_roles", "skip_sync"}:
        raise ValueError("unassigned_users must be sigup_roles or skip_sync")
    if "disallow_bind_anon" in preferences and not isinstance(preferences["disallow_bind_anon"], bool):
        raise ValueError("disallow_bind_anon must be a boolean")
    if "options" in preferences:
        options = preferences["options"]
        if not isinstance(options, Mapping) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in options.items()):
            raise ValueError("options must map naming-context strings to strings")
    if "option" in preferences:
        option = preferences["option"]
        options = preferences.get("options", {})
        if not isinstance(option, str) or (option and (not isinstance(options, Mapping) or option not in options)):
            raise ValueError("option must match one of the configured naming-context options")
    _json_value(preferences, "preferences")


def retain_existing_secret(data: Mapping[str, Any], before: Any) -> dict[str, Any]:
    result = dict(data)
    requested = data.get("preferences", {})
    current = before.get("preferences", {}) if isinstance(before, Mapping) else {}
    if not isinstance(requested, Mapping) or not isinstance(current, Mapping):
        return result
    preferences = dict(current)
    preferences.update(requested)
    bind_pw = requested.get("bind_pw")
    if "bind_pw" not in requested or bind_pw in ("[REDACTED]", _SECRET_MASK):
        existing = current.get("bind_pw")
        preferences["bind_pw"] = _SECRET_MASK if existing not in (None, "") else ""
    result["preferences"] = preferences
    return result


def materialize_payload(data: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = dict(data)
    preview = dict(data)
    preferences = data.get("preferences")
    if not isinstance(preferences, Mapping):
        return resolved, preview
    resolved_preferences = dict(preferences)
    preview_preferences = dict(preferences)
    bind_pw = preferences.get("bind_pw")
    if isinstance(bind_pw, Mapping):
        secret = os.environ[bind_pw["$secret_env"]]
        resolved_preferences["bind_pw"] = secret
        preview_preferences["bind_pw"] = "[SECRET PROVIDED BY PROCESS ENVIRONMENT]"
    elif bind_pw == _SECRET_MASK:
        preview_preferences["bind_pw"] = "[EXISTING SECRET RETAINED]"
    resolved["preferences"] = resolved_preferences
    preview["preferences"] = preview_preferences
    return resolved, preview
