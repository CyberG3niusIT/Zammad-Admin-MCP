"""Validated LDAP connection-check inputs for explicit staged actions."""

from collections.abc import Mapping
import os
import re
from typing import Any


_SECRET_MASK = "**********"
_SECRET_ENV = re.compile(r"(?:ZAMMAD|MCP)_SECRET_[A-Z0-9_]+$")


def _host(value: Any) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 255 or any(char.isspace() for char in value) or any(char in value for char in "/@?#") or "://" in value:
        raise ValueError("host must be a hostname or address without a URL scheme or path")


def retain_source_values(data: Mapping[str, Any], source: Any) -> dict[str, Any]:
    result = dict(data)
    preferences = source.get("preferences", {}) if isinstance(source, Mapping) else {}
    if not isinstance(preferences, Mapping):
        return result
    for key in ("host", "ssl", "ssl_verify", "base_dn", "bind_user"):
        if key not in result and key in preferences:
            result[key] = preferences[key]
    if "bind_pw" not in data or result.get("bind_pw") in ("[REDACTED]", _SECRET_MASK):
        current = preferences.get("bind_pw")
        result["bind_pw"] = _SECRET_MASK if current not in (None, "") else ""
    elif result["bind_pw"] == "[REDACTED]":
        result["bind_pw"] = _SECRET_MASK
    return result


def materialize_payload(data: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = dict(data)
    preview = dict(data)
    bind_pw = data.get("bind_pw")
    if isinstance(bind_pw, Mapping):
        secret = os.environ[bind_pw["$secret_env"]]
        resolved["bind_pw"] = secret
        preview["bind_pw"] = "[SECRET PROVIDED BY PROCESS ENVIRONMENT]"
    elif bind_pw == _SECRET_MASK:
        preview["bind_pw"] = "[EXISTING SECRET RETAINED]"
    return resolved, preview


def validate_payload(action: str, data: Any) -> None:
    if not isinstance(data, Mapping):
        raise ValueError("data must be a JSON object")
    if action == "discover":
        allowed = {"name", "host", "ssl", "ssl_verify", "active"}
        if set(data) - allowed or not {"name", "host", "ssl", "ssl_verify"}.issubset(data):
            raise ValueError("discover requires name, host, ssl, and ssl_verify")
        if not isinstance(data["name"], str) or not data["name"].strip() or len(data["name"]) > 100:
            raise ValueError("name must be a non-empty string of at most 100 characters")
        _host(data["host"])
        if not isinstance(data["ssl"], str) or data["ssl"] not in {"off", "ssl", "starttls"}:
            raise ValueError("ssl must be off, ssl, or starttls")
        if not isinstance(data["ssl_verify"], bool):
            raise ValueError("ssl_verify must be a boolean")
        if "active" in data and not isinstance(data["active"], bool):
            raise ValueError("active must be a boolean")
        return
    if action != "bind":
        raise ValueError("unsupported LDAP connection action")
    allowed = {"host", "ssl", "ssl_verify", "base_dn", "bind_user", "bind_pw"}
    if set(data) - allowed or not allowed.issubset(data):
        raise ValueError("bind requires host, ssl, ssl_verify, base_dn, bind_user, and bind_pw")
    _host(data["host"])
    if not isinstance(data["ssl"], str) or data["ssl"] not in {"off", "ssl", "starttls"}:
        raise ValueError("ssl must be off, ssl, or starttls")
    if not isinstance(data["ssl_verify"], bool):
        raise ValueError("ssl_verify must be a boolean")
    if not isinstance(data["base_dn"], str) or not isinstance(data["bind_user"], str):
        raise ValueError("base_dn and bind_user must be strings")
    bind_pw = data["bind_pw"]
    if bind_pw not in (None, "", _SECRET_MASK):
        if not isinstance(bind_pw, Mapping) or set(bind_pw) != {"$secret_env"}:
            raise ValueError("bind_pw must be empty or use a process environment reference")
        env_name = bind_pw["$secret_env"]
        if not isinstance(env_name, str) or not _SECRET_ENV.fullmatch(env_name) or not os.environ.get(env_name):
            raise ValueError("bind_pw must reference a configured ZAMMAD_SECRET_* or MCP_SECRET_* environment variable")
