"""Validated fields for staged external-credential configuration."""

import os
import re
from collections.abc import Mapping
from typing import Any


_FIELDS = {
    "application_id", "application_secret", "client_id", "client_secret", "client_tenant",
    "callback_url", "controller", "action", "provider",
}


def _secret_field(name: Any, credentials: Mapping[str, Any]) -> str:
    if name == "facebook" or ("application_secret" in credentials and "client_secret" not in credentials):
        return "application_secret"
    return "client_secret"


def validate_payload(operation: str, data: Any) -> None:
    allowed = {"name", "credentials"}
    if not isinstance(data, Mapping) or not data or set(data) - allowed:
        raise ValueError("external_credentials accepts name and credentials")
    if operation == "create" and not {"name", "credentials"}.issubset(data):
        raise ValueError("creating an external credential requires name and credentials")
    if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip()):
        raise ValueError("name must be a non-empty string")
    if "credentials" in data:
        credentials = data["credentials"]
        if not isinstance(credentials, Mapping) or not credentials or set(credentials) - _FIELDS:
            raise ValueError("credentials must contain supported provider fields")
        secret_field = _secret_field(data.get("name"), credentials)
        if secret_field not in credentials:
            raise ValueError(f"credentials replacement must include {secret_field}")
        if data.get("name") == "facebook" and not {"application_id", "application_secret"}.issubset(credentials):
            raise ValueError("Facebook credentials require application_id and application_secret")
        if data.get("name") in {"microsoft365", "microsoft_graph"} and not {"client_id", "client_secret"}.issubset(credentials):
            raise ValueError("Microsoft credentials require client_id and client_secret")
        for key, value in credentials.items():
            if key == secret_field:
                if not isinstance(value, Mapping) or set(value) != {"$secret_env"}:
                    raise ValueError(f"{secret_field} must use a process environment reference")
                env_name = value["$secret_env"]
                if not isinstance(env_name, str) or not re.fullmatch(r"(?:ZAMMAD|MCP)_SECRET_[A-Z0-9_]+", env_name):
                    raise ValueError(f"{secret_field} reference must name a ZAMMAD_SECRET_* or MCP_SECRET_* environment variable")
                if not os.environ.get(env_name):
                    raise ValueError(f"The referenced secret environment variable {env_name} is not configured")
            elif key in {"client_secret", "application_secret"}:
                raise ValueError(f"{key} cannot be supplied as an unused credential field")
            elif not isinstance(value, str):
                raise ValueError(f"credentials.{key} must be a string")


def materialize_payload(data: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved = dict(data)
    preview = dict(data)
    credentials = data.get("credentials")
    if isinstance(credentials, Mapping):
        secret_field = _secret_field(data.get("name"), credentials)
        reference = credentials[secret_field]["$secret_env"]
        secret = os.environ[reference]
        resolved["credentials"] = {**credentials, secret_field: secret}
        preview["credentials"] = {**credentials, secret_field: "[SECRET PROVIDED BY PROCESS ENVIRONMENT]"}
    return resolved, preview
