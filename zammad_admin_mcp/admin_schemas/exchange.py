"""Safe projections for Exchange integration data."""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


def project_exchange_integration_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid Exchange integration response")

    oauth = value.get("oauth")
    if oauth is not None and not isinstance(oauth, Mapping):
        raise RuntimeError("Zammad returned invalid Exchange OAuth metadata")

    credential_ids = value.get("external_credential_ids", [])
    if not isinstance(credential_ids, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 1
        for item in credential_ids
    ):
        raise RuntimeError("Zammad returned invalid Exchange credential metadata")

    return {
        "oauth_record_present": bool(oauth),
        "registered_application_count": len(credential_ids),
    }


def project_exchange_configuration(value: Any) -> dict[str, Any]:
    """Project the saved Exchange setting without returning contact examples."""
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid Exchange setting")

    projected = {str(key): item for key, item in value.items()}
    for state_key in ("state_current", "state_initial"):
        state = value.get(state_key)
        if not isinstance(state, Mapping):
            continue
        setting_value = state.get("value")
        if not isinstance(setting_value, Mapping):
            continue

        safe_config = {
            str(key): setting_value[key]
            for key in ("endpoint", "disable_ssl_verify", "user", "auth_type", "folders", "attributes")
            if key in setting_value
        }
        safe_config["password_configured"] = bool(setting_value.get("password"))
        safe_config["access_token_configured"] = bool(setting_value.get("access_token"))

        wizard_data = setting_value.get("wizardData")
        if isinstance(wizard_data, Mapping):
            backend_folders = wizard_data.get("backend_folders")
            backend_attributes = wizard_data.get("backend_attributes")
            safe_config["wizard_data_summary"] = {
                "backend_folder_count": len(backend_folders) if isinstance(backend_folders, (list, Mapping)) else 0,
                "backend_attribute_count": len(backend_attributes) if isinstance(backend_attributes, (list, Mapping)) else 0,
                "user_attribute_mapping_count": len(wizard_data.get("attributes", {}))
                if isinstance(wizard_data.get("attributes"), Mapping) else 0,
            }

        safe_state = {str(key): item for key, item in state.items()}
        safe_state["value"] = safe_config
        projected[state_key] = safe_state

    return projected


def prepare_exchange_dry_run_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("The saved Exchange configuration is missing")

    endpoint = value.get("endpoint")
    user = value.get("user")
    auth_type = value.get("auth_type", "basic")
    folders = value.get("folders")
    attributes = value.get("attributes")
    password = value.get("password")
    disable_ssl_verify = value.get("disable_ssl_verify", False)

    if not isinstance(endpoint, str) or not endpoint.strip() or len(endpoint) > 2048:
        raise ValueError("The saved Exchange endpoint is missing or invalid")
    try:
        parsed_endpoint = urlsplit(endpoint)
        hostname = parsed_endpoint.hostname
        parsed_endpoint.port
    except ValueError as exc:
        raise ValueError("The saved Exchange endpoint is invalid") from exc
    if parsed_endpoint.scheme not in {"http", "https"} or not hostname or parsed_endpoint.username or parsed_endpoint.password:
        raise ValueError("The saved Exchange endpoint must be an HTTP(S) URL without embedded credentials")
    if not isinstance(auth_type, str) or auth_type not in {"basic", "oauth"}:
        raise ValueError("The saved Exchange authentication method is invalid")
    if user is not None and (not isinstance(user, str) or len(user) > 320):
        raise ValueError("The saved Exchange user is invalid")
    if auth_type == "basic" and (not isinstance(user, str) or not user.strip()):
        raise ValueError("The saved Exchange user is missing")
    if auth_type == "basic" and (not isinstance(password, str) or not password):
        raise ValueError("The saved Exchange password is missing")
    if password is not None and not isinstance(password, str):
        raise ValueError("The saved Exchange password is invalid")
    if not isinstance(folders, list) or not 1 <= len(folders) <= 100 or any(
        not isinstance(folder, str) or not folder or len(folder) > 512 for folder in folders
    ):
        raise ValueError("The saved Exchange folder selection is missing or invalid")
    if len(set(folders)) != len(folders):
        raise ValueError("The saved Exchange folder selection contains duplicates")
    if not isinstance(attributes, Mapping) or not 1 <= len(attributes) <= 500 or any(
        not isinstance(source, str) or not source or len(source) > 256
        or not isinstance(target, str) or not target or len(target) > 256
        for source, target in attributes.items()
    ):
        raise ValueError("The saved Exchange attribute mapping is missing or invalid")
    if disable_ssl_verify not in (True, False, 0, 1, "0", "1"):
        raise ValueError("The saved Exchange TLS verification setting is invalid")

    payload = {
        "endpoint": endpoint,
        "auth_type": auth_type,
        "disable_ssl_verify": disable_ssl_verify in (True, 1, "1"),
        "folders": list(folders),
        "attributes": dict(attributes),
    }
    if user:
        payload["user"] = user
    if password is not None:
        payload["password"] = password
    return payload


def exchange_endpoint_host(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return host


def validate_exchange_connection_action(action: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("data must be a JSON object")
    if action == "autodiscover":
        if set(value) != {"user", "password"}:
            raise ValueError("autodiscover accepts only user and password")
        if not isinstance(value.get("user"), str) or "@" not in value["user"] or not value["user"].rsplit("@", 1)[1] or any(char.isspace() for char in value["user"]):
            raise ValueError("autodiscover user must be an email address")
        if not isinstance(value.get("password"), str) or not value["password"]:
            raise ValueError("autodiscover password is required")
        return {"user": value["user"], "password": value["password"]}

    allowed = {"endpoint", "user", "password", "auth_type", "disable_ssl_verify"}
    if action == "mapping":
        allowed.add("folders")
    required = {"endpoint", "auth_type"}
    if action == "mapping":
        required.add("folders")
    if set(value) - allowed or required - set(value):
        raise ValueError(f"{action} has missing or unsupported fields")

    endpoint = value.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip() or len(endpoint) > 2048:
        raise ValueError("endpoint is required")
    try:
        parts = urlsplit(endpoint)
        hostname = parts.hostname
        parts.port
    except ValueError as exc:
        raise ValueError("endpoint is invalid") from exc
    if parts.scheme not in {"http", "https"} or not hostname or parts.username or parts.password:
        raise ValueError("endpoint must be an HTTP(S) URL without embedded credentials")

    auth_type = value.get("auth_type")
    if not isinstance(auth_type, str) or auth_type not in {"basic", "oauth"}:
        raise ValueError("auth_type must be basic or oauth")
    user = value.get("user")
    if user is not None and (not isinstance(user, str) or len(user) > 320):
        raise ValueError("user is invalid")
    if auth_type == "basic" and (not isinstance(user, str) or not user.strip()):
        raise ValueError("basic authentication requires user")
    password = value.get("password")
    if auth_type == "basic" and (not isinstance(password, str) or not password):
        raise ValueError("basic authentication requires a password environment reference")
    if password is not None and not isinstance(password, str):
        raise ValueError("password must use a process environment reference")
    if auth_type == "oauth" and password is not None:
        raise ValueError("OAuth connection checks do not accept a password")
    verify = value.get("disable_ssl_verify", False)
    if verify not in (True, False, 0, 1, "0", "1"):
        raise ValueError("disable_ssl_verify must be a boolean")

    payload: dict[str, Any] = {
        "endpoint": endpoint,
        "auth_type": auth_type,
        "disable_ssl_verify": verify in (True, 1, "1"),
    }
    if user:
        payload["user"] = user
    if password is not None:
        payload["password"] = password
    if action == "mapping":
        folders = value.get("folders")
        if not isinstance(folders, list) or not 1 <= len(folders) <= 100 or any(
            not isinstance(folder, str) or not folder or len(folder) > 512 for folder in folders
        ) or len(set(folders)) != len(folders):
            raise ValueError("folders must be a unique list of 1 to 100 folder IDs")
        payload["folders"] = folders
    return payload


def project_exchange_connection_result(action: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid Exchange connection response")
    succeeded = value.get("result") == "ok"
    projected: dict[str, Any] = {"action": action, "status": "succeeded" if succeeded else "failed"}
    if not succeeded:
        return projected
    if action == "autodiscover":
        endpoint = value.get("endpoint")
        if isinstance(endpoint, str):
            try:
                host = exchange_endpoint_host(endpoint)
            except ValueError:
                host = ""
            if host:
                projected["endpoint_host"] = host
                return projected
        projected["status"] = "not_found"
        return projected
    if action == "folders":
        folders = value.get("folders")
        if not isinstance(folders, Mapping):
            raise RuntimeError("Zammad returned invalid Exchange folder data")
        projected["folders"] = [
            {"id": folder_id, "display_path": display_path}
            for folder_id, display_path in list(folders.items())[:500]
            if isinstance(folder_id, str) and isinstance(display_path, str)
        ]
        projected["truncated"] = len(folders) > 500
        return projected
    attributes = value.get("attributes")
    if not isinstance(attributes, Mapping):
        raise RuntimeError("Zammad returned invalid Exchange attribute data")
    projected["source_attributes"] = [
        name for name in list(attributes.keys())[:500] if isinstance(name, str)
    ]
    projected["truncated"] = len(attributes) > 500
    return projected


def project_exchange_import_status(value: Any, action: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        return {"action": action, "status": "not_found"}

    result = value.get("result") if isinstance(value.get("result"), Mapping) else {}
    count_keys = ("sum", "total", "created", "updated", "unchanged", "skipped", "failed", "deactivated")
    counts = {
        key: result[key]
        for key in count_keys
        if isinstance(result.get(key), int) and not isinstance(result.get(key), bool) and result[key] >= 0
    }
    finished = bool(value.get("finished_at"))
    has_error = bool(result.get("error"))
    has_info = bool(result.get("info"))
    failed = has_error or (action == "dry_run" and has_info)
    status = "failed" if failed else "finished" if finished else "running" if value.get("started_at") else "queued"
    return {
        "action": action,
        "status": status,
        "job_id": value.get("id") if isinstance(value.get("id"), int) and not isinstance(value.get("id"), bool) else None,
        "started_at": value.get("started_at"),
        "finished_at": value.get("finished_at"),
        "counts": counts,
        "has_error_detail": has_error,
        "has_info_detail": has_info,
    }
