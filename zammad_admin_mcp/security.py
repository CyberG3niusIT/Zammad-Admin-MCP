from __future__ import annotations

import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

_SECRET_WORDS = {"password", "pass", "pw", "secret", "token", "credential", "authorization"}
_SETTING_SECRET_SUFFIXES = (
    "password", "passwd", "pass", "pw", "secret", "token", "credential", "credentials",
    "private_key", "client_secret", "consumer_secret", "secret_key", "signing_key", "api_key", "access_key",
    "certificate", "cert",
)


def _is_secret_field(key: str, value: Any) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower()
    if normalized == "callback_url_uuid":
        return True
    if normalized in {"user_access_tokens", "access_tokens", "tokens"} and isinstance(value, (Mapping, list)):
        return False
    words = set(re.findall(r"[a-z0-9]+", normalized))
    return (
        bool(words & _SECRET_WORDS)
        or normalized.endswith(("_pw", "_pass"))
        or "private_key" in normalized
        or ("api" in words and "key" in words)
    )


def _is_sensitive_setting_name(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    normalized = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return normalized.endswith(tuple(f"_{suffix}" for suffix in _SETTING_SECRET_SUFFIXES)) or normalized in _SETTING_SECRET_SUFFIXES


def _scrub(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if _is_secret_field(str(k), v) and v not in (None, "", False) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _materialize_secret_values(
    value: Any, *, secret_context: bool = False, sensitive_setting_value: bool = False,
) -> tuple[Any, Any]:
    if isinstance(value, Mapping) and set(value) == {"$secret_env"}:
        if not secret_context:
            raise ValueError("Secret environment references are accepted only in secret fields")
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
        setting_name = value.get("name")
        for key, item in value.items():
            setting_value_object = sensitive_setting_value and key == "value" and isinstance(item, Mapping)
            if setting_value_object and set(item) != {"$secret_env"}:
                raise ValueError("Structured values for sensitive settings are not supported without a setting-specific schema")
            child_is_secret = (
                (secret_context and not setting_value_object)
                or _is_secret_field(str(key), item)
                or (setting_value_object and set(item) == {"$secret_env"})
            )
            child_setting_value = key == "state_current" and isinstance(item, Mapping) and _is_sensitive_setting_name(setting_name)
            if sensitive_setting_value and key == "value" and not isinstance(item, Mapping):
                child_is_secret = True
            resolved_item, preview_item = _materialize_secret_values(
                item, secret_context=child_is_secret, sensitive_setting_value=child_setting_value,
            )
            if child_is_secret and item not in (None, "", False) and not isinstance(item, Mapping):
                raise ValueError(f"Secret field {key!r} must use a secure environment reference, not an inline value")
            resolved[str(key)] = resolved_item
            preview[str(key)] = preview_item
        return resolved, preview
    if isinstance(value, list):
        pairs = [_materialize_secret_values(item, secret_context=secret_context) for item in value]
        return [item[0] for item in pairs], [item[1] for item in pairs]
    return value, value


def _collect_secret_literals(
    value: Any, *, secret_context: bool = False, sensitive_setting_value: bool = False,
) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if secret_context and value:
            found.append(value)
        return found
    if isinstance(value, Mapping):
        setting_name = value.get("name")
        for key, item in value.items():
            setting_value_object = sensitive_setting_value and key == "value" and isinstance(item, Mapping)
            child_is_secret = (secret_context and not setting_value_object) or _is_secret_field(str(key), item)
            child_setting_value = key == "state_current" and isinstance(item, Mapping) and _is_sensitive_setting_name(setting_name)
            if sensitive_setting_value and key == "value" and not isinstance(item, Mapping):
                child_is_secret = True
            found.extend(_collect_secret_literals(
                item, secret_context=child_is_secret, sensitive_setting_value=child_setting_value,
            ))
    elif isinstance(value, list):
        for item in value:
            found.extend(_collect_secret_literals(item, secret_context=secret_context))
    return found


def _redact_exact_secrets(value: Any, secrets_to_redact: list[str]) -> Any:
    if isinstance(value, Mapping):
        return {key: _redact_exact_secrets(item, secrets_to_redact) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_exact_secrets(item, secrets_to_redact) for item in value]
    if isinstance(value, str):
        for secret in sorted(set(secrets_to_redact), key=len, reverse=True):
            if not secret:
                continue
            if value == secret:
                return "[REDACTED]"
            if len(secret) >= 8:
                value = value.replace(secret, "[REDACTED]")
            else:
                value = re.sub(
                    rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
                    "[REDACTED]",
                    value,
                )
    return value


def _project_settings(value: Any) -> Any:
    if isinstance(value, list):
        return [_project_settings(item) for item in value]
    if not isinstance(value, Mapping):
        return value
    projected = {str(key): _project_settings(item) for key, item in value.items()}
    if _is_sensitive_setting_name(value.get("name")):
        for state_key in ("state_current", "state_initial"):
            state = value.get(state_key)
            if not isinstance(state, Mapping) or "value" not in state:
                continue
            raw_value = state["value"]
            safe_state = dict(projected.get(state_key, {}))
            safe_state["value"] = "[REDACTED]"
            safe_state["value_configured"] = raw_value not in (None, "", [], {})
            projected[state_key] = safe_state
    return projected


def _validate_setting_secret_reference(data: Mapping[str, Any]) -> None:
    setting_name = data.get("name")
    value = data.get("state_current", {}).get("value") if isinstance(data.get("state_current"), Mapping) else None
    if not _is_sensitive_setting_name(setting_name) or value in (None, ""):
        return
    if isinstance(value, Mapping) and set(value) == {"$secret_env"}:
        return
    if isinstance(value, Mapping):
        raise ValueError("Structured values for sensitive settings are not supported without a setting-specific schema")
    raise ValueError("Secret settings must use a secure environment reference, not an inline value")


def _store_generated_token(token: str, metadata: Mapping[str, Any]) -> Path:
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
