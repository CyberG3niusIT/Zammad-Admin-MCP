from collections.abc import Mapping
from typing import Any

from zammad_admin_mcp.security import _is_sensitive_setting_name, _scrub


_FIELDS = (
    "id",
    "user_id",
    "user_fullname",
    "action_type",
    "auditable_type",
    "auditable_id",
    "auditable_name",
    "value_from",
    "value_to",
    "source_ip",
    "preferences",
    "created_at",
    "updated_at",
)


def _project_event(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return an audit log entry")

    event_id = value.get("id")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id <= 0:
        raise RuntimeError("Zammad returned an invalid audit log ID")

    value_from = value.get("value_from")
    value_to = value.get("value_to")
    if value_from is not None and not isinstance(value_from, Mapping):
        raise RuntimeError("Zammad returned invalid audit log before-values")
    if value_to is not None and not isinstance(value_to, Mapping):
        raise RuntimeError("Zammad returned invalid audit log after-values")

    sensitive_setting = value.get("auditable_type") == "Setting" and any(
        _is_sensitive_setting_name(name)
        for name in (
            value.get("auditable_name"),
            value_from.get("name") if isinstance(value_from, Mapping) else None,
            value_to.get("name") if isinstance(value_to, Mapping) else None,
        )
    )

    projected = {key: value[key] for key in _FIELDS if key in value}
    for field in ("value_from", "value_to", "preferences"):
        nested = projected.get(field)
        if nested is not None:
            projected[field] = "[REDACTED]" if sensitive_setting and field != "preferences" else _scrub(nested)
    return projected


def project_collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RuntimeError("Zammad did not return an audit log list")
    return [_project_event(item) for item in value]


def project_item(value: Any) -> dict[str, Any]:
    return _project_event(value)
