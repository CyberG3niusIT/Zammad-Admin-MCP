from collections.abc import Mapping
from typing import Any

from zammad_admin_mcp.security import _is_secret_field


def project_history(value: Any, limit: int) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not isinstance(value.get("history"), list):
        raise RuntimeError("Zammad did not return a valid user history")

    history = value["history"]
    selected = history[-limit:]
    items = []
    for entry in selected:
        if not isinstance(entry, Mapping):
            continue
        item = {
            key: entry[key]
            for key in ("id", "type", "object", "attribute", "created_at", "created_by_id", "sourceable_type", "sourceable_id")
            if key in entry
        }
        attribute = entry.get("attribute")
        secret_attribute = isinstance(attribute, str) and _is_secret_field(attribute, None)
        for field in ("value_from", "value_to"):
            if field in entry:
                item[field] = "[REDACTED]" if secret_attribute and entry[field] not in (None, "") else entry[field]
        for field in ("id_from", "id_to"):
            if field in entry:
                item[field] = entry[field]
        if secret_attribute:
            item["values_redacted"] = any(entry.get(field) not in (None, "") for field in ("value_from", "value_to"))
        items.append(item)

    return {
        "history_count": len(history),
        "returned": len(items),
        "omitted_older_count": max(0, len(history) - len(items)),
        "assets_returned": False,
        "items": items,
    }
