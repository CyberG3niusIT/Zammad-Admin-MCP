from collections.abc import Mapping
from typing import Any


def project_collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise RuntimeError("Zammad did not return an HTTP log list")

    result = []
    for item in value:
        object_id = item.get("id")
        facility = item.get("facility")
        if isinstance(object_id, bool) or not isinstance(object_id, int) or object_id <= 0:
            raise RuntimeError("Zammad returned an invalid HTTP log ID")
        if not isinstance(facility, str) or not facility:
            raise RuntimeError("Zammad returned an invalid HTTP log facility")

        projected = {"id": object_id, "facility": facility}
        for field in ("direction", "method", "created_at"):
            value = item.get(field)
            if value is not None:
                if not isinstance(value, str):
                    raise RuntimeError(f"Zammad returned an invalid HTTP log {field}")
                projected[field] = value
        result.append(projected)

    return result
