from collections.abc import Mapping
from typing import Any


_TASK_FIELDS = {"id", "state", "deletable_id", "deletable_type", "created_by_id", "created_at", "updated_at"}
_PREFERENCE_FIELDS = {
    "user", "ticket", "owner_tickets_count", "customer_tickets_count", "delete_organization",
}


def project_deletion_target(kind: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return the selected deletion target")
    fields = (
        {"id", "firstname", "lastname", "email", "login", "active", "organization_id"}
        if kind == "User"
        else {"id", "number", "title", "state_id", "customer_id", "owner_id"}
    )
    return {key: value[key] for key in fields if key in value}


def project_selector(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return a deletion impact preview")
    count = value.get("object_count")
    ids = value.get("object_ids")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise RuntimeError("Zammad returned an invalid deletion impact count")
    if not isinstance(ids, list) or any(isinstance(item, bool) or not isinstance(item, int) for item in ids):
        raise RuntimeError("Zammad returned invalid deletion impact identifiers")
    return {"object_count": count, "sample_ids": ids[:6]}


def project_task(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return a data privacy task")
    result = {key: value[key] for key in _TASK_FIELDS if key in value}
    preferences = value.get("preferences")
    if isinstance(preferences, Mapping):
        result["preferences"] = {
            key: preferences[key]
            for key in _PREFERENCE_FIELDS
            if key in preferences
        }
    return result


def project_collection(value: Any) -> Any:
    if isinstance(value, list):
        return [project_task(item) for item in value]
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return data privacy tasks")

    result = {
        key: nested
        for key, nested in value.items()
        if key not in {"assets", "items", "data_privacy_tasks"}
    }
    items = value.get("items", value.get("data_privacy_tasks"))
    if isinstance(items, list):
        result["items"] = [project_task(item) for item in items]
    assets = value.get("assets")
    if isinstance(assets, Mapping):
        tasks = assets.get("DataPrivacyTask")
        if isinstance(tasks, Mapping):
            result["assets"] = {
                "DataPrivacyTask": {
                    str(task_id): project_task(task)
                    for task_id, task in tasks.items()
                    if isinstance(task, Mapping)
                }
            }
    return result
