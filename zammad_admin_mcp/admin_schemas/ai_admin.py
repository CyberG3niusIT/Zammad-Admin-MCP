import json
from collections.abc import Mapping
from typing import Any


_AGENT_FIELDS = {
    "name", "agent_type", "type_enrichment_data", "definition", "action_definition", "note", "active",
}
_TEXT_TOOL_FIELDS = {"name", "instruction", "group_ids", "note", "active"}
_MAX_JSON_BYTES = 1024 * 1024


def _validate_json_size(value: Mapping[str, Any]) -> None:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("AI configuration must contain JSON-compatible values") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("AI configuration must be no larger than 1 MiB")


def validate_payload(resource: str, operation: str, value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise ValueError("AI configuration must be a JSON object")
    allowed = _AGENT_FIELDS if resource == "ai_agents" else _TEXT_TOOL_FIELDS
    if set(value) - allowed:
        raise ValueError(f"Unsupported {resource.replace('_', ' ')} fields: {', '.join(sorted(set(value) - allowed))}")
    data = dict(value)
    if operation == "create":
        required = {"name", "agent_type"} if resource == "ai_agents" else {"name", "instruction"}
        if not required.issubset(data):
            raise ValueError(f"Create requires: {', '.join(sorted(required))}")
    if "name" in data:
        max_name = 250 if resource == "ai_agents" else 100
        if not isinstance(data["name"], str) or not data["name"].strip() or len(data["name"]) > max_name:
            raise ValueError(f"name must be a non-empty string of at most {max_name} characters")
    if "note" in data and data["note"] is not None and (not isinstance(data["note"], str) or len(data["note"]) > 250):
        raise ValueError("note must be null or a string of at most 250 characters")
    if "active" in data and not isinstance(data["active"], bool):
        raise ValueError("active must be a boolean")

    if resource == "ai_agents":
        if "agent_type" in data and (not isinstance(data["agent_type"], str) or not data["agent_type"] or len(data["agent_type"]) > 250):
            raise ValueError("agent_type must be a non-empty type name of at most 250 characters")
        for field in ("type_enrichment_data", "definition", "action_definition"):
            if field in data and not isinstance(data[field], Mapping):
                raise ValueError(f"{field} must be a JSON object")
    else:
        if "instruction" in data and (not isinstance(data["instruction"], str) or not data["instruction"] or len(data["instruction"].encode("utf-8")) > _MAX_JSON_BYTES):
            raise ValueError("instruction must be non-empty text no larger than 1 MiB")
        if "group_ids" in data:
            group_ids = data["group_ids"]
            if not isinstance(group_ids, list) or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in group_ids):
                raise ValueError("group_ids must be a list of positive integers")
            if len(group_ids) != len(set(group_ids)):
                raise ValueError("group_ids must not contain duplicates")

    _validate_json_size(data)
    return data, dict(data)


def project_object(resource: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return an AI configuration object")
    fields = _AGENT_FIELDS | {"id", "created_at", "updated_at"} if resource == "ai_agents" else _TEXT_TOOL_FIELDS | {"id", "created_at", "updated_at"}
    return {key: value[key] for key in fields if key in value}


def project_collection(resource: str, value: Any) -> Any:
    if isinstance(value, list):
        return [project_object(resource, item) for item in value]
    if isinstance(value, Mapping) and isinstance(value.get("items"), list):
        return {**value, "items": [project_object(resource, item) for item in value["items"]]}
    raise RuntimeError("Zammad did not return an AI configuration list")


def project_agent_types(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise RuntimeError("Zammad did not return AI agent type schemas")
    fields = {"id", "name", "description", "custom", "definition", "action_definition", "form_schema", "placeholder_field_names"}
    return [{key: item[key] for key in fields if key in item} for item in value]
