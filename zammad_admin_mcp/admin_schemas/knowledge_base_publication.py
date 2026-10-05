from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


_TIMESTAMP_FIELDS = ("internal_at", "published_at", "archived_at")
_ACTOR_FIELDS = ("internal_by_id", "published_by_id", "archived_by_id")


def project_answer_snapshot(
    answer_value: Any,
    knowledge_base_id: int,
    answer_id: int,
    category_value: Any,
) -> dict[str, Any]:
    if not isinstance(answer_value, Mapping):
        raise RuntimeError("Zammad did not return a Knowledge Base answer")
    assets = answer_value.get("assets")
    answer_assets = assets.get("KnowledgeBaseAnswer") if isinstance(assets, Mapping) else None
    answer = answer_assets.get(str(answer_id)) if isinstance(answer_assets, Mapping) else None
    if not isinstance(answer, Mapping) or answer.get("id") != answer_id:
        raise RuntimeError("Zammad returned an invalid Knowledge Base answer")
    category_id = answer.get("category_id")
    if isinstance(category_id, bool) or not isinstance(category_id, int) or category_id <= 0:
        raise RuntimeError("Zammad returned an invalid Knowledge Base answer category")
    if not isinstance(category_value, Mapping):
        raise RuntimeError("Zammad did not return the Knowledge Base answer category")
    if category_value.get("id") != category_id or category_value.get("knowledge_base_id") != knowledge_base_id:
        raise ValueError("answer_id does not identify an answer in the selected Knowledge Base")

    result: dict[str, Any] = {"id": answer_id, "category_id": category_id}
    for field in _TIMESTAMP_FIELDS:
        value = answer.get(field)
        if value is not None and not isinstance(value, str):
            raise RuntimeError("Zammad returned an invalid Knowledge Base publication timestamp")
        result[field] = value
    for field in _ACTOR_FIELDS:
        value = answer.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
            raise RuntimeError("Zammad returned an invalid Knowledge Base publication actor")
        result[field] = value
    return result


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Publication timestamps must use ISO 8601 format") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Publication timestamps must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def current_state(snapshot: Mapping[str, Any], now: datetime | None = None) -> str:
    current_time = now or datetime.now(timezone.utc)
    for state in ("archived", "published", "internal"):
        value = snapshot.get(f"{state}_at")
        if isinstance(value, str) and _parse_timestamp(value) < current_time:
            return state
    return "draft"


def validate_transition(snapshot: Mapping[str, Any], action: str) -> str:
    state = current_state(snapshot)
    allowed = {
        "internal": {"draft"},
        "publish": {"draft", "internal"},
        "archive": {"internal", "published"},
        "unarchive": {"archived"},
    }
    if action not in allowed or state not in allowed[action]:
        raise ValueError(f"Knowledge Base answer cannot perform {action} from state {state}")
    if action == "unarchive":
        return "published" if snapshot.get("published_at") is not None else "internal"
    return {"internal": "internal", "publish": "published", "archive": "archived"}[action]


def validate_schedule_updates(
    value: Any,
    snapshot: Mapping[str, Any],
    now: datetime | None = None,
) -> tuple[dict[str, str | None], dict[str, Any]]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("updates must be a non-empty object")
    unknown = set(value) - set(_TIMESTAMP_FIELDS)
    if unknown:
        raise ValueError(f"Unsupported publication fields: {', '.join(sorted(unknown))}")

    current_time = now or datetime.now(timezone.utc)
    request: dict[str, str | None] = {}
    effective: dict[str, datetime | None] = {}
    after: dict[str, Any] = {"id": snapshot["id"], "category_id": snapshot["category_id"]}
    for field in _TIMESTAMP_FIELDS:
        before_value = snapshot.get(field)
        before_time = _parse_timestamp(before_value) if isinstance(before_value, str) else None
        raw = value.get(field, before_value)
        if field in value:
            if raw is not None and raw != "--now--" and not isinstance(raw, str):
                raise ValueError(f"{field} must be an ISO 8601 timestamp, --now--, or null")
            if isinstance(raw, str) and raw != "--now--":
                parsed = _parse_timestamp(raw)
                if parsed < current_time:
                    raise ValueError("Scheduled publication timestamps must be in the future; use --now-- for immediate changes")
                request[field] = raw
                effective[field] = parsed
                after[field] = raw
            elif raw == "--now--":
                request[field] = raw
                effective[field] = current_time
                after[field] = current_time.isoformat().replace("+00:00", "Z")
            else:
                request[field] = None
                effective[field] = None
                after[field] = None
        else:
            effective[field] = before_time
            after[field] = before_value

    internal_at = effective["internal_at"]
    published_at = effective["published_at"]
    archived_at = effective["archived_at"]
    if internal_at is not None and published_at is not None and published_at < internal_at:
        raise ValueError("published_at must not be earlier than internal_at")
    if internal_at is not None and archived_at is not None and archived_at < internal_at:
        raise ValueError("archived_at must not be earlier than internal_at")
    if published_at is not None and archived_at is not None and archived_at < published_at:
        raise ValueError("archived_at must not be earlier than published_at")
    if all(after[field] == snapshot.get(field) for field in _TIMESTAMP_FIELDS):
        raise ValueError("Publication timestamps already match the requested values")
    return request, after
