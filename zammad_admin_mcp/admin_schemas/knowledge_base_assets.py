from collections.abc import Mapping
from typing import Any


_MODELS = {
    "knowledge_bases": "KnowledgeBase",
    "knowledge_base_translations": "KnowledgeBaseTranslation",
    "locales": "KnowledgeBaseLocale",
    "categories": "KnowledgeBaseCategory",
    "category_translations": "KnowledgeBaseCategoryTranslation",
    "answers": "KnowledgeBaseAnswer",
    "answer_translations": "KnowledgeBaseAnswerTranslation",
}


def _records(assets: Mapping[str, Any], model: str) -> list[Mapping[str, Any]]:
    values = assets.get(model, {})
    if not isinstance(values, Mapping):
        raise RuntimeError(f"Zammad returned invalid {model} assets")
    result = []
    for record_id, value in values.items():
        if not isinstance(value, Mapping):
            raise RuntimeError(f"Zammad returned an invalid {model} record")
        object_id = value.get("id")
        if isinstance(object_id, bool) or not isinstance(object_id, int) or object_id <= 0:
            raise RuntimeError(f"Zammad returned an invalid {model} ID")
        if str(object_id) != str(record_id):
            raise RuntimeError(f"Zammad returned a mismatched {model} ID")
        result.append(value)
    return sorted(result, key=lambda value: value["id"])


def _ids(value: Any, field: str) -> list[int]:
    if not isinstance(value, list):
        raise RuntimeError(f"Zammad returned invalid {field}")
    result = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise RuntimeError(f"Zammad returned invalid {field}")
        result.append(item)
    if len(result) != len(set(result)):
        raise RuntimeError(f"Zammad returned duplicate {field}")
    return result


def _relationship_id(value: Any, field: str, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuntimeError(f"Zammad returned invalid {field}")
    return value


def _named_translation(record: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {"id": record["id"]}
    for field in fields:
        if field not in record:
            raise RuntimeError("Zammad returned an incomplete Knowledge Base translation")
        value = record[field]
        if field == "title" and not isinstance(value, str):
            raise RuntimeError("Zammad returned invalid Knowledge Base translation title")
        if field.endswith("_id"):
            result[field] = _relationship_id(value, field)
        else:
            result[field] = value
    return result


def project_inventory(value: Any) -> dict[str, Any]:
    if value == []:
        assets: Mapping[str, Any] = {}
    elif not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return Knowledge Base assets")
    else:
        assets_value = value.get("assets")
        assets = assets_value if isinstance(assets_value, Mapping) else value

    knowledge_bases = []
    for record in _records(assets, _MODELS["knowledge_bases"]):
        projected: dict[str, Any] = {"id": record["id"]}
        if "active" in record:
            if not isinstance(record["active"], bool):
                raise RuntimeError("Zammad returned an invalid Knowledge Base active flag")
            projected["active"] = record["active"]
        if "kb_locale_ids" in record:
            projected["kb_locale_ids"] = _ids(record["kb_locale_ids"], "Knowledge Base locale IDs")
        if "category_ids" in record:
            projected["category_ids"] = _ids(record["category_ids"], "Knowledge Base category IDs")
        if "answer_ids" in record:
            projected["answer_ids"] = _ids(record["answer_ids"], "Knowledge Base answer IDs")
        knowledge_bases.append(projected)

    locales = []
    for record in _records(assets, _MODELS["locales"]):
        projected = {"id": record["id"]}
        for field in ("system_locale_id", "primary", "knowledge_base_id"):
            if field in record:
                item = record[field]
                if field.endswith("_id"):
                    item = _relationship_id(item, field)
                elif not isinstance(item, bool):
                    raise RuntimeError("Zammad returned an invalid Knowledge Base locale primary flag")
                projected[field] = item
        locales.append(projected)

    categories = []
    for record in _records(assets, _MODELS["categories"]):
        projected = {"id": record["id"]}
        for field in ("knowledge_base_id", "parent_id"):
            if field in record:
                projected[field] = _relationship_id(record[field], field, optional=field == "parent_id")
        for field in ("child_ids", "translation_ids", "answer_ids"):
            if field in record:
                projected[field] = _ids(record[field], field)
        if "category_icon" in record:
            if not isinstance(record["category_icon"], str):
                raise RuntimeError("Zammad returned an invalid Knowledge Base category icon")
            projected["category_icon"] = record["category_icon"]
        if "position" in record:
            position = record["position"]
            if isinstance(position, bool) or not isinstance(position, int):
                raise RuntimeError("Zammad returned an invalid Knowledge Base category position")
            projected["position"] = position
        categories.append(projected)

    answers = []
    for record in _records(assets, _MODELS["answers"]):
        projected = {"id": record["id"]}
        if "category_id" in record:
            projected["category_id"] = _relationship_id(record["category_id"], "answer category_id")
        if "translation_ids" in record:
            projected["translation_ids"] = _ids(record["translation_ids"], "answer translation IDs")
        answers.append(projected)

    return {
        "knowledge_bases": knowledge_bases,
        "knowledge_base_translations": [
            _named_translation(record, ("knowledge_base_id", "kb_locale_id", "title"))
            for record in _records(assets, _MODELS["knowledge_base_translations"])
        ],
        "locales": locales,
        "categories": categories,
        "category_translations": [
            _named_translation(record, ("category_id", "kb_locale_id", "title"))
            for record in _records(assets, _MODELS["category_translations"])
        ],
        "answers": answers,
        "answer_translations": [
            _named_translation(record, ("answer_id", "kb_locale_id", "title"))
            for record in _records(assets, _MODELS["answer_translations"])
        ],
        "scope": "Knowledge Base records available to the authenticated Zammad user",
        "answer_bodies_returned": False,
    }
