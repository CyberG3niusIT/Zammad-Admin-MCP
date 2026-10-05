from collections.abc import Mapping
from typing import Any, Literal


def project_siblings(
    inventory: Mapping[str, Any],
    knowledge_base_id: int,
    kind: Literal["root_categories", "categories", "answers"],
    category_id: int | None,
) -> dict[str, Any]:
    knowledge_bases = inventory.get("knowledge_bases")
    categories = inventory.get("categories")
    answers = inventory.get("answers")
    if not isinstance(knowledge_bases, list) or not isinstance(categories, list) or not isinstance(answers, list):
        raise RuntimeError("Zammad returned an incomplete Knowledge Base ordering inventory")
    bases = [item for item in knowledge_bases if isinstance(item, Mapping) and item.get("id") == knowledge_base_id]
    if len(bases) != 1:
        raise ValueError("knowledge_base_id does not identify an available Knowledge Base")
    base = bases[0]
    base_category_ids = base.get("category_ids")
    if not isinstance(base_category_ids, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in base_category_ids
    ):
        raise RuntimeError("Zammad returned invalid Knowledge Base category IDs")

    kb_categories = [
        item for item in categories
        if isinstance(item, Mapping) and item.get("knowledge_base_id") == knowledge_base_id
    ]
    if {item.get("id") for item in kb_categories} != set(base_category_ids):
        raise RuntimeError("Zammad returned an incomplete Knowledge Base category inventory")
    for item in kb_categories:
        if "parent_id" not in item or (item["parent_id"] is not None and item["parent_id"] not in base_category_ids):
            raise RuntimeError("Zammad returned an invalid Knowledge Base category tree")
    category_by_id = {item["id"]: item for item in kb_categories}

    if kind == "root_categories":
        if category_id is not None:
            raise ValueError("root_categories does not accept category_id")
        selected = [item for item in kb_categories if item.get("parent_id") is None]
    else:
        if isinstance(category_id, bool) or not isinstance(category_id, int) or category_id not in category_by_id:
            raise ValueError("category_id must identify a category in the selected Knowledge Base")
        parent = category_by_id[category_id]
        if kind == "categories":
            selected = [item for item in kb_categories if item.get("parent_id") == category_id]
            child_ids = parent.get("child_ids")
            if not isinstance(child_ids, list) or set(child_ids) != {item["id"] for item in selected}:
                raise RuntimeError("Zammad returned inconsistent Knowledge Base child category IDs")
        else:
            raw_answer_ids = parent.get("answer_ids")
            if not isinstance(raw_answer_ids, list) or any(
                isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in raw_answer_ids
            ):
                raise RuntimeError("Zammad returned invalid Knowledge Base category answer IDs")
            selected = [
                item for item in answers
                if isinstance(item, Mapping) and item.get("category_id") == category_id
            ]
            if {item.get("id") for item in selected} != set(raw_answer_ids):
                raise RuntimeError("Zammad returned an incomplete category answer inventory")

    projected = []
    for item in selected:
        item_id = item.get("id")
        position = item.get("position")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
            raise RuntimeError("Zammad returned an invalid Knowledge Base ordering ID")
        if isinstance(position, bool) or not isinstance(position, int):
            raise RuntimeError("Zammad returned an invalid Knowledge Base ordering position")
        projected.append({"id": item_id, "position": position})
    projected.sort(key=lambda item: (item["position"], item["id"]))
    return {
        "knowledge_base_id": knowledge_base_id,
        "kind": kind,
        "category_id": category_id,
        "items": projected,
    }


def validate_order(value: Any, snapshot: Mapping[str, Any]) -> list[int]:
    if not isinstance(value, list):
        raise ValueError("ordered_ids must be a list")
    current_ids = [item["id"] for item in snapshot["items"]]
    ordered_ids = []
    for item_id in value:
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
            raise ValueError("ordered_ids must contain positive integer IDs")
        ordered_ids.append(item_id)
    if len(ordered_ids) != len(set(ordered_ids)) or set(ordered_ids) != set(current_ids):
        raise ValueError("ordered_ids must contain every sibling ID exactly once")
    if ordered_ids == current_ids:
        raise ValueError("The requested Knowledge Base order already matches the current order")
    return ordered_ids


def preview_after(snapshot: Mapping[str, Any], ordered_ids: list[int]) -> dict[str, Any]:
    return {
        **snapshot,
        "items": [{"id": item_id, "position": index} for index, item_id in enumerate(ordered_ids)],
    }
