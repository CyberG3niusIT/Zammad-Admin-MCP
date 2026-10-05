from collections.abc import Mapping
from typing import Any


def _id_list(value: Any, field: str) -> list[int]:
    if not isinstance(value, list) or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in value):
        raise RuntimeError(f"Zammad returned invalid {field}")
    if len(value) != len(set(value)):
        raise RuntimeError(f"Zammad returned duplicate {field}")
    return value


def project_snapshot(
    knowledge_base_id: int,
    knowledge_base: Any,
    inventory: Mapping[str, Any],
    header_menu: Mapping[str, Any],
    footer_menu: Mapping[str, Any],
    permissions: Any,
    category_permissions: Mapping[int, Any],
    answer_attachments: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(knowledge_base, Mapping) or knowledge_base.get("id") != knowledge_base_id:
        raise RuntimeError("Zammad did not return the selected Knowledge Base record")
    expected_category_ids = _id_list(knowledge_base.get("category_ids"), "Knowledge Base category IDs")
    expected_locale_ids = _id_list(knowledge_base.get("kb_locale_ids"), "Knowledge Base locale IDs")

    bases = [item for item in inventory.get("knowledge_bases", []) if isinstance(item, Mapping) and item.get("id") == knowledge_base_id]
    if len(bases) != 1:
        raise ValueError("knowledge_base_id does not identify one available Knowledge Base")
    base = bases[0]
    if set(_id_list(base.get("category_ids"), "Knowledge Base category IDs")) != set(expected_category_ids):
        raise RuntimeError("Knowledge Base deletion inventory is missing categories")
    if "kb_locale_ids" in base and set(_id_list(base["kb_locale_ids"], "Knowledge Base locale IDs")) != set(expected_locale_ids):
        raise RuntimeError("Knowledge Base deletion inventory is missing locales")

    categories = [
        item for item in inventory.get("categories", [])
        if isinstance(item, Mapping) and item.get("knowledge_base_id") == knowledge_base_id
    ]
    if {item.get("id") for item in categories} != set(expected_category_ids):
        raise RuntimeError("Knowledge Base deletion inventory is missing category records")
    category_ids = set(expected_category_ids)
    categories_by_id = {item["id"]: item for item in categories}
    children_by_parent: dict[int | None, set[int]] = {}
    for category in categories:
        category_id = category["id"]
        parent_id = category.get("parent_id")
        if parent_id is not None and parent_id not in category_ids:
            raise RuntimeError("Knowledge Base deletion inventory contains an unrelated parent category")
        children_by_parent.setdefault(parent_id, set()).add(category_id)
    for category in categories:
        child_ids = set(_id_list(category.get("child_ids"), "Knowledge Base child category IDs"))
        if child_ids != children_by_parent.get(category["id"], set()):
            raise RuntimeError("Knowledge Base deletion inventory contains an incomplete category tree")
    answer_ids = {
        answer_id
        for category in categories
        for answer_id in _id_list(category.get("answer_ids"), "Knowledge Base category answer IDs")
    }
    answers = [
        item for item in inventory.get("answers", [])
        if isinstance(item, Mapping) and item.get("category_id") in category_ids
    ]
    if {item.get("id") for item in answers} != answer_ids:
        raise RuntimeError("Knowledge Base deletion inventory is missing answer records")
    if any(item.get("category_id") not in categories_by_id for item in answers):
        raise RuntimeError("Knowledge Base deletion inventory contains an answer outside the selected Knowledge Base")
    for category in categories:
        category_answer_ids = set(_id_list(category.get("answer_ids"), "Knowledge Base category answer IDs"))
        actual_answer_ids = {item["id"] for item in answers if item.get("category_id") == category["id"]}
        if category_answer_ids != actual_answer_ids:
            raise RuntimeError("Knowledge Base deletion inventory contains an incomplete category answer set")
    if set(answer_attachments) != answer_ids:
        raise RuntimeError("Knowledge Base deletion attachment inventory is incomplete")

    locales = [item for item in header_menu.get("locales", []) if isinstance(item, Mapping)]
    if {item.get("id") for item in locales} != set(expected_locale_ids):
        raise RuntimeError("Knowledge Base deletion inventory is missing locale records")
    if header_menu.get("knowledge_base_id") != knowledge_base_id or footer_menu.get("knowledge_base_id") != knowledge_base_id:
        raise RuntimeError("Knowledge Base menu snapshots do not match the selected Knowledge Base")
    if [item.get("id") for item in header_menu.get("locales", [])] != [item.get("id") for item in footer_menu.get("locales", [])]:
        raise RuntimeError("Knowledge Base header and footer locale snapshots do not match")

    translation_titles = {
        "knowledge_base": [
            item for item in inventory.get("knowledge_base_translations", [])
            if isinstance(item, Mapping) and item.get("knowledge_base_id") == knowledge_base_id
        ],
        "categories": [
            item for item in inventory.get("category_translations", [])
            if isinstance(item, Mapping) and item.get("category_id") in category_ids
        ],
        "answers": [
            item for item in inventory.get("answer_translations", [])
            if isinstance(item, Mapping) and item.get("answer_id") in answer_ids
        ],
    }
    expected_translation_ids = {
        "knowledge_base": set(_id_list(knowledge_base.get("translation_ids", base.get("translation_ids")), "Knowledge Base translation IDs")),
        "categories": {
            translation_id
            for category in categories
            for translation_id in _id_list(category.get("translation_ids"), "Knowledge Base category translation IDs")
        },
        "answers": {
            translation_id
            for answer in answers
            for translation_id in _id_list(answer.get("translation_ids"), "Knowledge Base answer translation IDs")
        },
    }
    translation_id_fields = {
        "knowledge_base": "knowledge_base_id",
        "categories": "category_id",
        "answers": "answer_id",
    }
    for kind, translations in translation_titles.items():
        relation_field = translation_id_fields[kind]
        if {item.get("id") for item in translations} != expected_translation_ids[kind]:
            raise RuntimeError(f"Knowledge Base deletion inventory is missing {kind} translations")
        if any(item.get("kb_locale_id") not in set(expected_locale_ids) for item in translations):
            raise RuntimeError(f"Knowledge Base deletion inventory contains an unrelated {kind} translation")
        if any(item.get(relation_field) not in ({knowledge_base_id} if kind == "knowledge_base" else category_ids if kind == "categories" else answer_ids) for item in translations):
            raise RuntimeError(f"Knowledge Base deletion inventory contains an unrelated {kind} translation")
    answer_translation_records = translation_titles["answers"]
    content_owners = {}
    for translation in answer_translation_records:
        content_id = _id_list([translation.get("content_id")], "Knowledge Base answer translation content ID")[0]
        if content_id in content_owners:
            raise RuntimeError("Zammad returned duplicate Knowledge Base answer translation content IDs")
        content_owners[content_id] = translation
    content_records = inventory.get("answer_translation_contents", [])
    if not isinstance(content_records, list):
        raise RuntimeError("Zammad returned invalid Knowledge Base answer translation content assets")
    if {item.get("id") for item in content_records if isinstance(item, Mapping)} != set(content_owners):
        raise RuntimeError("Knowledge Base deletion inventory is missing answer content assets")
    answer_translation_contents = []
    for content in content_records:
        if not isinstance(content, Mapping) or content.get("id") not in content_owners:
            raise RuntimeError("Knowledge Base deletion inventory contains unrelated answer content")
        owner = content_owners[content["id"]]
        answer_translation_contents.append({
            "id": content["id"],
            "answer_id": owner["answer_id"],
            "translation_id": owner["id"],
            "attachments": content["attachments"],
            "inline_attachment_ids": content["inline_attachment_ids"],
        })
    if not isinstance(permissions, Mapping) or not isinstance(category_permissions, Mapping):
        raise RuntimeError("Zammad did not return Knowledge Base permission snapshots")
    if set(category_permissions) != category_ids:
        raise RuntimeError("Knowledge Base deletion permission inventory is incomplete")

    return {
        "knowledge_base": dict(knowledge_base),
        "categories": sorted(categories, key=lambda item: item["id"]),
        "answers": sorted(answers, key=lambda item: item["id"]),
        "answer_attachments": {str(key): answer_attachments[key] for key in sorted(answer_attachments)},
        "answer_translation_contents": sorted(answer_translation_contents, key=lambda item: item["id"]),
        "translation_titles": translation_titles,
        "header_menu": dict(header_menu),
        "footer_menu": dict(footer_menu),
        "permissions": dict(permissions),
        "category_permissions": {str(key): category_permissions[key] for key in sorted(category_permissions)},
    }


def preview(snapshot: Mapping[str, Any], knowledge_base_id: int) -> dict[str, Any]:
    knowledge_base = snapshot["knowledge_base"]
    titles = [item.get("title") for item in snapshot["translation_titles"]["knowledge_base"] if isinstance(item.get("title"), str)]
    categories = snapshot["categories"]
    answers = snapshot["answers"]
    locales = snapshot["header_menu"]["locales"]
    answer_attachment_ids = {
        item["id"]
        for answer in snapshot["answer_attachments"].values()
        for item in answer.get("attachments", [])
    }
    content_attachment_ids = {
        attachment_id
        for item in snapshot["answer_translation_contents"]
        for attachment_id in [
            *[attachment["id"] for attachment in item["attachments"]],
            *item["inline_attachment_ids"],
        ]
    }
    attachment_ids = answer_attachment_ids | content_attachment_ids
    return {
        "knowledge_base_id": knowledge_base_id,
        "title_translations": titles,
        "active": knowledge_base.get("active"),
        "category_count": len(categories),
        "category_ids": [item["id"] for item in categories],
        "answer_count": len(answers),
        "answer_ids": [item["id"] for item in answers],
        "attachment_count": len(attachment_ids),
        "attachment_ids": sorted(attachment_ids),
        "locale_count": len(locales),
        "locale_ids": [item["id"] for item in locales],
        "header_menu_item_count": sum(len(item["menu_items"]) for item in locales),
        "footer_menu_item_count": sum(len(item["menu_items"]) for item in snapshot["footer_menu"]["locales"]),
        "configured_role_permission_count": sum(
            len(item.get("permissions", []))
            for item in [snapshot["permissions"], *snapshot["category_permissions"].values()]
            if isinstance(item, Mapping) and isinstance(item.get("permissions"), list)
        ),
    }
