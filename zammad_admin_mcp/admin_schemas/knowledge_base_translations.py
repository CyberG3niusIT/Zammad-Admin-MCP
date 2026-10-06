from collections.abc import Mapping
from typing import Any


def project_snapshot(value: Any, knowledge_base_id: int, kb_locale_id: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return Knowledge Base translation inventory")
    bases = [
        item for item in value.get("knowledge_bases", [])
        if isinstance(item, Mapping) and item.get("id") == knowledge_base_id
    ]
    locales = [
        item for item in value.get("locales", [])
        if isinstance(item, Mapping)
        and item.get("id") == kb_locale_id
        and item.get("knowledge_base_id") == knowledge_base_id
    ]
    translations = [
        item for item in value.get("knowledge_base_translations", [])
        if isinstance(item, Mapping)
        and item.get("knowledge_base_id") == knowledge_base_id
        and item.get("kb_locale_id") == kb_locale_id
    ]
    if len(bases) != 1 or len(locales) != 1 or len(translations) != 1:
        raise ValueError("kb_locale_id does not identify one translated entry in the selected Knowledge Base")
    translation = translations[0]
    footer_note = translation.get("footer_note")
    if footer_note is not None and not isinstance(footer_note, str):
        raise RuntimeError("Zammad returned an invalid Knowledge Base footer note")
    title = translation.get("title")
    if not isinstance(title, str):
        raise RuntimeError("Zammad returned an invalid Knowledge Base title")
    return {
        "knowledge_base_id": knowledge_base_id,
        "active": bases[0].get("active"),
        "locale": dict(locales[0]),
        "translation": {
            "id": translation["id"],
            "kb_locale_id": kb_locale_id,
            "title": title,
            "footer_note": footer_note,
        },
    }


def validate_update(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("data must be a non-empty JSON object")
    unknown = set(value) - {"title", "footer_note"}
    if unknown:
        raise ValueError(f"Unsupported Knowledge Base translation fields: {', '.join(sorted(unknown))}")
    result: dict[str, str] = {}
    if "title" in value:
        title = value["title"]
        if not isinstance(title, str) or not title.strip() or len(title) > 250:
            raise ValueError("title must be a non-empty string of at most 250 characters")
        result["title"] = title
    if "footer_note" in value:
        footer_note = value["footer_note"]
        if not isinstance(footer_note, str) or len(footer_note) > 2000:
            raise ValueError("footer_note must be a string of at most 2000 characters")
        result["footer_note"] = footer_note
    return result


def preview_after(snapshot: Mapping[str, Any], updates: Mapping[str, str]) -> dict[str, Any]:
    return {
        "knowledge_base_id": snapshot["knowledge_base_id"],
        "kb_locale_id": snapshot["translation"]["kb_locale_id"],
        "translation_id": snapshot["translation"]["id"],
        "title": updates.get("title", snapshot["translation"]["title"]),
        "footer_note": updates.get("footer_note", snapshot["translation"]["footer_note"]),
    }
