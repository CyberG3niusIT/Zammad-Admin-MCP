from collections.abc import Mapping
from typing import Any


def _records(assets: Mapping[str, Any], model: str) -> list[Mapping[str, Any]]:
    values = assets.get(model, {})
    if not isinstance(values, Mapping):
        raise RuntimeError(f"Zammad returned invalid {model} assets")
    result = []
    for record_id, value in values.items():
        if not isinstance(value, Mapping):
            raise RuntimeError(f"Zammad returned an invalid {model} record")
        item_id = value.get("id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
            raise RuntimeError(f"Zammad returned an invalid {model} ID")
        if str(item_id) != str(record_id):
            raise RuntimeError(f"Zammad returned a mismatched {model} ID")
        result.append(value)
    return sorted(result, key=lambda item: item["id"])


def project_snapshot(value: Any, knowledge_base_id: int, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return Knowledge Base manager assets")
    assets = value.get("assets", value)
    if not isinstance(assets, Mapping):
        raise RuntimeError("Zammad returned invalid Knowledge Base manager assets")

    bases = [item for item in _records(assets, "KnowledgeBase") if item["id"] == knowledge_base_id]
    if len(bases) != 1:
        raise ValueError("knowledge_base_id does not identify a configured Knowledge Base")

    locales = []
    locale_ids = set()
    for item in _records(assets, "KnowledgeBaseLocale"):
        owner_id = item.get("knowledge_base_id")
        if isinstance(owner_id, bool) or not isinstance(owner_id, int) or owner_id <= 0:
            raise RuntimeError("Zammad returned an invalid Knowledge Base locale")
        if owner_id != knowledge_base_id:
            continue
        locale_id = item["id"]
        system_locale_id = item.get("system_locale_id")
        if isinstance(system_locale_id, bool) or not isinstance(system_locale_id, int) or system_locale_id <= 0:
            raise RuntimeError("Zammad returned an invalid Knowledge Base locale")
        if locale_id in locale_ids:
            raise RuntimeError("Zammad returned duplicate Knowledge Base locales")
        locale_ids.add(locale_id)
        locales.append({"id": locale_id, "system_locale_id": system_locale_id})
    if not locales:
        raise RuntimeError("Zammad returned no locales for the selected Knowledge Base")

    items_by_locale = {locale_id: [] for locale_id in locale_ids}
    for item in _records(assets, "KnowledgeBaseMenuItem"):
        locale_id = item.get("kb_locale_id")
        if isinstance(locale_id, bool) or not isinstance(locale_id, int) or locale_id <= 0:
            raise RuntimeError("Zammad returned an invalid Knowledge Base menu item locale")
        if locale_id not in items_by_locale or item.get("location") != location:
            continue
        title = item.get("title")
        url = item.get("url")
        position = item.get("position")
        new_tab = item.get("new_tab")
        if not isinstance(title, str) or not isinstance(url, str):
            raise RuntimeError("Zammad returned an invalid Knowledge Base menu item")
        if isinstance(position, bool) or not isinstance(position, int) or not isinstance(new_tab, bool):
            raise RuntimeError("Zammad returned invalid Knowledge Base menu item settings")
        items_by_locale[locale_id].append({
            "id": item["id"], "title": title, "url": url,
            "position": position, "new_tab": new_tab,
        })

    for items in items_by_locale.values():
        items.sort(key=lambda item: (item["position"], item["id"]))
    return {
        "knowledge_base_id": knowledge_base_id,
        "location": location,
        "locales": [
            {**locale, "menu_items": items_by_locale[locale["id"]]}
            for locale in sorted(locales, key=lambda item: item["id"])
        ],
    }


def validate_update(value: Any, snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(snapshot["locales"]):
        raise ValueError("menu_items_sets must contain one complete set for every Knowledge Base locale")
    location = snapshot["location"]
    locales = {locale["id"]: locale for locale in snapshot["locales"]}
    seen_locales = set()
    normalized = []

    for location_set in value:
        if not isinstance(location_set, Mapping) or set(location_set) != {"kb_locale_id", "location", "menu_items"}:
            raise ValueError("Each menu set must contain only kb_locale_id, location, and menu_items")
        locale_id = location_set["kb_locale_id"]
        if isinstance(locale_id, bool) or not isinstance(locale_id, int) or locale_id not in locales or locale_id in seen_locales:
            raise ValueError("menu_items_sets must identify every Knowledge Base locale exactly once")
        if location_set["location"] != location:
            raise ValueError("Every menu set must use the selected header or footer location")
        seen_locales.add(locale_id)
        menu_items = location_set["menu_items"]
        if not isinstance(menu_items, list) or len(menu_items) > 100:
            raise ValueError("menu_items must be a list with at most 100 entries")

        current = {item["id"]: item for item in locales[locale_id]["menu_items"]}
        seen_ids = set()
        normalized_items = []
        for item in menu_items:
            if not isinstance(item, Mapping) or set(item) - {"id", "title", "url", "new_tab", "_destroy"}:
                raise ValueError("Menu items contain unsupported fields")
            title = item.get("title")
            url = item.get("url")
            new_tab = item.get("new_tab")
            destroy = item.get("_destroy")
            if not isinstance(title, str) or not title.strip() or len(title) > 100:
                raise ValueError("Menu item titles must contain 1 to 100 characters")
            if not isinstance(url, str) or not url.strip() or len(url) > 500:
                raise ValueError("Menu item URLs must contain 1 to 500 characters")
            if not isinstance(new_tab, bool) or not isinstance(destroy, bool):
                raise ValueError("Menu item new_tab and _destroy values must be booleans")
            result = {"title": title, "url": url, "new_tab": new_tab, "_destroy": destroy}
            if "id" in item and item["id"] is not None:
                item_id = item["id"]
                if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id not in current or item_id in seen_ids:
                    raise ValueError("Menu item IDs must match the current locale and location")
                seen_ids.add(item_id)
                result["id"] = item_id
            elif destroy:
                raise ValueError("A new menu item cannot be marked for deletion")
            normalized_items.append(result)
        if seen_ids != set(current):
            raise ValueError("Every existing menu item must appear exactly once in its locale set")
        normalized.append({"kb_locale_id": locale_id, "location": location, "menu_items": normalized_items})

    if seen_locales != set(locales):
        raise ValueError("menu_items_sets must identify every Knowledge Base locale exactly once")
    return sorted(normalized, key=lambda item: item["kb_locale_id"])


def preview_after(snapshot: Mapping[str, Any], update: list[dict[str, Any]]) -> dict[str, Any]:
    sets = {item["kb_locale_id"]: item["menu_items"] for item in update}
    locales = []
    for locale in snapshot["locales"]:
        menu_items = []
        for position, item in enumerate(sets[locale["id"]]):
            if item["_destroy"]:
                continue
            menu_items.append({
                "id": item.get("id"), "title": item["title"], "url": item["url"],
                "position": position, "new_tab": item["new_tab"],
            })
        locales.append({"id": locale["id"], "system_locale_id": locale["system_locale_id"], "menu_items": menu_items})
    return {**snapshot, "locales": locales}
