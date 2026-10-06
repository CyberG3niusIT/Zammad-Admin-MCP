from typing import Any


def create_payload(system_locale_id: Any) -> dict[str, Any]:
    if isinstance(system_locale_id, bool) or not isinstance(system_locale_id, int) or system_locale_id <= 0:
        raise ValueError("system_locale_id must be a positive integer")
    return {
        "iconset": "FontAwesome",
        "color_highlight": "#38ae6a",
        "color_header": "#f9fafb",
        "color_header_link": "hsl(206,8%,50%)",
        "homepage_layout": "grid",
        "category_layout": "grid",
        "kb_locales_attributes": [
            {"system_locale_id": system_locale_id, "primary": True}
        ],
    }
