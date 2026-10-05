from collections.abc import Mapping
from typing import Any


def validate_payload(data: Any) -> None:
    if not isinstance(data, Mapping) or set(data) != {"pages"}:
        raise ValueError("Facebook channel updates require a pages mapping")
    pages = data["pages"]
    if not isinstance(pages, Mapping) or not pages:
        raise ValueError("pages must map Facebook page IDs to group assignments")
    for page_id, assignment in pages.items():
        if not isinstance(page_id, str) or not page_id.strip() or len(page_id) > 100:
            raise ValueError("Facebook page IDs must be non-empty strings of at most 100 characters")
        if not isinstance(assignment, Mapping) or set(assignment) != {"group_id"}:
            raise ValueError("each Facebook page assignment accepts exactly group_id")
        group_id = assignment["group_id"]
        if group_id in (None, ""):
            continue
        if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id <= 0:
            raise ValueError("Facebook page group_id must be a positive integer or empty")
