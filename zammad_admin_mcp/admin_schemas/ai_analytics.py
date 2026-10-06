"""Bounded, content-free summaries for Zammad AI analytics exports."""

from datetime import datetime, timedelta, timezone
from typing import Any
from collections.abc import Mapping


_MAX_RANGE = timedelta(days=7)
_MAX_RECORDS = 10_000


def validate_window(created_after: Any, created_before: Any) -> tuple[str, str]:
    if not isinstance(created_after, str) or not isinstance(created_before, str):
        raise ValueError("created_after and created_before must be ISO 8601 timestamps")
    try:
        start = datetime.fromisoformat(created_after.replace("Z", "+00:00"))
        stop = datetime.fromisoformat(created_before.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("created_after and created_before must be ISO 8601 timestamps") from None
    if start.tzinfo is None or stop.tzinfo is None:
        raise ValueError("timestamps must include a UTC offset")
    start = start.astimezone(timezone.utc)
    stop = stop.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if start >= stop:
        raise ValueError("created_after must be earlier than created_before")
    if stop > now:
        raise ValueError("created_before cannot be in the future")
    if stop - start > _MAX_RANGE:
        raise ValueError("AI analytics summaries are limited to a seven-day window")
    return start.isoformat().replace("+00:00", "Z"), stop.isoformat().replace("+00:00", "Z")


def project_summary(value: Any, report_type: str) -> dict[str, Any]:
    if report_type not in {"errors", "with_usages"}:
        raise ValueError("Unsupported AI analytics report type")
    if not isinstance(value, list) or len(value) > _MAX_RECORDS:
        raise RuntimeError("Zammad returned an invalid AI analytics report")
    if any(not isinstance(record, Mapping) for record in value):
        raise RuntimeError("Zammad returned an invalid AI analytics record")

    result: dict[str, Any] = {
        "report_type": report_type,
        "records": len(value),
        "possibly_truncated": len(value) == _MAX_RECORDS,
        "zammad_record_limit": _MAX_RECORDS,
    }
    if report_type == "errors":
        result["error_records"] = len(value)
        return result

    totals = {"usages": 0, "likes": 0, "dislikes": 0, "comments": 0}
    for record in value:
        for key, field in (("usages", "usages_count"), ("likes", "likes_count"), ("dislikes", "dislikes_count")):
            count = record.get(field)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise RuntimeError("Zammad returned invalid AI analytics counts")
            totals[key] += count
        comments = record.get("comments")
        if not isinstance(comments, list):
            raise RuntimeError("Zammad returned invalid AI analytics comments metadata")
        totals["comments"] += len(comments)
    result["usage_totals"] = totals
    return result
