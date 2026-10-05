"""Validated job definitions for staged Zammad automation changes."""

import math
import re
from collections.abc import Mapping
from typing import Any


_FIELDS = {
    "name", "timeplan", "object", "condition", "perform", "disable_notification",
    "active", "note", "timezone", "localization",
}
_OBJECTS = {"Ticket": "ticket", "User": "user", "Organization": "organization"}
_DAYS = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
_FIELD_NAME = re.compile(r"^[a-z]+\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")


def _json_value(value: Any, path: str, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError(f"{path} is nested too deeply")
    if isinstance(value, str):
        if len(value) > 100_000:
            raise ValueError(f"{path} is too long")
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must contain finite JSON numbers")
        return
    if isinstance(value, list):
        if len(value) > 500:
            raise ValueError(f"{path} has too many list entries")
        for index, item in enumerate(value):
            _json_value(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping) and len(value) <= 500 and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _json_value(item, f"{path}.{key}", depth + 1)
        return
    raise ValueError(f"{path} must contain bounded JSON-compatible values")


def _validate_timeplan(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != {"days", "hours", "minutes"}:
        raise ValueError("timeplan must contain days, hours, and minutes")
    days = value["days"]
    if not isinstance(days, Mapping) or not days or set(days) - _DAYS:
        raise ValueError("timeplan.days must select one or more weekdays")
    if any(not isinstance(enabled, bool) for enabled in days.values()) or not any(days.values()):
        raise ValueError("timeplan.days must contain boolean selections with at least one enabled day")
    for key, maximum in (("hours", 23), ("minutes", 59)):
        values = value[key]
        if (
            not isinstance(values, list) or not values
            or any(isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= maximum for item in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError(f"timeplan.{key} must contain unique integers from 0 through {maximum}")


def _validate_fields(value: Any, object_name: str, *, actions: bool) -> None:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("perform and condition must be non-empty field maps")
    prefix = _OBJECTS[object_name]
    for field, rule in value.items():
        if not isinstance(field, str) or not _FIELD_NAME.fullmatch(field) or not field.startswith(prefix + "."):
            raise ValueError(f"job fields must belong to the selected {object_name} object")
        if not isinstance(rule, Mapping):
            raise ValueError(f"job field {field!r} must map to an object")
        if actions:
            if set(rule) != {"value"}:
                raise ValueError(f"job action {field!r} accepts exactly one value")
        elif set(rule) not in ({"operator", "value"}, {"operator", "value", "range"}):
            raise ValueError(f"job condition {field!r} requires operator and value, with optional range")
        if not actions and (
            not isinstance(rule["operator"], str) or not rule["operator"].strip()
            or len(rule["operator"]) > 100
        ):
            raise ValueError(f"job condition {field!r} requires a non-empty operator")
        if "range" in rule and not isinstance(rule["range"], str):
            raise ValueError(f"job condition {field!r} range must be a string")
        _json_value(rule["value"], f"job.{field}.value")


def validate_payload(operation: str, data: Any) -> None:
    if not isinstance(data, Mapping) or not data or set(data) - _FIELDS:
        raise ValueError("jobs accepts name, timeplan, object, condition, perform, active, note, timezone, localization, and disable_notification")
    if operation == "create" and not {"name", "timeplan", "object", "condition", "perform"}.issubset(data):
        raise ValueError("creating a job requires name, timeplan, object, condition, and perform")
    if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip()):
        raise ValueError("name must be a non-empty string")
    if "note" in data and data["note"] is not None and (not isinstance(data["note"], str) or len(data["note"]) > 250):
        raise ValueError("note must be a string of at most 250 characters or null")
    for key in ("active", "disable_notification"):
        if key in data and not isinstance(data[key], bool):
            raise ValueError(f"{key} must be a boolean")
    for key in ("timezone", "localization"):
        if key in data and data[key] is not None and not isinstance(data[key], str):
            raise ValueError(f"{key} must be a string or null")
    object_name = data.get("object")
    if "object" in data and (not isinstance(object_name, str) or object_name not in _OBJECTS):
        raise ValueError("object must be Ticket, User, or Organization")
    if "timeplan" in data:
        _validate_timeplan(data["timeplan"])
    if "condition" in data or "perform" in data:
        if not isinstance(object_name, str) or object_name not in _OBJECTS:
            raise ValueError("updating condition or perform requires the selected object")
        if "condition" in data:
            _validate_fields(data["condition"], object_name, actions=False)
        if "perform" in data:
            _validate_fields(data["perform"], object_name, actions=True)
