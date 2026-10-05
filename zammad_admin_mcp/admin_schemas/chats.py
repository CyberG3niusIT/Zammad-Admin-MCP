"""Endpoint-specific payload validation for Zammad 7.1.2 chat configuration."""

from collections.abc import Mapping
from math import isfinite
from typing import Any


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("chat preferences are nested too deeply")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("chat preferences cannot contain non-finite numbers")
        return
    if isinstance(value, list):
        if len(value) > 500:
            raise ValueError("chat preference arrays may contain at most 500 entries")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > 500 or any(not isinstance(key, str) for key in value):
            raise ValueError("chat preference objects require string keys and at most 500 entries")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise ValueError("chat preferences must contain only JSON-compatible values")


def validate_payload(operation: str, data: Any) -> None:
    allowed = {"name", "note", "preferences"}
    required = {"name"} if operation == "create" else set()
    if not isinstance(data, Mapping) or not data or set(data) - allowed or not required.issubset(data):
        raise ValueError("chats accepts name, note, and preferences; create requires name")
    if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip()):
        raise ValueError("name must be a non-empty string")
    if "note" in data and (not isinstance(data["note"], str) or len(data["note"]) > 250):
        raise ValueError("note must be a string of at most 250 characters")
    if "preferences" in data:
        if not isinstance(data["preferences"], Mapping):
            raise ValueError("preferences must be a JSON object")
        _validate_json_value(data["preferences"])
