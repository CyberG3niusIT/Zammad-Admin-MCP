"""Endpoint-specific validation for Zammad 7.1.2 postmaster filters."""

from collections.abc import Mapping
import math
from typing import Any


_OPERATORS = {
    "contains", "contains not", "is any of", "is none of",
    "starts with one of", "ends with one of", "matches regex", "does not match regex",
}
_LIST_OPERATORS = {"is any of", "is none of", "starts with one of", "ends with one of"}
_SENSITIVE_ACTION_WORDS = ("password", "secret", "token", "credential", "authorization", "private_key", "api_key", "access_key")


def _validate_json_value(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must contain finite JSON numbers")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _validate_json_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path} must contain JSON-compatible values")


def validate_payload(operation: str, data: Any) -> None:
    allowed = {"name", "channel", "match", "perform", "note", "active"}
    if not isinstance(data, Mapping) or not data or set(data) - allowed:
        raise ValueError("postmaster_filters accepts name, channel, match, perform, note, and active")
    if operation == "create":
        if not {"name", "match"}.issubset(data):
            raise ValueError("creating a postmaster filter requires name and match")
        if data.get("channel", "email") != "email":
            raise ValueError("postmaster filters support only the email channel")
    elif "channel" in data:
        raise ValueError("channel is fixed to email and cannot be updated")
    if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip()):
        raise ValueError("name must be a non-empty string")
    if "note" in data and data["note"] is not None and (not isinstance(data["note"], str) or len(data["note"]) > 250):
        raise ValueError("note must be null or a string of at most 250 characters")
    if "active" in data and not isinstance(data["active"], bool):
        raise ValueError("active must be a boolean")
    if "match" in data:
        match = data["match"]
        if not isinstance(match, Mapping) or not match:
            raise ValueError("match must contain at least one email-header rule")
        for field, rule in match.items():
            if not isinstance(field, str) or not field.strip() or not isinstance(rule, Mapping):
                raise ValueError("each match rule must map a non-empty header name to operator and value")
            if set(rule) != {"operator", "value"}:
                raise ValueError("each match rule accepts exactly operator and value")
            operator, value = rule["operator"], rule["value"]
            if not isinstance(operator, str) or operator not in _OPERATORS:
                raise ValueError("unsupported postmaster match operator")
            if operator in _LIST_OPERATORS:
                if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
                    raise ValueError("list match operators require a non-empty list of strings")
            elif not isinstance(value, str) or not value.strip():
                raise ValueError("this match operator requires a non-empty string value")
    if "perform" in data:
        perform = data["perform"]
        if not isinstance(perform, Mapping):
            raise ValueError("perform must be an object keyed by Zammad postmaster actions")
        for action, options in perform.items():
            if not isinstance(action, str) or not action.startswith("x-zammad-") or not isinstance(options, Mapping):
                raise ValueError("each perform action must be a Zammad x-zammad-* action object")
            if any(word in action.lower() for word in _SENSITIVE_ACTION_WORDS):
                raise ValueError("credential-related attributes are not supported in postmaster actions")
            _validate_json_value(options, f"perform.{action}")
            if "value" not in options:
                raise ValueError(f"perform action {action!r} requires a value")
            if action in {"x-zammad-ticket-owner_id", "x-zammad-ticket-customer_id"}:
                value = options["value"]
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (str, int))
                    or value in (None, "")
                    or isinstance(value, int) and value <= 0
                ):
                    raise ValueError(f"perform action {action!r} requires a non-empty value")
