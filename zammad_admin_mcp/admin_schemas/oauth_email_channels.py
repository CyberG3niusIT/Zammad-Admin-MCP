from collections.abc import Mapping
from typing import Any


def validate_group_payload(data: Any) -> int:
    if not isinstance(data, Mapping) or set(data) != {"group_id"}:
        raise ValueError("Microsoft channel reassignment requires exactly group_id")
    group_id = data["group_id"]
    if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id <= 0:
        raise ValueError("group_id must be a positive integer")
    return group_id


def validate_configure_payload(resource: str, data: Any) -> dict[str, Any]:
    if resource not in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        raise ValueError("Unsupported OAuth email channel type")
    if not isinstance(data, Mapping) or not data or set(data) - {"group_id", "active", "options", "group_email_address", "group_email_address_id"}:
        raise ValueError("Microsoft channel configuration accepts group, sender, active, and options fields")
    result = dict(data)
    if "group_id" in result:
        group_id = result["group_id"]
        if isinstance(group_id, bool) or not isinstance(group_id, int) or group_id <= 0:
            raise ValueError("group_id must be a positive integer")
    if "active" in result and not isinstance(result["active"], bool):
        raise ValueError("active must be a boolean")
    if "group_email_address" in result and not isinstance(result["group_email_address"], bool):
        raise ValueError("group_email_address must be a boolean")
    if "group_email_address_id" in result:
        address_id = result["group_email_address_id"]
        if isinstance(address_id, bool) or not isinstance(address_id, int) or address_id <= 0:
            raise ValueError("group_email_address_id must be a positive integer")
        if result.get("group_email_address") is not True:
            raise ValueError("group_email_address_id requires group_email_address=true")
    if result.get("group_email_address") is True and "group_id" not in result:
        raise ValueError("group_id is required when changing a group's sending address")
    if "options" in result:
        options = result["options"]
        if not isinstance(options, Mapping) or not options:
            raise ValueError("options must be a non-empty object")
        allowed_options = {"keep_on_server", "archive", "archive_before", "archive_state_id"}
        allowed_options.add("folder_id" if resource == "microsoft_graph_channels" else "folder")
        if set(options) - allowed_options:
            raise ValueError("options contains fields unsupported for this Microsoft channel")
        options = dict(options)
        folder_key = "folder_id" if resource == "microsoft_graph_channels" else "folder"
        if folder_key in options:
            folder = options[folder_key]
            limit = 120 if folder_key == "folder" else 255
            if not isinstance(folder, str) or len(folder) > limit:
                raise ValueError(f"{folder_key} must be a string of at most {limit} characters")
        if "keep_on_server" in options and not isinstance(options["keep_on_server"], bool):
            raise ValueError("keep_on_server must be a boolean")
        if "archive" in options and not isinstance(options["archive"], bool):
            raise ValueError("archive must be a boolean")
        if "archive_before" in options and (not isinstance(options["archive_before"], str) or not options["archive_before"].strip() or len(options["archive_before"]) > 64):
            raise ValueError("archive_before must be a non-empty date-time string of at most 64 characters")
        if "archive_state_id" in options:
            state_id = options["archive_state_id"]
            if isinstance(state_id, bool) or not isinstance(state_id, int) or state_id <= 0:
                raise ValueError("archive_state_id must be a positive integer")
        result["options"] = options
    if not any(key in result for key in {"group_id", "active", "options", "group_email_address"}):
        raise ValueError("At least one supported Microsoft channel setting is required")
    return result


def validate_probe_payload(resource: str, data: Any) -> dict[str, Any]:
    if resource not in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        raise ValueError("Unsupported OAuth email channel type")
    if data in (None, {}):
        return {}
    if not isinstance(data, Mapping) or set(data) != {"options"}:
        raise ValueError("Microsoft channel probe accepts only an options object")
    options = data["options"]
    if not isinstance(options, Mapping) or not options:
        raise ValueError("options must be a non-empty object")
    folder_key = "folder_id" if resource == "microsoft_graph_channels" else "folder"
    if set(options) - {folder_key, "keep_on_server"}:
        raise ValueError("Probe options contain unsupported fields")
    checked = dict(options)
    if folder_key in checked:
        folder = checked[folder_key]
        limit = 255 if folder_key == "folder_id" else 120
        if not isinstance(folder, str) or len(folder) > limit:
            raise ValueError(f"{folder_key} must be a string of at most {limit} characters")
    if "keep_on_server" in checked and not isinstance(checked["keep_on_server"], bool):
        raise ValueError("keep_on_server must be a boolean")
    return {"options": checked}
