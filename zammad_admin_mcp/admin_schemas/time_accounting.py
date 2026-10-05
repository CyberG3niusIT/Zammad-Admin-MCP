from collections.abc import Mapping
from typing import Any


_TYPE_FIELDS = {"name", "note"}
_REPORTS = {"by_activity", "by_ticket", "by_customer", "by_organization"}


def validate_type_payload(operation: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value or set(value) - _TYPE_FIELDS:
        raise ValueError("Activity types accept only name and note")
    result = dict(value)
    if operation == "create" and "name" not in result:
        raise ValueError("Activity type creation requires name")
    if "name" in result and (not isinstance(result["name"], str) or not result["name"].strip()):
        raise ValueError("name must be non-empty text")
    if "note" in result and (not isinstance(result["note"], str) or len(result["note"]) > 250):
        raise ValueError("note must be text of at most 250 characters")
    return result


def project_types(value: Any) -> Any:
    if isinstance(value, list):
        return [_project_type(item) for item in value]
    if isinstance(value, Mapping) and isinstance(value.get("items"), list):
        return {**value, "items": [_project_type(item) for item in value["items"]]}
    raise RuntimeError("Zammad did not return activity types")


def _project_type(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid activity type")
    return {key: value[key] for key in ("id", "name", "note", "created_at", "updated_at") if key in value}


def validate_report_request(report: str, year: int, month: int, limit: int) -> None:
    if not isinstance(report, str) or report not in _REPORTS:
        raise ValueError("Unsupported time accounting report")
    if isinstance(year, bool) or not isinstance(year, int) or not 1900 <= year <= 9999:
        raise ValueError("year must be between 1900 and 9999")
    if isinstance(month, bool) or not isinstance(month, int) or not 1 <= month <= 12:
        raise ValueError("month must be between 1 and 12")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")


def project_report(report: str, value: Any) -> list[dict[str, Any]]:
    if report not in _REPORTS or not isinstance(value, list):
        raise RuntimeError("Zammad did not return a time accounting report")
    result: list[dict[str, Any]] = []
    for row in value:
        if not isinstance(row, Mapping):
            raise RuntimeError("Zammad returned an invalid time accounting report row")
        if report in {"by_activity", "by_ticket"}:
            ticket = row.get("ticket")
            if not isinstance(ticket, Mapping):
                continue
            safe_ticket = {
                key: ticket[key]
                for key in ("id", "number", "title", "customer_id", "organization_id")
                if key in ticket
            }
            projected = {"ticket": safe_ticket}
            for key in ("time_unit", "type", "customer", "organization", "agent", "created_at"):
                if key in row:
                    projected[key] = row[key]
            result.append(projected)
            continue
        if report == "by_customer":
            customer = row.get("customer")
            organization = row.get("organization")
            result.append({
                "customer": _project_identity(customer, ("id", "firstname", "lastname")),
                "organization": _project_identity(organization, ("id", "name")),
                "time_unit": row.get("time_unit"),
            })
            continue
        result.append({
            "organization": _project_identity(row.get("organization"), ("id", "name")),
            "time_unit": row.get("time_unit"),
        })
    return result


def _project_identity(value: Any, fields: tuple[str, ...]) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid time accounting report identity")
    return {key: value[key] for key in fields if key in value}
