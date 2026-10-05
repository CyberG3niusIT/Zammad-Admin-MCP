from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


MAX_CSV_BYTES = 5 * 1024 * 1024
SUPPORTED_SEPARATORS = {",", ";", "|", "\t"}


def validate_csv_input(csv_data: Any, separator: Any) -> tuple[str, str]:
    if not isinstance(csv_data, str) or not csv_data.strip():
        raise ValueError("csv_data must be a non-empty CSV string")
    if len(csv_data.encode("utf-8")) > MAX_CSV_BYTES:
        raise ValueError("csv_data exceeds the 5 MiB import limit")
    if not isinstance(separator, str) or separator not in SUPPORTED_SEPARATORS:
        raise ValueError("separator must be one of comma, semicolon, pipe, or tab")
    return csv_data, separator


def project_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return a user import result")

    result = value.get("result")
    if not isinstance(result, str) or result not in {"success", "failed"}:
        raise RuntimeError("Zammad returned an invalid user import result")

    projected: dict[str, Any] = {
        "result": result,
        "dry_run": value.get("try") is True,
        "records_returned": False,
    }
    stats = value.get("stats")
    if isinstance(stats, Mapping):
        safe_stats = {}
        for field in ("created", "updated", "deleted"):
            count = stats.get(field)
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                safe_stats[field] = count
        projected["stats"] = safe_stats
    if result == "success" and not {"created", "updated"}.issubset(projected.get("stats", {})):
        raise RuntimeError("Zammad returned incomplete user import counts")

    errors = value.get("errors", [])
    if not isinstance(errors, list):
        errors = []
    safe_errors = []
    for error in errors:
        if not isinstance(error, str):
            continue
        match = re.match(r"^Line (\d+):\s*(.*)$", error)
        if match:
            message = match.group(2).lower()
            if "duplicate record" in message:
                code = "duplicate_record"
            elif "unknown user" in message:
                code = "unknown_user_id"
            elif "unable to create record" in message:
                code = "create_validation_failed"
            elif "unable to update record" in message:
                code = "update_validation_failed"
            else:
                code = "row_validation_failed"
            safe_errors.append({"line": int(match.group(1)), "code": code})
            continue

        message = error.lower()
        known_errors = {
            "unable to parse empty file/string": "empty_csv",
            "unable to parse file/string without header": "missing_header",
            "no records found in file/string": "no_records",
            "no lookup column": "missing_lookup_column",
        }
        code = next((code for prefix, code in known_errors.items() if prefix in message), "import_validation_failed")
        safe_errors.append({"code": code})

    projected["errors"] = safe_errors
    projected["error_count"] = len(errors)
    if result == "success" and errors:
        raise RuntimeError("Zammad returned inconsistent user import errors")
    return projected


def equivalent_results(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return (
        first.get("result") == second.get("result")
        and first.get("stats") == second.get("stats")
        and first.get("errors") == second.get("errors")
    )
