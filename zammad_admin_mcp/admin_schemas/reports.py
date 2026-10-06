"""Safe report configuration and aggregate projections for Zammad reports."""

from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from math import isfinite
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


_MAX_BACKENDS = 8
_MAX_BUCKETS = {
    "realtime": 60,
    "day": 24,
    "week": 7,
    "month": 31,
    "year": 12,
}


def project_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("error"):
        raise RuntimeError("Zammad report configuration is unavailable")
    config = value.get("config")
    profiles = value.get("profiles")
    metrics = config.get("metric") if isinstance(config, Mapping) else None
    if not isinstance(metrics, Mapping) or not isinstance(profiles, list):
        raise RuntimeError("Zammad returned an invalid report configuration")

    projected_metrics: dict[str, Any] = {}
    for key, metric in metrics.items():
        if not isinstance(key, str) or not isinstance(metric, Mapping):
            raise RuntimeError("Zammad returned an invalid report metric")
        backends = metric.get("backend")
        if not isinstance(backends, list):
            raise RuntimeError("Zammad returned an invalid report backend list")
        projected_backends: list[dict[str, Any]] = []
        seen: set[str] = set()
        for backend in backends:
            if not isinstance(backend, Mapping):
                raise RuntimeError("Zammad returned an invalid report backend")
            name = backend.get("name")
            display = backend.get("display")
            if not isinstance(name, str) or not name or name in seen or not isinstance(display, str):
                raise RuntimeError("Zammad returned invalid report backend metadata")
            seen.add(name)
            projected_backends.append({
                "name": name,
                "display": display,
                "selected_by_default": backend.get("selected") is True,
                "data_download": backend.get("dataDownload") is True,
            })
        projected_metrics[key] = {
            "name": key,
            "display": metric.get("display") if isinstance(metric.get("display"), str) else key,
            "selected_by_default": metric.get("default") is True,
            "backends": projected_backends,
        }

    projected_profiles: list[dict[str, Any]] = []
    seen_profile_ids: set[int] = set()
    for profile in profiles:
        if not isinstance(profile, Mapping):
            raise RuntimeError("Zammad returned an invalid report profile")
        profile_id = profile.get("id")
        name = profile.get("name")
        if isinstance(profile_id, bool) or not isinstance(profile_id, int) or profile_id <= 0 or not isinstance(name, str):
            raise RuntimeError("Zammad returned invalid report profile metadata")
        if profile_id in seen_profile_ids:
            raise RuntimeError("Zammad returned duplicate report profiles")
        seen_profile_ids.add(profile_id)
        projected_profiles.append({"id": profile_id, "name": name})

    return {"metrics": projected_metrics, "profiles": projected_profiles}


def validate_request(
    config: Mapping[str, Any],
    *,
    profile_id: Any,
    metric: Any,
    backends: Any,
    time_range: str,
    year: Any = None,
    month: Any = None,
    day: Any = None,
    week: Any = None,
    timezone: Any = None,
) -> tuple[dict[str, Any], int, dict[str, str]]:
    if isinstance(profile_id, bool) or not isinstance(profile_id, int) or profile_id <= 0:
        raise ValueError("profile_id must be a positive integer")
    profile = next((item for item in config["profiles"] if item["id"] == profile_id), None)
    if profile is None:
        raise ValueError("profile_id must identify a profile available to the current Zammad user")

    metrics = config["metrics"]
    if not isinstance(metric, str) or metric not in metrics:
        raise ValueError("metric must be selected from the current Zammad report configuration")
    available = {
        item["name"]: item["display"] for item in metrics[metric]["backends"]
    }
    if (
        not isinstance(backends, Sequence)
        or isinstance(backends, (str, bytes))
        or not backends
        or len(backends) > _MAX_BACKENDS
        or any(not isinstance(item, str) for item in backends)
        or len(set(backends)) != len(backends)
    ):
        raise ValueError(f"backends must be a non-empty list of at most {_MAX_BACKENDS} unique names")
    if set(backends) - available.keys():
        raise ValueError("backends must be selected from the chosen metric's Zammad configuration")

    body: dict[str, Any] = {
        "profile_id": profile_id,
        "metric": metric,
        "backends": {name: True for name in backends},
        "timeRange": time_range,
    }
    if not isinstance(time_range, str) or time_range not in _MAX_BUCKETS:
        raise ValueError("time_range must be realtime, day, week, month, or year")
    if timezone is not None:
        if not isinstance(timezone, str) or not timezone or len(timezone) > 100:
            raise ValueError("timezone must be a valid IANA timezone name")
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("timezone must be a valid IANA timezone name") from None
        body["timezone"] = timezone

    supplied = {"year": year, "month": month, "day": day, "week": week}
    required = {
        "realtime": set(),
        "day": {"year", "month", "day"},
        "week": {"year", "week"},
        "month": {"year", "month"},
        "year": {"year"},
    }[time_range]
    for name, value in supplied.items():
        if name in required:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer for the selected time_range")
            if name == "year" and not 1970 <= value <= date.today().year:
                raise ValueError("year must be from 1970 through the current year")
            body[name] = value
        elif value is not None:
            raise ValueError(f"{name} is not used by the selected time_range")
    if time_range == "day":
        try:
            selected_date = date(year, month, day)
        except (TypeError, ValueError):
            raise ValueError("year, month, and day must form a valid calendar date") from None
        if selected_date > date.today():
            raise ValueError("day reports cannot end in the future")
    elif time_range == "week":
        try:
            week_start = date.fromisocalendar(year, week, 1)
        except (TypeError, ValueError):
            raise ValueError("year and week must identify a valid ISO week") from None
        if week_start > date.today():
            raise ValueError("week reports cannot start in the future")
    elif time_range == "month":
        try:
            selected_date = date(year, month, 1)
        except (TypeError, ValueError):
            raise ValueError("year and month must identify a valid calendar month") from None
        if selected_date > date.today():
            raise ValueError("month reports cannot start in the future")
    elif time_range == "year":
        try:
            selected_date = date(year, 1, 1)
        except (TypeError, ValueError):
            raise ValueError("year must identify a valid calendar year") from None
        if selected_date > date.today():
            raise ValueError("year reports cannot start in the future")

    return body, _MAX_BUCKETS[time_range], available


def validate_ticket_preview_request(
    config: Mapping[str, Any],
    *,
    profile_id: Any,
    metric: Any,
    backend: Any,
    time_range: str,
    year: Any = None,
    month: Any = None,
    day: Any = None,
    week: Any = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    if time_range not in {"realtime", "day", "week"}:
        raise ValueError("ticket previews support only realtime, day, and week periods")
    projected_metrics = config["metrics"]
    if not isinstance(metric, str) or metric not in projected_metrics:
        raise ValueError("metric must be selected from the current Zammad report configuration")
    backend_config = next(
        (item for item in projected_metrics[metric]["backends"] if item["name"] == backend),
        None,
    )
    if backend_config is None or backend_config.get("data_download") is not True:
        raise ValueError("backend must be available for ticket details in the current Zammad report configuration")

    payload, _, labels = validate_request(
        config,
        profile_id=profile_id,
        metric=metric,
        backends=[backend],
        time_range=time_range,
        year=year,
        month=month,
        day=day,
        week=week,
    )
    earliest = date.today() - timedelta(days=6)
    if time_range == "day" and date(year, month, day) < earliest:
        raise ValueError("ticket previews are limited to the last seven days")
    if time_range == "week" and date.fromisocalendar(year, week, 1) < earliest:
        raise ValueError("ticket previews are limited to the last seven days")
    payload.pop("backends")
    payload["downloadBackendSelected"] = backend
    return payload, labels


def project_ticket_preview(
    value: Any,
    *,
    limit: int = 100,
) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return report ticket details")
    count = value.get("count")
    ticket_ids = value.get("ticket_ids")
    assets = value.get("assets")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise RuntimeError("Zammad returned an invalid report ticket count")
    if not isinstance(ticket_ids, list):
        raise RuntimeError("Zammad returned an invalid report ticket list")
    if any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in ticket_ids):
        raise RuntimeError("Zammad returned invalid report ticket identifiers")
    if not isinstance(assets, Mapping):
        raise RuntimeError("Zammad returned invalid report ticket assets")
    ticket_assets = assets.get("Ticket", {})
    if not isinstance(ticket_assets, Mapping) or (ticket_ids and not ticket_assets):
        raise RuntimeError("Zammad returned invalid report ticket assets")

    records: list[dict[str, Any]] = []
    for ticket_id in ticket_ids[:limit]:
        ticket = ticket_assets.get(ticket_id, ticket_assets.get(str(ticket_id)))
        if not isinstance(ticket, Mapping):
            continue
        title = ticket.get("title")
        created_at = ticket.get("created_at")
        number = ticket.get("number")
        state_id = ticket.get("state_id")
        group_id = ticket.get("group_id")
        if title is not None and not isinstance(title, str):
            raise RuntimeError("Zammad returned an invalid report ticket title")
        if created_at is not None and not isinstance(created_at, str):
            raise RuntimeError("Zammad returned an invalid report ticket timestamp")
        if number is not None and (isinstance(number, bool) or not isinstance(number, (int, str))):
            raise RuntimeError("Zammad returned an invalid report ticket number")
        if any(item is not None and (isinstance(item, bool) or not isinstance(item, int) or item <= 0) for item in (state_id, group_id)):
            raise RuntimeError("Zammad returned invalid report ticket relationship IDs")
        records.append({
            "id": ticket_id,
            "number": number,
            "title": title[:500] if title is not None else None,
            "title_truncated": title is not None and len(title) > 500,
            "state_id": state_id,
            "group_id": group_id,
            "created_at": created_at,
        })
    return {
        "matching_count": count,
        "returned_count": len(records),
        "truncated": count > len(records),
        "records": records,
    }


def project_aggregates(
    value: Any,
    *,
    selected_backends: Sequence[str],
    max_buckets: int,
    metric: str,
) -> dict[str, list[int | None]]:
    if not isinstance(value, Mapping) or not isinstance(value.get("data"), Mapping):
        raise RuntimeError("Zammad did not return report aggregates")
    data = value["data"]
    if set(data) - set(selected_backends):
        raise RuntimeError("Zammad returned an unrequested report backend")
    result: dict[str, list[int | None]] = {}
    for name, buckets in data.items():
        if not isinstance(buckets, list) or len(buckets) > max_buckets:
            raise RuntimeError("Zammad returned an invalid report time series")
        allow_negative = metric == "count" and name.endswith("::backlog")
        projected: list[int | None] = []
        for count in buckets:
            if count is None:
                projected.append(None)
                continue
            if isinstance(count, bool) or not isinstance(count, (int, float)):
                raise RuntimeError("Zammad returned an invalid report bucket")
            if isinstance(count, float) and (not isfinite(count) or not count.is_integer()):
                raise RuntimeError("Zammad returned an invalid report bucket")
            integer_count = int(count)
            if integer_count < 0 and not allow_negative:
                raise RuntimeError("Zammad returned an invalid negative report bucket")
            projected.append(integer_count)
        result[name] = projected
    return result
