from collections.abc import Mapping
from typing import Any


def project_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return system report metadata")
    descriptions = value.get("descriptions")
    fetched = value.get("fetch")
    if not isinstance(descriptions, list) or not isinstance(fetched, Mapping):
        raise RuntimeError("Zammad returned an invalid system report")
    report = fetched.get("system_report")
    if not isinstance(report, Mapping):
        raise RuntimeError("Zammad returned an invalid system report payload")

    summary: dict[str, Any] = {}
    version = report.get("version")
    if isinstance(version, (str, int, float)):
        summary["version"] = version

    postgres = report.get("postgre_sql")
    if isinstance(postgres, Mapping):
        summary["database"] = {
            key: postgres[key]
            for key in ("version", "database_size_human", "attachments_size_human")
            if isinstance(postgres.get(key), (str, int, float))
        }

    entities = report.get("entities")
    if isinstance(entities, Mapping):
        counts = entities.get("counts")
        if isinstance(counts, Mapping):
            summary["entity_counts"] = {
                str(key): count
                for key, count in counts.items()
                if isinstance(key, str) and isinstance(count, int) and not isinstance(count, bool)
            }

    channels = report.get("channel")
    if isinstance(channels, Mapping):
        summary["active_channels"] = {
            str(key): count
            for key, count in channels.items()
            if isinstance(key, str) and isinstance(count, int) and not isinstance(count, bool)
        }

    failed_emails = report.get("failed_emails")
    if isinstance(failed_emails, int) and not isinstance(failed_emails, bool):
        summary["failed_email_count"] = failed_emails

    ruby = report.get("ruby")
    if isinstance(ruby, Mapping):
        interpreter = ruby.get("interpreter")
        if isinstance(interpreter, Mapping):
            summary["runtime"] = {
                key: interpreter[key]
                for key in ("platform", "version", "engine", "patchlevel")
                if isinstance(interpreter.get(key), (str, int, float))
            }

    addons = report.get("addons")
    if isinstance(addons, list):
        summary["addons"] = [
            {key: item[key] for key in ("name", "version", "vendor", "state") if isinstance(item.get(key), (str, int, float))}
            for item in addons
            if isinstance(item, Mapping)
        ]

    summary["descriptions"] = [item for item in descriptions if isinstance(item, str)]
    summary["sensitive_sections_returned"] = False
    return summary
