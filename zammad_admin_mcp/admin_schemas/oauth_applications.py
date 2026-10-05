from collections.abc import Mapping
import ipaddress
from typing import Any
from urllib.parse import urlsplit


_FIELDS = {"name", "redirect_uri"}


def validate_payload(operation: str, value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or not value or set(value) - _FIELDS:
        raise ValueError("OAuth applications accept only name and redirect_uri")
    if operation == "create" and set(value) != _FIELDS:
        raise ValueError("OAuth application creation requires name and redirect_uri")
    result = dict(value)
    if "name" in result:
        name = result["name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 100 or "\n" in name or "\r" in name:
            raise ValueError("name must be a non-empty single line of at most 100 characters")
    if "redirect_uri" in result:
        redirects = result["redirect_uri"]
        if not isinstance(redirects, str) or not redirects.strip() or len(redirects) > 250:
            raise ValueError("redirect_uri must contain at least one URI and be at most 250 characters")
        entries = [item.strip() for item in redirects.splitlines()]
        if not entries or any(not item or any(char.isspace() for char in item) for item in entries):
            raise ValueError("redirect_uri must contain one non-empty URI per line")
        if len(entries) != len(set(entries)):
            raise ValueError("redirect_uri must not repeat a URI")
        for entry in entries:
            parsed = urlsplit(entry)
            if not parsed.scheme or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("redirect_uri entries must be absolute and must not contain credentials or fragments")
            if parsed.scheme in {"http", "https"} and not parsed.hostname:
                raise ValueError("HTTP redirect_uri entries must include a host")
    preview = dict(result)
    if "redirect_uri" in result:
        warnings: list[str] = []
        for entry in result["redirect_uri"].splitlines():
            parsed = urlsplit(entry.strip())
            scheme = parsed.scheme.lower()
            if scheme in {"blob", "data", "file", "filesystem", "javascript", "vbscript"}:
                raise ValueError("redirect_uri must not use a browser-executable or local-file scheme")
            if scheme == "http":
                host = parsed.hostname or ""
                loopback = host.lower() == "localhost" or host.lower().endswith(".localhost")
                try:
                    loopback = loopback or ipaddress.ip_address(host).is_loopback
                except ValueError:
                    pass
                if not loopback:
                    warnings.append("A non-loopback HTTP redirect URI does not protect the authorization response with TLS.")
        if warnings:
            preview["redirect_uri_warnings"] = sorted(set(warnings))
    return result, preview


def project_application(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return an OAuth application")
    fields = {"id", "name", "redirect_uri", "uid", "confidential", "scopes", "created_at", "updated_at", "clients"}
    result = {key: value[key] for key in fields if key in value}
    result["client_key_present"] = isinstance(value.get("secret"), str) and bool(value["secret"])
    return result


def project_collection(value: Any) -> Any:
    if isinstance(value, list):
        return [project_application(item) for item in value]
    if isinstance(value, Mapping) and isinstance(value.get("items"), list):
        return {**value, "items": [project_application(item) for item in value["items"]]}
    if isinstance(value, Mapping):
        assets = value.get("assets")
        applications = assets.get("Application") if isinstance(assets, Mapping) else None
        if isinstance(applications, Mapping):
            return {
                **{key: nested for key, nested in value.items() if key != "assets"},
                "assets": {
                    "Application": {
                        str(application_id): project_application(application)
                        for application_id, application in applications.items()
                        if isinstance(application, Mapping)
                    }
                },
            }
    raise RuntimeError("Zammad did not return an OAuth application list")
