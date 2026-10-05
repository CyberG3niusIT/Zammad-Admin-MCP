import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


_PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PACKAGE_VERSION = re.compile(r"[0-9][A-Za-z0-9.+_-]{0,127}\Z")
_DEPENDENCY = re.compile(r"(?:>=|==|<=) \d+\.\d+\.\d+\Z")
_MAX_FILE_BYTES = 25 * 1024 * 1024
_MAX_PACKAGE_JSON_BYTES = 40 * 1024 * 1024


def validate_install_payload(package: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(package, Mapping) or set(package) - {
        "name", "version", "vendor", "url", "dependencies", "files", "migrations",
    }:
        raise ValueError("Package data contains unsupported fields")
    name = package.get("name")
    version = package.get("version")
    files = package.get("files")
    if not isinstance(name, str) or not _PACKAGE_NAME.fullmatch(name):
        raise ValueError("Package name must use letters, numbers, dots, underscores, or hyphens")
    if not isinstance(version, str) or not _PACKAGE_VERSION.fullmatch(version):
        raise ValueError("Package version must be a non-empty version string")
    if not isinstance(files, list) or not files:
        raise ValueError("Package data must contain at least one file")
    vendor = package.get("vendor")
    if vendor is not None and (not isinstance(vendor, str) or len(vendor) > 255):
        raise ValueError("Package vendor must be a string no longer than 255 characters")
    url = package.get("url")
    if url is not None:
        parsed = urlsplit(url) if isinstance(url, str) else None
        if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Package URL must be an absolute HTTP(S) URL without embedded credentials")
    dependencies = package.get("dependencies", {})
    if not isinstance(dependencies, Mapping):
        raise ValueError("Package dependencies must be an object")
    for dependency_name, requirement in dependencies.items():
        if not isinstance(dependency_name, str) or not _PACKAGE_NAME.fullmatch(dependency_name):
            raise ValueError("Package dependency names are invalid")
        if not isinstance(requirement, str) or not _DEPENDENCY.fullmatch(requirement):
            raise ValueError("Package dependencies must use Zammad's >=, ==, or <= three-part version format")

    seen_locations: set[str] = set()
    file_previews: list[dict[str, Any]] = []
    total_bytes = 0
    for item in files:
        if not isinstance(item, Mapping) or set(item) - {"location", "content", "permission"} or not {"location", "content"}.issubset(item):
            raise ValueError("Each package file must contain only location, content, and optional permission")
        location = item["location"]
        content = item["content"]
        if not isinstance(location, str) or not location or location.startswith(("/", "\\")) or "\\" in location:
            raise ValueError("Package file locations must be relative POSIX paths")
        if any(part in {"", ".", ".."} for part in location.split("/")) or "%2e%2e" in location.lower():
            raise ValueError("Package file location contains an unsafe path component")
        if location in seen_locations:
            raise ValueError("Package file locations must be unique")
        seen_locations.add(location)
        if not isinstance(content, str):
            raise ValueError("Package file content must be base64 text")
        try:
            decoded = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Package file content contains invalid base64") from exc
        total_bytes += len(decoded)
        if total_bytes > _MAX_FILE_BYTES:
            raise ValueError("Decoded package files must total no more than 25 MiB")
        permission = item.get("permission", "644")
        if not isinstance(permission, str) or not re.fullmatch(r"[0-7]{3,4}", permission) or int(permission, 8) > 0o777:
            raise ValueError("Package file permission must be a valid mode from 0000 through 0777")
        file_previews.append({
            "location": location,
            "size_bytes": len(decoded),
            "sha256": hashlib.sha256(decoded).hexdigest(),
            "permission": permission,
        })

    encoded = json.dumps(package, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > _MAX_PACKAGE_JSON_BYTES:
        raise ValueError("Serialized package data must be no larger than 40 MiB")
    prepared = dict(package)
    return prepared, {
        "name": name,
        "version": version,
        "vendor": vendor,
        "url": url,
        "dependencies": dict(dependencies),
        "file_count": len(file_previews),
        "files": file_previews,
        "total_file_bytes": total_bytes,
        "migration_count": len(package.get("migrations", [])) if isinstance(package.get("migrations", []), list) else None,
        "package_sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "package_data_returned": False,
    }


def project_inventory(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not isinstance(value.get("packages"), list):
        raise RuntimeError("Zammad did not return package inventory metadata")
    fields = {"id", "name", "version", "vendor", "url", "state", "created_at", "updated_at"}
    packages = value["packages"]
    if any(not isinstance(item, Mapping) for item in packages):
        raise RuntimeError("Zammad returned invalid package inventory entries")
    return {
        "packages": [{key: item[key] for key in fields if key in item} for item in packages],
        "package_installation": value.get("package_installation") is True,
        "local_gemfiles": value.get("local_gemfiles") is True,
    }
