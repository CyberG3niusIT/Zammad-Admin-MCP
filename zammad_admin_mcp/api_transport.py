from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


def _api_root() -> str:
    raw_url = os.environ.get("ZAMMAD_URL", "").strip()
    token = os.environ.get("ZAMMAD_HTTP_TOKEN", "").strip()
    if not raw_url or not token:
        raise ValueError("ZAMMAD_URL and ZAMMAD_HTTP_TOKEN must be configured")
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ZAMMAD_URL must be an absolute HTTP or HTTPS URL")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("ZAMMAD_URL must use HTTPS unless it targets a loopback address")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("ZAMMAD_URL must not contain credentials, a query, or a fragment")
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v1"):
        path = f"{path}/api/v1" if path else "/api/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _headers() -> dict[str, str]:
    token = os.environ.get("ZAMMAD_HTTP_TOKEN", "").strip()
    if not token:
        raise ValueError("ZAMMAD_HTTP_TOKEN must be configured")
    return {"Authorization": f"Token token={token}", "Accept": "application/json"}


async def request(
    method: str,
    path: str,
    payload: Any = None,
    params: dict[str, Any] | None = None,
    files: dict[str, tuple[str, bytes, str]] | None = None,
    accept_package_redirect: bool = False,
) -> Any:
    if files is not None and (method, path) != ("POST", "/packages"):
        raise ValueError("Multipart upload is only supported for package installation")
    if accept_package_redirect and (method, path) != ("POST", "/packages"):
        raise ValueError("Redirect acceptance is only supported for package installation")
    headers = _headers()
    if files is None:
        headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient(
        base_url=_api_root(), headers=headers,
        timeout=httpx.Timeout(30.0), follow_redirects=False,
    ) as client:
        request_options: dict[str, Any] = {"params": params}
        if files is None:
            request_options["json"] = payload
        else:
            request_options["files"] = files
        response = await client.request(method, path.lstrip("/"), **request_options)
    if response.is_redirect:
        redirect = urlsplit(response.headers.get("location", ""))
        if (
            accept_package_redirect
            and response.status_code in {302, 303}
            and not redirect.scheme
            and not redirect.netloc
            and redirect.path == "/"
            and redirect.query == ""
            and redirect.fragment == "system/package"
        ):
            return {"package_redirect_accepted": True}
        raise RuntimeError("Zammad redirected an API request; check ZAMMAD_URL")
    if response.status_code >= 400:
        raise RuntimeError(f"Zammad API request failed with HTTP {response.status_code}; check endpoint, payload, and token permissions")
    if not response.content:
        return {}
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError("Zammad returned a non-JSON API response") from exc
