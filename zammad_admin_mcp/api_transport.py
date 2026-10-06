from __future__ import annotations

import json
import os
import re
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
    max_response_bytes: int | None = None,
) -> Any:
    knowledge_base_attachment_upload = (
        method == "POST"
        and re.fullmatch(r"/knowledge_bases/\d+/answers/\d+/attachments", path) is not None
    )
    if knowledge_base_attachment_upload and (files is None or set(files) != {"file"}):
        raise ValueError("Knowledge Base attachment upload requires one file field")
    if (method, path) == ("POST", "/packages") and files is not None and set(files) != {"file_upload"}:
        raise ValueError("Package installation requires one package file field")
    if files is not None and (method, path) != ("POST", "/packages") and not knowledge_base_attachment_upload:
        raise ValueError("Multipart upload is only supported for fixed package and Knowledge Base attachment routes")
    if accept_package_redirect and (method, path) != ("POST", "/packages"):
        raise ValueError("Redirect acceptance is only supported for package installation")
    headers = _headers()
    if files is None:
        headers["Content-Type"] = "application/json"
    async with httpx.AsyncClient(
        base_url=_api_root(), headers=headers,
        timeout=httpx.Timeout(120.0 if (method, path) == ("POST", "/users/import") else 30.0), follow_redirects=False,
    ) as client:
        request_options: dict[str, Any] = {"params": params}
        if files is None:
            request_options["json"] = payload
        else:
            request_options["files"] = files
        if max_response_bytes is None:
            response = await client.request(method, path.lstrip("/"), **request_options)
        else:
            if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes < 1:
                raise ValueError("Response size limit must be a positive integer")
            async with client.stream(method, path.lstrip("/"), **request_options) as streamed:
                if streamed.is_redirect:
                    raise RuntimeError("Zammad redirected an API request; check ZAMMAD_URL")
                if streamed.status_code >= 400:
                    raise RuntimeError(f"Zammad API request failed with HTTP {streamed.status_code}; check endpoint, payload, and token permissions")
                content = bytearray()
                async for chunk in streamed.aiter_bytes():
                    if len(content) + len(chunk) > max_response_bytes:
                        raise RuntimeError("Zammad API response exceeded the configured size limit")
                    content.extend(chunk)
            try:
                return json.loads(content)
            except json.JSONDecodeError as exc:
                raise RuntimeError("Zammad returned a non-JSON API response") from exc
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
