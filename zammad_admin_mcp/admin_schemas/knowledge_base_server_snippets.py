from collections.abc import Mapping
from typing import Any


def project(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return Knowledge Base server snippets")
    address = value.get("address")
    address_type = value.get("address_type")
    snippets = value.get("snippets")
    if not isinstance(address, str) or not address or len(address) > 1024:
        raise RuntimeError("Zammad returned an invalid Knowledge Base address")
    if address_type not in {"domain", "path"}:
        raise RuntimeError("Zammad returned an invalid Knowledge Base address type")
    if not isinstance(snippets, Mapping) or set(snippets) != {"nginx", "apache"}:
        raise RuntimeError("Zammad returned an invalid server snippet set")
    projected_snippets = {}
    for name in ("nginx", "apache"):
        snippet = snippets[name]
        if not isinstance(snippet, str) or len(snippet) > 64_000:
            raise RuntimeError("Zammad returned an invalid server snippet")
        projected_snippets[name] = snippet
    return {
        "address": address,
        "address_type": address_type,
        "snippets": projected_snippets,
    }
