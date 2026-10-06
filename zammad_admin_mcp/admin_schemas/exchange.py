"""Safe projections for Exchange integration status."""

from collections.abc import Mapping
from typing import Any


def project_exchange_integration_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid Exchange integration response")

    oauth = value.get("oauth")
    if oauth is not None and not isinstance(oauth, Mapping):
        raise RuntimeError("Zammad returned invalid Exchange OAuth metadata")

    credential_ids = value.get("external_credential_ids", [])
    if not isinstance(credential_ids, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 1
        for item in credential_ids
    ):
        raise RuntimeError("Zammad returned invalid Exchange credential metadata")

    return {
        "oauth_record_present": bool(oauth),
        "registered_application_count": len(credential_ids),
    }
