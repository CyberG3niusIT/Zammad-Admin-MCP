"""Safe projections for Exchange integration data."""

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


def project_exchange_configuration(value: Any) -> dict[str, Any]:
    """Project the saved Exchange setting without returning contact examples."""
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad returned an invalid Exchange setting")

    projected = {str(key): item for key, item in value.items()}
    for state_key in ("state_current", "state_initial"):
        state = value.get(state_key)
        if not isinstance(state, Mapping):
            continue
        setting_value = state.get("value")
        if not isinstance(setting_value, Mapping):
            continue

        safe_config = {
            str(key): setting_value[key]
            for key in ("endpoint", "disable_ssl_verify", "user", "auth_type", "folders", "attributes")
            if key in setting_value
        }
        safe_config["password_configured"] = bool(setting_value.get("password"))
        safe_config["access_token_configured"] = bool(setting_value.get("access_token"))

        wizard_data = setting_value.get("wizardData")
        if isinstance(wizard_data, Mapping):
            backend_folders = wizard_data.get("backend_folders")
            backend_attributes = wizard_data.get("backend_attributes")
            safe_config["wizard_data_summary"] = {
                "backend_folder_count": len(backend_folders) if isinstance(backend_folders, (list, Mapping)) else 0,
                "backend_attribute_count": len(backend_attributes) if isinstance(backend_attributes, (list, Mapping)) else 0,
                "user_attribute_mapping_count": len(wizard_data.get("attributes", {}))
                if isinstance(wizard_data.get("attributes"), Mapping) else 0,
            }

        safe_state = {str(key): item for key, item in state.items()}
        safe_state["value"] = safe_config
        projected[state_key] = safe_state

    return projected
