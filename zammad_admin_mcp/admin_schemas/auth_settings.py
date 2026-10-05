from collections.abc import Callable, Mapping
from typing import Any


_SCHEMAS: dict[str, dict[str, str]] = {
    "auth_google_oauth2_credentials": {
        "client_id": "text",
        "client_secret": "secret",
    },
    "auth_saml_credentials": {
        "display_name": "text",
        "idp_sso_target_url": "text",
        "idp_slo_service_url": "text",
        "idp_cert": "certificate",
        "idp_cert_fingerprint": "text",
        "name_identifier_format": "text",
        "uid_attribute": "text",
        "ssl_verify": "boolean",
        "security": "security_mode",
        "certificate": "certificate",
        "private_key": "secret",
        "private_key_secret": "secret",
    },
    "auth_openid_connect_credentials": {
        "display_name": "text",
        "identifier": "text",
        "issuer": "text",
        "uid_field": "text",
        "scope": "text",
        "pkce": "boolean",
    },
}
_HIDDEN_FIELDS = {
    "auth_google_oauth2_credentials": {"client_secret"},
    "auth_saml_credentials": {"idp_cert", "certificate", "private_key", "private_key_secret"},
    "auth_openid_connect_credentials": set(),
}
_READ_ONLY_FIELDS = {
    "auth_google_oauth2_credentials": {"callback_url"},
    "auth_saml_credentials": {"callback_url"},
    "auth_openid_connect_credentials": {"callback_url"},
}
_MAX_FIELD_CHARS = 65536


def supports(name: Any) -> bool:
    return isinstance(name, str) and name in _SCHEMAS


def _present(value: Any) -> bool:
    return value not in (None, "", "**********")


def project_setting(value: Mapping[str, Any]) -> dict[str, Any]:
    name = value.get("name")
    schema = _SCHEMAS.get(name) if isinstance(name, str) else None
    if schema is None:
        raise ValueError("Unsupported authentication credential setting")
    result = {key: nested for key, nested in value.items() if key not in {"state_current", "state_initial"}}
    hidden = _HIDDEN_FIELDS[name]
    for state_name in ("state_current", "state_initial"):
        state = value.get(state_name)
        if not isinstance(state, Mapping):
            continue
        raw = state.get("value")
        safe_state = {key: nested for key, nested in state.items() if key != "value"}
        if isinstance(raw, Mapping):
            safe_value = {
                key: nested for key, nested in raw.items()
                if key in schema and key not in hidden or key in _READ_ONLY_FIELDS[name]
            }
            safe_value["provider_auth_material_configured"] = any(_present(raw.get(key)) for key in hidden)
            safe_value["idp_certificate_configured"] = (
                _present(raw.get("idp_cert")) if name == "auth_saml_credentials" else None
            )
            safe_value["saml_certificate_configured"] = (
                _present(raw.get("certificate")) if name == "auth_saml_credentials" else None
            )
            safe_state["value"] = safe_value
        else:
            safe_state["value"] = raw
        result[state_name] = safe_state
    return result


def prepare_update(
    payload: Any,
    before: Any,
    materialize_secret_values: Callable[[Mapping[str, Any]], tuple[dict[str, Any], dict[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    if not isinstance(payload, Mapping) or set(payload) != {"name", "state_current"}:
        raise ValueError("Authentication credential updates require name and state_current only")
    name = payload.get("name")
    schema = _SCHEMAS.get(name) if isinstance(name, str) else None
    if schema is None:
        raise ValueError("Unsupported authentication credential setting")
    if not isinstance(before, Mapping) or before.get("name") != name:
        raise RuntimeError("Zammad did not return the selected authentication setting")
    proposed_state = payload.get("state_current")
    proposed = proposed_state.get("value") if isinstance(proposed_state, Mapping) else None
    if not isinstance(proposed, Mapping) or not proposed:
        raise ValueError("state_current.value must be a non-empty object of authentication fields")
    unsupported = set(proposed) - set(schema)
    if "callback_url" in proposed:
        unsupported.add("callback_url")
    if unsupported:
        raise ValueError(f"Unsupported or read-only authentication fields: {', '.join(sorted(unsupported))}")
    current_state = before.get("state_current")
    current_value = current_state.get("value") if isinstance(current_state, Mapping) else None
    if not isinstance(current_value, Mapping):
        raise RuntimeError("Zammad did not return the current authentication settings")
    merged = dict(current_value)
    preview_merged = dict(current_value)
    effects = [f"Change {name} sign-in configuration; if this provider is active, user authentication may fail."]

    for field, requested in proposed.items():
        kind = schema[field]
        if kind == "secret":
            if requested in (None, ""):
                merged[field] = ""
                preview_merged[field] = ""
                effects.append(f"Clear {field}")
                continue
            if not isinstance(requested, Mapping) or set(requested) != {"$secret_env"}:
                raise ValueError(f"{field} must use a process environment secret reference or an empty value to clear it")
            resolved, preview = materialize_secret_values({field: requested})
            if not isinstance(resolved.get(field), str) or len(resolved[field]) > _MAX_FIELD_CHARS:
                raise ValueError(f"{field} must be text of at most {_MAX_FIELD_CHARS} characters")
            merged[field] = resolved[field]
            preview_merged[field] = preview[field]
            effects.append(f"Set {field} from a process environment reference")
            continue
        if kind == "boolean":
            if not isinstance(requested, bool):
                raise ValueError(f"{field} must be a boolean")
        elif kind == "security_mode":
            if not isinstance(requested, str) or requested not in {"off", "on", "sign", "encrypt"}:
                raise ValueError("security must be off, on, sign, or encrypt")
        elif kind == "certificate":
            if not isinstance(requested, str) or len(requested) > _MAX_FIELD_CHARS:
                raise ValueError(f"{field} must be text of at most {_MAX_FIELD_CHARS} characters")
            if requested and "-----BEGIN CERTIFICATE-----" not in requested:
                raise ValueError(f"{field} must contain a PEM certificate")
        elif kind == "text":
            if not isinstance(requested, str) or len(requested) > _MAX_FIELD_CHARS:
                raise ValueError(f"{field} must be text of at most {_MAX_FIELD_CHARS} characters")
        merged[field] = requested
        preview_merged[field] = requested

    write_payload = {"name": name, "state_current": {"value": merged}}
    preview_payload = {"name": name, "state_current": {"value": preview_merged}}
    return write_payload, preview_payload, effects
