from __future__ import annotations

import base64
import binascii
import hashlib
import re
import ssl
from collections.abc import Mapping
from typing import Any


_MAX_KEY_CHARACTERS = 2 * 1024 * 1024
_CERTIFICATE_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+?)\s*-----END CERTIFICATE-----"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:PGP PRIVATE KEY BLOCK|RSA PRIVATE KEY|DSA PRIVATE KEY|EC PRIVATE KEY|ENCRYPTED PRIVATE KEY|PRIVATE KEY)-----"
)
_SAFE_PGP_FIELDS = {
    "id", "fingerprint", "name", "email_addresses", "expires_at",
    "domain_alias", "created_at", "updated_at",
}
_SAFE_SMIME_FIELDS = {
    "id", "subject", "doc_hash", "fingerprint", "not_before_at", "not_after_at",
    "created_at", "updated_at", "subject_alternative_name", "usage",
}


def project_pgp_key(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    projected = {key: value[key] for key in _SAFE_PGP_FIELDS if key in value}
    projected["private_key_configured"] = bool(value.get("key") or value.get("secret"))
    projected["passphrase_configured"] = bool(value.get("passphrase"))
    return projected


def project_pgp_collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RuntimeError("Zammad did not return PGP key metadata")
    return [project_pgp_key(item) for item in value if isinstance(item, Mapping)]


def project_smime_certificate(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    projected = {key: value[key] for key in _SAFE_SMIME_FIELDS if key in value}
    projected["private_key_configured"] = bool(value.get("private_key"))
    projected["private_key_secret_configured"] = bool(value.get("private_key_secret"))
    return projected


def project_smime_collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RuntimeError("Zammad did not return S/MIME certificate metadata")
    return [project_smime_certificate(item) for item in value if isinstance(item, Mapping)]


def project_smime_private_key_collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise RuntimeError("Zammad did not return S/MIME private key metadata")
    return [{
        "id": item.get("id"),
        "private_key_configured": bool(item.get("private_key")),
        "private_key_secret_configured": bool(item.get("private_key_secret")),
    } for item in value if isinstance(item, Mapping)]


def validate_pgp_create(data: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(data, Mapping) or not {"private_key"}.issubset(data) or set(data) - {
        "private_key", "passphrase", "domain_alias",
    }:
        raise ValueError("PGP key creation requires private_key and accepts optional passphrase and domain_alias")
    private_key = data["private_key"]
    is_secret_reference = isinstance(private_key, Mapping) and set(private_key) == {"$secret_env"}
    if "passphrase" in data and not (isinstance(data["passphrase"], Mapping) and set(data["passphrase"]) == {"$secret_env"}):
        raise ValueError("passphrase must be supplied by a process environment reference")
    if not is_secret_reference:
        if not isinstance(private_key, str) or len(private_key) > _MAX_KEY_CHARACTERS:
            raise ValueError("private_key must be an environment reference or public PGP key text")
        if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in private_key or "-----BEGIN PGP PRIVATE KEY BLOCK-----" in private_key:
            raise ValueError("Inline PGP material must be a public key; private keys require a process environment reference")
    if "domain_alias" in data and (not isinstance(data["domain_alias"], str) or len(data["domain_alias"]) > 255):
        raise ValueError("domain_alias must be text no longer than 255 characters")
    return dict(data), {
        "private_key": "[KEY PROVIDED]",
        "passphrase": "[SECRET PROVIDED BY PROCESS ENVIRONMENT]" if "passphrase" in data else None,
        "domain_alias": data.get("domain_alias"),
        "private_key_returned": False,
    }


def validate_pgp_material(value: Any) -> None:
    if not isinstance(value, str) or not value or len(value) > _MAX_KEY_CHARACTERS:
        raise ValueError("private_key must be non-empty text no larger than 2 MiB")
    if not (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----" in value
        or "-----BEGIN PGP PUBLIC KEY BLOCK-----" in value
    ):
        raise ValueError("private_key must contain an armored PGP key")


def validate_smime_certificate(certificate: Any) -> tuple[dict[str, str], dict[str, Any]]:
    if not isinstance(certificate, str) or not certificate or len(certificate) > _MAX_KEY_CHARACTERS:
        raise ValueError("certificate must be PEM text no larger than 2 MiB")
    blocks = list(_CERTIFICATE_BLOCK.finditer(certificate))
    residue = _CERTIFICATE_BLOCK.sub("", certificate)
    if not blocks or "-----BEGIN" in residue or "-----END" in residue or residue.strip():
        raise ValueError("certificate must contain one or more PEM CERTIFICATE blocks only")
    fingerprints: list[str] = []
    for block in blocks:
        try:
            der = base64.b64decode(re.sub(r"\s+", "", block.group(1)), validate=True)
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=block.group(0))
        except (binascii.Error, ValueError, ssl.SSLError) as exc:
            raise ValueError("certificate contains invalid X.509 data") from exc
        fingerprints.append(hashlib.sha256(der).hexdigest())
    return {"certificate": certificate}, {
        "certificate_count": len(fingerprints),
        "certificate_sha256_fingerprints": fingerprints,
        "certificate_data_returned": False,
    }


def validate_smime_private_key(data: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(data, Mapping) or "private_key" not in data or set(data) - {"private_key", "secret"}:
        raise ValueError("S/MIME private key setup requires private_key and accepts optional secret")
    for field in ("private_key", "secret"):
        if field in data and not (isinstance(data[field], Mapping) and set(data[field]) == {"$secret_env"}):
            raise ValueError(f"{field} must be supplied by a process environment reference")
    return dict(data), {
        "private_key": "[SECRET PROVIDED BY PROCESS ENVIRONMENT]",
        "secret": "[SECRET PROVIDED BY PROCESS ENVIRONMENT]" if "secret" in data else None,
        "private_key_returned": False,
    }


def validate_materialized_private_key(data: Mapping[str, Any], field: str) -> None:
    value = data.get(field)
    if not isinstance(value, str) or not value or len(value) > _MAX_KEY_CHARACTERS:
        raise ValueError(f"{field} must be non-empty text no larger than 2 MiB")
    if _PRIVATE_KEY_BLOCK.search(value) is None:
        raise ValueError(f"{field} must contain armored private key material")
