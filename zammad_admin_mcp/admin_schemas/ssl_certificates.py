import base64
import binascii
import hashlib
import re
import ssl
from collections.abc import Mapping
from typing import Any


_PEM_CERTIFICATE = re.compile(
    r"\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\s*\Z"
)
_MAX_CERTIFICATE_BYTES = 1024 * 1024
_MAX_PEM_CHARACTERS = 2 * 1024 * 1024


def validate_payload(data: Any) -> tuple[dict[str, str], dict[str, Any]]:
    if not isinstance(data, Mapping) or set(data) != {"certificate"}:
        raise ValueError("SSL certificate creation requires exactly one PEM certificate")
    certificate = data["certificate"]
    if not isinstance(certificate, str):
        raise ValueError("certificate must be PEM text")
    if len(certificate) > _MAX_PEM_CHARACTERS:
        raise ValueError("certificate PEM input must be no larger than 2 MiB")
    match = _PEM_CERTIFICATE.fullmatch(certificate)
    if match is None:
        raise ValueError("certificate must contain exactly one PEM CERTIFICATE block")
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=certificate)
    except (binascii.Error, ValueError, ssl.SSLError) as exc:
        raise ValueError("certificate contains invalid X.509 base64 data") from exc
    if not der or len(der) > _MAX_CERTIFICATE_BYTES:
        raise ValueError("certificate must be non-empty and no larger than 1 MiB")
    return {"certificate": certificate}, {
        "sha1_fingerprint": hashlib.sha1(der, usedforsecurity=False).hexdigest(),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "der_size_bytes": len(der),
        "certificate_data_returned": False,
    }


def project_certificate(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    fields = {"id", "fingerprint", "subject", "not_before", "not_after", "ca", "created_at", "updated_at"}
    return {key: value[key] for key in fields if key in value}


def project_collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return SSL certificate assets")
    assets = value.get("SSLCertificate")
    if not isinstance(assets, Mapping):
        raise RuntimeError("Zammad did not return SSL certificate metadata")
    return [project_certificate(item) for item in assets.values() if isinstance(item, Mapping)]
