import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from typing import Any


_DATA_URL = re.compile(r"data:(image/(?:png|jpeg|gif|webp|svg\+xml));base64,([A-Za-z0-9+/]*={0,2})\Z")
_MAX_ORIGINAL_BYTES = 8 * 1024 * 1024
_MAX_RESIZED_BYTES = 1024 * 1024


def validate_payload(data: Any) -> dict[str, Any]:
    if not isinstance(data, Mapping) or not data or set(data) - {"logo", "logo_resize"}:
        raise ValueError("Product logo updates accept logo and logo_resize data URLs")
    if not any(key in data for key in {"logo", "logo_resize"}):
        raise ValueError("At least one product logo image is required")
    preview: dict[str, Any] = {}
    for key, limit in (("logo", _MAX_ORIGINAL_BYTES), ("logo_resize", _MAX_RESIZED_BYTES)):
        if key not in data:
            continue
        value = data[key]
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a base64 image data URL")
        match = _DATA_URL.fullmatch(value)
        if match is None:
            raise ValueError(f"{key} must use PNG, JPEG, GIF, WebP, or SVG image data")
        try:
            decoded = base64.b64decode(match.group(2), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"{key} contains invalid base64 data") from exc
        if not decoded or len(decoded) > limit:
            raise ValueError(f"{key} must be non-empty and no larger than {limit} bytes")
        preview[key] = {
            "mime_type": match.group(1),
            "size_bytes": len(decoded),
            "sha256": hashlib.sha256(decoded).hexdigest(),
        }
    return {"setting": "product_logo", "images": preview, "stored_image_data_returned": False}
