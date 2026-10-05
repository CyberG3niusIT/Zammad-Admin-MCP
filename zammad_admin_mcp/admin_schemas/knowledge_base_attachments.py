import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from typing import Any


_MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
_MAX_ENCODED_BYTES = ((_MAX_ATTACHMENT_BYTES + 2) // 3) * 4
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MIME_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(?:;[^\x00-\x1f\x7f]*)?\Z")


def project_snapshot(value: Any, knowledge_base_id: int, answer_id: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeError("Zammad did not return a Knowledge Base answer")
    assets = value.get("assets")
    answer_assets = assets.get("KnowledgeBaseAnswer") if isinstance(assets, Mapping) else None
    answer = answer_assets.get(str(answer_id)) if isinstance(answer_assets, Mapping) else None
    if not isinstance(answer, Mapping) or answer.get("id") != answer_id:
        raise RuntimeError("Zammad returned an invalid Knowledge Base answer")
    category_id = answer.get("category_id")
    if isinstance(category_id, bool) or not isinstance(category_id, int) or category_id <= 0:
        raise RuntimeError("Zammad returned an invalid Knowledge Base answer category")
    raw_attachments = answer.get("attachments", [])
    if not isinstance(raw_attachments, list):
        raise RuntimeError("Zammad returned invalid Knowledge Base attachment metadata")
    attachments = []
    for item in raw_attachments:
        if not isinstance(item, Mapping):
            raise RuntimeError("Zammad returned invalid Knowledge Base attachment metadata")
        attachment_id = item.get("id")
        filename = item.get("filename")
        size = item.get("size")
        if isinstance(attachment_id, bool) or not isinstance(attachment_id, int) or attachment_id <= 0:
            raise RuntimeError("Zammad returned an invalid Knowledge Base attachment ID")
        if not isinstance(filename, str) or not filename or len(filename) > 255:
            raise RuntimeError("Zammad returned an invalid Knowledge Base attachment filename")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise RuntimeError("Zammad returned an invalid Knowledge Base attachment size")
        projected = {"id": attachment_id, "filename": filename, "size_bytes": size}
        content_type = item.get("preferences", {}).get("Content-Type") if isinstance(item.get("preferences"), Mapping) else None
        if isinstance(content_type, str):
            projected["content_type"] = content_type
        attachments.append(projected)
    attachments.sort(key=lambda item: item["id"])
    if len({item["id"] for item in attachments}) != len(attachments):
        raise RuntimeError("Zammad returned duplicate Knowledge Base attachment IDs")
    return {
        "knowledge_base_id": knowledge_base_id,
        "answer_id": answer_id,
        "category_id": category_id,
        "attachments": attachments,
    }


def validate_upload(filename: Any, content_type: Any, content_base64: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(filename, str) or not filename or len(filename) > 255 or _CONTROL.search(filename):
        raise ValueError("filename must be a plain filename of at most 255 characters")
    if filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise ValueError("filename must not contain a path")
    if not isinstance(content_type, str) or len(content_type) > 255 or not _MIME_TYPE.fullmatch(content_type):
        raise ValueError("content_type must be a valid MIME type string")
    if not isinstance(content_base64, str) or not content_base64:
        raise ValueError("content_base64 must contain the attachment file")
    if len(content_base64) > _MAX_ENCODED_BYTES:
        raise ValueError("Knowledge Base attachment exceeds the MCP 10 MiB upload limit")
    try:
        content = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("content_base64 contains invalid base64 data") from exc
    if not content:
        raise ValueError("Empty Knowledge Base attachments are not supported")
    if len(content) > _MAX_ATTACHMENT_BYTES:
        raise ValueError("Knowledge Base attachment exceeds the MCP 10 MiB upload limit")
    digest = hashlib.sha256(content).hexdigest()
    return {"filename": filename, "content_type": content_type, "content": content}, {
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(content),
        "sha256": digest,
        "content_returned": False,
    }
