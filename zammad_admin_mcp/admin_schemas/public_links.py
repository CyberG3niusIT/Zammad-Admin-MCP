"""Validated payloads for Zammad 7.1.2 public-link CRUD."""

from collections.abc import Mapping
from urllib.parse import urlsplit
from typing import Any


def validate_payload(operation: str, data: Any) -> None:
    allowed = {"link", "title", "screen", "prio"}
    required = {"link", "title", "screen"} if operation == "create" else set()
    if not isinstance(data, Mapping) or not data or set(data) - allowed or not required.issubset(data):
        raise ValueError("public_links accepts link, title, screen, and optional prio; create requires link, title, and screen")
    if "link" in data:
        link = data["link"]
        if not isinstance(link, str) or not link or len(link) > 500:
            raise ValueError("link must be a non-empty URL of at most 500 characters")
        try:
            parsed = urlsplit(link)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("link must be a valid HTTP or HTTPS URL") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("link must be an absolute HTTP or HTTPS URL without embedded credentials")
    if "title" in data and (not isinstance(data["title"], str) or not data["title"].strip() or len(data["title"]) > 200):
        raise ValueError("title must be a non-empty string of at most 200 characters")
    if "screen" in data:
        screens = data["screen"]
        available = {"login", "signup", "password_reset"}
        if (
            not isinstance(screens, list) or not screens
            or any(not isinstance(screen, str) or screen not in available for screen in screens)
            or len(set(screens)) != len(screens)
        ):
            raise ValueError("screen must be a non-empty list of unique login, signup, or password_reset values")
    if "prio" in data and (isinstance(data["prio"], bool) or not isinstance(data["prio"], int)):
        raise ValueError("prio must be an integer")
