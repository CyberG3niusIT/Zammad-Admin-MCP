"""Zammad administrative MCP."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from zammad_admin_mcp.api_transport import request as _send_api_request
from zammad_admin_mcp.security import _collect_secret_literals
from zammad_admin_mcp.security import _is_sensitive_setting_name
from zammad_admin_mcp.security import _materialize_secret_values
from zammad_admin_mcp.security import _project_settings
from zammad_admin_mcp.security import _redact_exact_secrets
from zammad_admin_mcp.security import _scrub
from zammad_admin_mcp.security import _store_generated_token
from zammad_admin_mcp.security import _validate_setting_secret_reference
from zammad_admin_mcp.security import _validate_token_create_payload
from zammad_admin_mcp.admin_schemas.chats import validate_payload as validate_chat_payload
from zammad_admin_mcp.admin_schemas.facebook_channels import validate_payload as validate_facebook_channel_payload
from zammad_admin_mcp.admin_schemas.oauth_email_channels import validate_configure_payload as validate_oauth_email_configure_payload
from zammad_admin_mcp.admin_schemas.oauth_email_channels import validate_group_payload as validate_oauth_email_group_payload
from zammad_admin_mcp.admin_schemas.oauth_email_channels import validate_probe_payload as validate_oauth_email_probe_payload
from zammad_admin_mcp.admin_schemas.external_credentials import materialize_payload as materialize_external_credentials
from zammad_admin_mcp.admin_schemas.external_credentials import validate_payload as validate_external_credentials_payload
from zammad_admin_mcp.admin_schemas.exchange import project_exchange_configuration
from zammad_admin_mcp.admin_schemas.exchange import prepare_exchange_dry_run_payload
from zammad_admin_mcp.admin_schemas.exchange import exchange_endpoint_host
from zammad_admin_mcp.admin_schemas.exchange import project_exchange_import_status
from zammad_admin_mcp.admin_schemas.exchange import project_exchange_integration_status
from zammad_admin_mcp.admin_schemas.exchange import project_exchange_connection_result
from zammad_admin_mcp.admin_schemas.exchange import validate_exchange_connection_action
from zammad_admin_mcp.admin_schemas.jobs import validate_payload as validate_job_payload
from zammad_admin_mcp.admin_schemas.ldap_actions import materialize_payload as materialize_ldap_action
from zammad_admin_mcp.admin_schemas.ldap_actions import retain_source_values as retain_ldap_action_values
from zammad_admin_mcp.admin_schemas.ldap_actions import validate_payload as validate_ldap_action_payload
from zammad_admin_mcp.admin_schemas.ldap_sources import materialize_payload as materialize_ldap_source
from zammad_admin_mcp.admin_schemas.ldap_sources import role_ids as ldap_role_ids
from zammad_admin_mcp.admin_schemas.ldap_sources import retain_existing_secret as retain_ldap_secret
from zammad_admin_mcp.admin_schemas.ldap_sources import validate_payload as validate_ldap_source_payload
from zammad_admin_mcp.admin_schemas.postmaster_filters import validate_payload as validate_postmaster_filter_payload
from zammad_admin_mcp.admin_schemas.public_links import validate_payload as validate_public_link_payload
from zammad_admin_mcp.admin_schemas.product_logo import validate_payload as validate_product_logo_payload
from zammad_admin_mcp.admin_schemas.packages import project_inventory as project_package_inventory
from zammad_admin_mcp.admin_schemas.packages import validate_install_payload as validate_package_install_payload
from zammad_admin_mcp.admin_schemas.ssl_certificates import project_certificate as project_ssl_certificate
from zammad_admin_mcp.admin_schemas.ssl_certificates import project_collection as project_ssl_certificate_collection
from zammad_admin_mcp.admin_schemas.ssl_certificates import validate_payload as validate_ssl_certificate_payload
from zammad_admin_mcp.admin_schemas.crypto_material import project_pgp_collection
from zammad_admin_mcp.admin_schemas.crypto_material import project_pgp_key
from zammad_admin_mcp.admin_schemas.crypto_material import project_smime_collection
from zammad_admin_mcp.admin_schemas.crypto_material import project_smime_certificate
from zammad_admin_mcp.admin_schemas.crypto_material import project_smime_private_key_collection
from zammad_admin_mcp.admin_schemas.crypto_material import validate_materialized_private_key
from zammad_admin_mcp.admin_schemas.crypto_material import validate_pgp_material
from zammad_admin_mcp.admin_schemas.crypto_material import validate_pgp_create
from zammad_admin_mcp.admin_schemas.crypto_material import validate_smime_certificate
from zammad_admin_mcp.admin_schemas.crypto_material import validate_smime_private_key
from zammad_admin_mcp.admin_schemas.system_report import project_summary as project_system_report_summary
from zammad_admin_mcp.admin_schemas.ai_admin import project_collection as project_ai_collection
from zammad_admin_mcp.admin_schemas.ai_admin import project_object as project_ai_object
from zammad_admin_mcp.admin_schemas.ai_admin import project_agent_snapshot
from zammad_admin_mcp.admin_schemas.ai_admin import project_agent_types
from zammad_admin_mcp.admin_schemas.ai_admin import validate_payload as validate_ai_payload
from zammad_admin_mcp.admin_schemas.sessions import project_sessions
from zammad_admin_mcp.admin_schemas.data_privacy import project_collection as project_data_privacy_tasks
from zammad_admin_mcp.admin_schemas.data_privacy import project_deletion_target
from zammad_admin_mcp.admin_schemas.data_privacy import project_selector as project_data_privacy_selector
from zammad_admin_mcp.admin_schemas.auth_settings import prepare_update as prepare_auth_setting_update
from zammad_admin_mcp.admin_schemas.auth_settings import project_setting as project_auth_setting
from zammad_admin_mcp.admin_schemas.auth_settings import supports as is_auth_credential_setting
from zammad_admin_mcp.admin_schemas.oauth_applications import project_application as project_oauth_application
from zammad_admin_mcp.admin_schemas.oauth_applications import project_collection as project_oauth_applications
from zammad_admin_mcp.admin_schemas.oauth_applications import validate_payload as validate_oauth_application_payload
from zammad_admin_mcp.admin_schemas.time_accounting import project_report as project_time_accounting_report
from zammad_admin_mcp.admin_schemas.time_accounting import project_types as project_time_accounting_types
from zammad_admin_mcp.admin_schemas.time_accounting import validate_report_request as validate_time_accounting_report_request
from zammad_admin_mcp.admin_schemas.time_accounting import validate_type_payload as validate_time_accounting_type_payload
from zammad_admin_mcp.admin_schemas.reports import project_config as project_report_config
from zammad_admin_mcp.admin_schemas.reports import project_aggregates as project_report_aggregates
from zammad_admin_mcp.admin_schemas.reports import validate_request as validate_report_request
from zammad_admin_mcp.admin_schemas.knowledge_base_assets import project_inventory as project_knowledge_base_inventory
from zammad_admin_mcp.admin_schemas.knowledge_base_attachments import project_snapshot as project_knowledge_base_attachments_snapshot
from zammad_admin_mcp.admin_schemas.knowledge_base_attachments import validate_upload as validate_knowledge_base_attachment_upload
from zammad_admin_mcp.admin_schemas.knowledge_base_deletion import preview as preview_knowledge_base_deletion
from zammad_admin_mcp.admin_schemas.knowledge_base_deletion import project_snapshot as project_knowledge_base_deletion_snapshot
from zammad_admin_mcp.admin_schemas.knowledge_base_menu import preview_after as preview_knowledge_base_menu_after
from zammad_admin_mcp.admin_schemas.knowledge_base_menu import project_snapshot as project_knowledge_base_menu_snapshot
from zammad_admin_mcp.admin_schemas.knowledge_base_menu import validate_update as validate_knowledge_base_menu_update
from zammad_admin_mcp.admin_schemas.knowledge_base_ordering import preview_after as preview_knowledge_base_order_after
from zammad_admin_mcp.admin_schemas.knowledge_base_ordering import project_siblings as project_knowledge_base_siblings
from zammad_admin_mcp.admin_schemas.knowledge_base_ordering import validate_order as validate_knowledge_base_order
from zammad_admin_mcp.admin_schemas.knowledge_base_publication import current_state as knowledge_base_publication_state
from zammad_admin_mcp.admin_schemas.knowledge_base_publication import project_answer_snapshot as project_knowledge_base_publication_snapshot
from zammad_admin_mcp.admin_schemas.knowledge_base_publication import validate_schedule_updates as validate_knowledge_base_schedule_updates
from zammad_admin_mcp.admin_schemas.knowledge_base_publication import validate_transition as validate_knowledge_base_publication_transition
from zammad_admin_mcp.admin_schemas.knowledge_base_creation import create_payload as knowledge_base_create_payload
from zammad_admin_mcp.admin_schemas.knowledge_base_translations import preview_after as preview_knowledge_base_translation_after
from zammad_admin_mcp.admin_schemas.knowledge_base_translations import project_snapshot as project_knowledge_base_translation_snapshot
from zammad_admin_mcp.admin_schemas.knowledge_base_translations import validate_update as validate_knowledge_base_translation_update
from zammad_admin_mcp.admin_schemas.knowledge_base_server_snippets import project as project_knowledge_base_server_snippets
from zammad_admin_mcp.admin_schemas.http_logs import project_collection as project_http_logs
from zammad_admin_mcp.admin_schemas.audit_logs import project_collection as project_audit_logs
from zammad_admin_mcp.admin_schemas.audit_logs import project_item as project_audit_log
from zammad_admin_mcp.admin_schemas.user_imports import equivalent_results as equivalent_user_import_results
from zammad_admin_mcp.admin_schemas.user_imports import project_result as project_user_import_result
from zammad_admin_mcp.admin_schemas.user_imports import project_result as project_organization_import_result
from zammad_admin_mcp.admin_schemas.user_imports import validate_csv_input as validate_user_import_input
from zammad_admin_mcp.admin_schemas.user_history import project_history as project_user_history
from zammad_admin_mcp.admin_schemas.user_history import project_history as project_organization_history

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

@dataclass(frozen=True)
class Resource:
    path: str
    operations: frozenset[str] = frozenset({"create", "update", "delete"})
    risk: str = "Configuration change; inspect the preview before approval."
    high_impact: bool = False
    item: bool = True


_RESOURCES: dict[str, Resource] = {
    "groups": Resource("/groups", risk="Changes ticket routing and group access.", high_impact=True),
    "roles": Resource("/roles", operations=frozenset({"create", "update"}), risk="Changes user permissions and may remove administrative access.", high_impact=True),
    "calendars": Resource("/calendars", risk="Changes working hours used by SLAs.", high_impact=True),
    "slas": Resource("/slas", risk="Changes ticket escalation and response targets.", high_impact=True),
    "triggers": Resource("/triggers", risk="May send email or invoke webhooks for future ticket events.", high_impact=True),
    "ticket_states": Resource("/ticket_states", risk="Changes the ticket state model.", high_impact=True),
    "ticket_priorities": Resource("/ticket_priorities", risk="Changes the ticket priority model.", high_impact=True),
    "macros": Resource("/macros"),
    "overviews": Resource("/overviews"),
    "templates": Resource("/templates"),
    "text_modules": Resource("/text_modules"),
    "core_workflows": Resource("/core_workflows", risk="Changes fields and values presented in ticket forms.", high_impact=True),
    "signatures": Resource("/signatures", risk="Changes message signatures available to agents."),
    "sms_channels": Resource(
        "/channels_sms", operations=frozenset({"create", "update", "delete", "enable", "disable", "test"}),
        risk="Configures SMS delivery or inbound handling; test sends a real SMS and may incur provider charges.", high_impact=True,
    ),
    "telegram_channels": Resource(
        "/channels_telegram", operations=frozenset({"create", "update", "delete", "enable", "disable"}), item=False,
        risk="Creates or changes a Telegram bot integration and can set a webhook with Telegram.", high_impact=True,
    ),
    "whatsapp_channels": Resource(
        "/channels/admin/whatsapp", operations=frozenset({"create", "update", "delete", "enable", "disable", "preload"}), item=False,
        risk="Changes a WhatsApp Business integration or calls Meta to verify/preload phone numbers.", high_impact=True,
    ),
    "facebook_channels": Resource(
        "/channels_facebook", operations=frozenset({"update", "delete", "enable", "disable"}),
        risk="Changes or removes an existing Facebook page integration.",
        high_impact=True, item=False,
    ),
    "google_channels": Resource(
        "/channels_google", operations=frozenset({"delete", "enable", "disable", "reassign", "configure", "probe", "rollback_migration"}),
        risk="Probes read the mailbox and refresh OAuth access; configuration resets status and clears logs, archive settings affect later imports, and deletion also removes the associated email address.",
        high_impact=True, item=False,
    ),
    "microsoft365_channels": Resource(
        "/channels_microsoft365", operations=frozenset({"delete", "enable", "disable", "reassign", "configure", "probe", "rollback_migration"}),
        risk="Probes read the mailbox and refresh OAuth access; configuration resets status and clears logs, archive settings affect later imports, and deletion also removes the associated email address.",
        high_impact=True, item=False,
    ),
    "microsoft_graph_channels": Resource(
        "/channels/admin/microsoft_graph", operations=frozenset({"delete", "enable", "disable", "reassign", "configure", "probe"}),
        risk="Probes read the mailbox and refresh OAuth access; configuration resets status and clears logs, and archive settings affect later imports.",
        high_impact=True, item=False,
    ),
    "report_profiles": Resource("/report_profiles"),
    "webhooks": Resource("/webhooks", risk="May call an external system when referenced by a trigger.", high_impact=True),
    "email_addresses": Resource("/email_addresses", risk="Deleting an address can clear group sender settings.", high_impact=True),
    "checklist_templates": Resource("/checklist_templates", risk="Changes reusable checklists available to agents.", high_impact=True),
    "audit_logs": Resource(
        "/audit_logs", operations=frozenset(),
        risk="Read-only security history on Zammad versions that expose the API; sensitive setting values and secret-like fields are redacted.",
    ),
    "tag_list": Resource("/tag_list", risk="Renaming or deleting a tag changes how ticket data is categorized.", high_impact=True),
    "organizations": Resource("/organizations", risk="Changes or permanently deletes organization and user associations.", high_impact=True),
    "users": Resource("/users", operations=frozenset({"create", "update", "delete", "unlock"}), risk="Changes user identity, roles, and access; unlocking permits a locked account to authenticate again.", high_impact=True),
    "object_manager_attributes": Resource("/object_manager_attributes", operations=frozenset({"create", "update", "delete", "discard_changes"}), risk="Attribute changes are queued until migration. Discarding removes queued additions and clears pending changes; executing removal migrations permanently deletes their values.", high_impact=True),
    "user_access_tokens": Resource(
        "/user_access_token",
        operations=frozenset({"create", "delete"}),
        risk="Creates a one-time API secret or revokes a token; either action can lock out integrations.",
        high_impact=True,
    ),
    "email_channels": Resource(
        "/channels_email",
        operations=frozenset({"enable", "disable", "delete", "reassign"}),
        risk="Changes or stops an inbound mailbox; email polling and ticket creation may be affected.",
        high_impact=True,
        item=False,
    ),
    "settings": Resource("/settings", operations=frozenset({"update", "reset"}), risk="May change authentication, integrations, security, or service behavior.", high_impact=True),
    "product_logo": Resource("/settings", operations=frozenset({"update"}), risk="Replaces the product logo displayed in Zammad, including its sign-in page.", high_impact=True),
    "jobs": Resource("/jobs", risk="Scheduled jobs can change tickets, users, or organizations when they run.", high_impact=True),
    "public_links": Resource("/public_links", risk="Changes public login, signup, or password-reset links; inspect destination and screen before approval.", high_impact=True),
    "postmaster_filters": Resource("/postmaster_filters", risk="Changes inbound email processing, ticket routing, and actions.", high_impact=True),
    "ldap_sources": Resource("/ldap_sources", risk="LDAP settings affect authentication and user synchronization; bind passwords are set only from process environment references.", high_impact=True),
    "chats": Resource("/chats", risk="Chat configuration changes availability; deletion also removes chat sessions.", high_impact=True),
    "external_credentials": Resource(
        "/external_credentials", operations=frozenset({"create", "update", "delete", "verify"}),
        risk="Replaces connected provider settings or secrets and may affect external integrations; verification may contact the provider.",
        high_impact=True,
    ),
    "translations": Resource(
        "/translations/customized", operations=frozenset({"upsert", "reset", "delete"}),
        risk="Changes translated text displayed throughout Zammad for a locale.", high_impact=True, item=False,
    ),
    "ssl_certificates": Resource(
        "/ssl_certificates", operations=frozenset({"create", "delete"}),
        risk="Changes certificates trusted by Zammad integrations; removing a certificate can break TLS connections.", high_impact=True, item=False,
    ),
    "monitoring": Resource(
        "/monitoring/health_check", operations=frozenset({"rotate_token", "restart_failed_jobs"}),
        risk="Rotates the external monitoring credential or reactivates failed scheduler jobs.", high_impact=True, item=False,
    ),
    "packages": Resource(
        "/packages", operations=frozenset({"install", "uninstall"}),
        risk="Package installation writes executable application files; removal reverses package migrations and removes files.", high_impact=True, item=False,
    ),
    "system_report": Resource(
        "/system_report", operations=frozenset(),
        risk="Returns a redacted system summary; environment values, settings, hardware identifiers, paths, and activity timestamps are excluded.", item=False,
    ),
    "ai_agents": Resource(
        "/ai_agents", risk="AI agents can process ticket data and trigger automated ticket changes; provider calls can incur usage charges.", high_impact=True,
    ),
    "ai_agent_types": Resource(
        "/ai_agents/types", operations=frozenset(),
        risk="Returns available agent type schemas and their supported configuration fields.", item=False,
    ),
    "ai_text_tools": Resource(
        "/ai_text_tools", risk="Writing Assistant tools send selected article text and configured context to the AI provider; use can incur provider charges.", high_impact=True,
    ),
    "sessions": Resource(
        "/sessions", operations=frozenset({"delete"}),
        risk="Ends the selected user's active Zammad session and requires them to sign in again.", item=False, high_impact=True,
    ),
    "data_privacy_tasks": Resource(
        "/data_privacy_tasks", operations=frozenset(),
        risk="Returns sanitized metadata for asynchronous account or ticket deletion tasks.", item=False,
    ),
    "oauth_applications": Resource(
        "/applications", risk="Changes OAuth client registrations, redirect destinations, or client credentials.", high_impact=True,
    ),
    "time_accounting_types": Resource(
        "/time_accounting/types", operations=frozenset({"create", "update"}),
        risk="Changes the activity categories available for time accounting.", high_impact=True,
    ),
}

_SPECIAL_CHANNEL = "email_notification"
_SPECIAL_PATH = "/channels_email_notification"
_SPECIAL_READ_PATH = "/channels_email"
_MESSAGING_CHANNELS_RESOURCE = "messaging_channels"
_EMAIL_ACCOUNT_RESOURCE = "email_account"
_EMAIL_ACCOUNT_VERIFY_PATH = "/channels_email_verify"
_EXCHANGE_INTEGRATION_INDEX_PATH = "/integration/exchange/index"
_EXCHANGE_AUTODISCOVER_PATH = "/integration/exchange/autodiscover"
_EXCHANGE_FOLDERS_PATH = "/integration/exchange/folders"
_EXCHANGE_MAPPING_PATH = "/integration/exchange/mapping"
_EXCHANGE_IMPORT_DRY_RUN_PATH = "/integration/exchange/job_try"
_EXCHANGE_IMPORT_START_PATH = "/integration/exchange/job_start"
_EMAIL_CHANNEL_ENABLE_PATH = "/channels_email_enable"
_EMAIL_CHANNEL_DISABLE_PATH = "/channels_email_disable"
_EMAIL_CHANNEL_GROUP_PATH = "/channels_email_group"
_HTTP_LOG_FACILITY_PATHS = {
    "AI::Provider": "/http_logs/AI::Provider",
    "check_mk": "/http_logs/check_mk",
    "clearbit": "/http_logs/clearbit",
    "cti": "/http_logs/cti",
    "EWS": "/http_logs/EWS",
    "GitHub": "/http_logs/GitHub",
    "GitLab": "/http_logs/GitLab",
    "idoit": "/http_logs/idoit",
    "ldap": "/http_logs/ldap",
    "MicrosoftGraph": "/http_logs/MicrosoftGraph",
    "PGP": "/http_logs/PGP",
    "placetel": "/http_logs/placetel",
    "S/MIME": "/http_logs/S/MIME",
    "SAML": "/http_logs/SAML",
    "sipagte.io": "/http_logs/sipagte.io",
    "sipgate.io": "/http_logs/sipgate.io",
    "webhook": "/http_logs/webhook",
    "WhatsApp::Business": "/http_logs/WhatsApp::Business",
}
_MESSAGE_CHANNEL_RESOURCES = {"sms_channels", "telegram_channels", "whatsapp_channels"}
_PLAN_TTL_SECONDS = 300
_MAX_PLANS = 100
_MAX_KNOWLEDGE_BASE_ATTACHMENT_UPLOAD_PLANS = 5
_PLANS: dict[str, dict[str, Any]] = {}
_PLAN_LOCK = asyncio.Lock()
_CRYPTO_SNAPSHOT_KEY = secrets.token_bytes(32)
_WRITE_LOCK = asyncio.Lock()
_PLAN_CLEANER: asyncio.Task[None] | None = None

mcp = FastMCP("zammad-admin")


def _validate_id(object_id: int | None) -> int:
    if isinstance(object_id, bool) or not isinstance(object_id, int) or object_id <= 0:
        raise ValueError("object_id must be a positive integer")
    return object_id


def _json(value: Any) -> str:
    return json.dumps(_scrub(value), ensure_ascii=False, indent=2, sort_keys=True)


def _project_admin_settings(value: Any) -> Any:
    if isinstance(value, list):
        return [
            project_auth_setting(item) if isinstance(item, Mapping) and is_auth_credential_setting(item.get("name"))
            else project_exchange_configuration(item) if isinstance(item, Mapping) and item.get("name") == "exchange_config"
            else _project_settings(item)
            for item in value
        ]
    if isinstance(value, Mapping) and is_auth_credential_setting(value.get("name")):
        return project_auth_setting(value)
    if isinstance(value, Mapping) and value.get("name") == "exchange_config":
        return project_exchange_configuration(value)
    return _project_settings(value)


def _validate_sso_trusted_ip_ranges(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if len(value) > 4096:
        raise ValueError("auth_sso_trusted_ips cannot exceed 4096 characters")
    if not value.strip():
        return []
    entries = [item.strip() for item in value.split(",")]
    if any(not item for item in entries):
        raise ValueError("auth_sso_trusted_ips must contain comma-separated IP addresses or CIDR ranges")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in entries:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError("auth_sso_trusted_ips contains an invalid IP address or CIDR range") from exc
    return networks


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _crypto_digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(_CRYPTO_SNAPSHOT_KEY, raw.encode("utf-8"), hashlib.sha256).hexdigest()


async def _crypto_material_snapshot(resource: str, object_id: int | None = None) -> Any:
    if resource == "pgp_keys":
        if object_id is None:
            return await _get("/integration/pgp/key")
        return await _get(f"/integration/pgp/key/{_validate_id(object_id)}")
    if resource in {"smime_certificates", "smime_private_keys"}:
        certificates = await _get("/integration/smime/certificate")
        if not isinstance(certificates, list):
            raise RuntimeError("Zammad did not return S/MIME certificate inventory")
        if object_id is None:
            return certificates
        matches = [item for item in certificates if isinstance(item, Mapping) and item.get("id") == object_id]
        if len(matches) != 1:
            raise ValueError("object_id must identify exactly one existing S/MIME certificate")
        return matches[0]
    raise ValueError("Unsupported cryptographic material resource")


def _proxy_test_fingerprint(data: Mapping[str, Any]) -> str:
    return _digest({
        "proxy": data.get("proxy"),
        "username_configured": "proxy_username" in data,
        "password_configured": "proxy_password" in data,
        "bypass_list_configured": bool(data.get("proxy_no")),
    })


def _snapshot_fingerprint(resource: str, value: Any) -> str:
    if resource == "user_access_tokens" and isinstance(value, Mapping):
        permissions = value.get("permissions", [])
        tokens = value.get("tokens", [])
        stable = {
            "permissions": sorted(
                (item.get("name"), item.get("active"))
                for item in permissions if isinstance(item, Mapping) and isinstance(item.get("name"), str)
            ),
            "token_ids": sorted(item.get("id") for item in tokens if isinstance(item, Mapping)),
        }
        return _digest(stable)
    return _digest(value)


def _validate_channel_payload(resource: str, operation: str, data: Any) -> None:
    def text(value: Any, field: str, *, secret: bool = False) -> None:
        if isinstance(value, Mapping) and set(value) == {"$secret_env"} and secret:
            return
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")

    def keys(payload: Any, allowed: set[str], required: set[str], label: str) -> Mapping[str, Any]:
        if not isinstance(payload, Mapping) or set(payload) - allowed or not required.issubset(payload):
            raise ValueError(f"{label} accepts only {', '.join(sorted(allowed))}; required: {', '.join(sorted(required))}")
        return payload

    if operation in {"enable", "disable", "delete"}:
        if data not in (None, {}):
            raise ValueError(f"{operation} does not accept data")
        return

    if operation == "test" and resource == "sms_channels":
        payload = keys(data, {"options", "recipient", "message"}, {"options", "recipient", "message"}, "SMS test")
        options = keys(payload["options"], {"adapter", "token", "sender", "account_id", "gateway"}, {"adapter"}, "SMS test options")
        adapter = options["adapter"]
        fields = {
            "sms/message_bird": {"adapter", "token", "sender"},
            "sms/twilio": {"adapter", "account_id", "token", "sender"},
            "sms/massenversand": {"adapter", "gateway", "token", "sender"},
        }
        if adapter not in fields or set(options) - fields[adapter]:
            raise ValueError("Unsupported SMS adapter or option fields")
        if adapter == "sms/massenversand":
            raise ValueError("The Massenversand test endpoint can expose its token in provider errors; test it through Zammad's UI")
        for key in set(options) - {"adapter"}:
            text(options[key], f"options.{key}", secret=key == "token")
        text(payload["recipient"], "recipient")
        text(payload["message"], "message")
        return

    if operation == "preload" and resource == "whatsapp_channels":
        payload = keys(data, {"channel_id", "business_id", "access_token"}, set(), "WhatsApp preload")
        if "channel_id" in payload:
            _validate_id(payload["channel_id"])
            if set(payload) != {"channel_id"}:
                raise ValueError("For an existing WhatsApp channel, preload accepts only channel_id")
        elif set(payload) != {"business_id", "access_token"}:
            raise ValueError("WhatsApp preload requires channel_id or business_id and access_token")
        if "business_id" in payload:
            text(payload["business_id"], "business_id")
            text(payload["access_token"], "access_token", secret=True)
        return

    if resource == "sms_channels":
        payload = keys(data, {"area", "options", "group_id"}, {"area", "options"}, "SMS channel")
        if payload["area"] not in {"Sms::Account", "Sms::Notification"}:
            raise ValueError("SMS area must be Sms::Account or Sms::Notification")
        if payload["area"] == "Sms::Account":
            if "group_id" not in payload:
                raise ValueError("SMS account channels require group_id")
            _validate_id(payload["group_id"])
        elif "group_id" in payload:
            raise ValueError("SMS notification channels do not accept group_id")
        options = keys(payload["options"], {"adapter", "token", "sender", "account_id", "gateway"}, {"adapter"}, "SMS options")
        fields = {
            "sms/message_bird": {"adapter", "token", "sender"},
            "sms/twilio": {"adapter", "account_id", "token", "sender"},
            "sms/massenversand": {"adapter", "gateway", "token", "sender"},
        }
        adapter = options["adapter"]
        if adapter not in fields or set(options) - fields[adapter]:
            raise ValueError("Unsupported SMS adapter or option fields")
        if adapter == "sms/massenversand" and payload["area"] != "Sms::Notification":
            raise ValueError("Massenversand is supported only for notification channels")
        for key in set(options) - {"adapter"}:
            text(options[key], f"options.{key}", secret=key == "token")
        if adapter == "sms/massenversand":
            gateway = urlsplit(options["gateway"])
            try:
                address = ipaddress.ip_address(gateway.hostname or "")
            except ValueError:
                address = None
            if (
                gateway.scheme != "https" or not gateway.hostname or gateway.username or gateway.password
                or gateway.query or gateway.fragment or address is not None
                or gateway.hostname.lower() == "localhost" or "." not in gateway.hostname
            ):
                raise ValueError("Massenversand gateway must be an HTTPS hostname URL without credentials, query, or fragment")
        return

    if resource == "telegram_channels":
        payload = keys(data, {"api_token", "group_id", "welcome", "goodbye"}, {"api_token", "group_id"}, "Telegram channel")
        text(payload["api_token"], "api_token", secret=True)
        _validate_id(payload["group_id"])
        for key in {"welcome", "goodbye"} & set(payload):
            if not isinstance(payload[key], str):
                raise ValueError(f"{key} must be a string")
        return

    if resource == "whatsapp_channels":
        allowed = {"business_id", "access_token", "app_secret", "phone_number_id", "group_id", "welcome", "reminder_active", "reminder_message"}
        required = {"business_id", "phone_number_id", "group_id"}
        if operation != "update":
            required.update({"access_token", "app_secret"})
        payload = keys(data, allowed, required, "WhatsApp channel")
        for key in {"business_id", "phone_number_id"}:
            text(payload[key], key)
        for key in {"access_token", "app_secret"} & set(payload):
            text(payload[key], key, secret=True)
        _validate_id(payload["group_id"])
        if "welcome" in payload and not isinstance(payload["welcome"], str):
            raise ValueError("welcome must be a string")
        if "reminder_active" in payload and not isinstance(payload["reminder_active"], bool):
            raise ValueError("reminder_active must be a boolean")
        if "reminder_message" in payload and not isinstance(payload["reminder_message"], str):
            raise ValueError("reminder_message must be a string")


def _resource(resource: str) -> Resource:
    try:
        return _RESOURCES[resource]
    except KeyError as exc:
        raise ValueError("Unsupported Zammad admin resource") from exc


async def _request(
    method: str,
    path: str,
    payload: Any = None,
    params: dict[str, Any] | None = None,
    files: dict[str, tuple[str, bytes, str]] | None = None,
    accept_package_redirect: bool = False,
) -> Any:
    allowed = {
        "/version", _SPECIAL_READ_PATH, _SPECIAL_PATH, _EMAIL_ACCOUNT_VERIFY_PATH,
        _EXCHANGE_INTEGRATION_INDEX_PATH, _EXCHANGE_AUTODISCOVER_PATH,
        _EXCHANGE_FOLDERS_PATH, _EXCHANGE_MAPPING_PATH,
        _EXCHANGE_IMPORT_DRY_RUN_PATH,
        _EXCHANGE_IMPORT_START_PATH,
        _EMAIL_CHANNEL_ENABLE_PATH, _EMAIL_CHANNEL_DISABLE_PATH, "/roles?expand=true",
        "/channels_sms_enable", "/channels_sms_disable", "/channels_sms/test",
        "/channels_telegram_enable", "/channels_telegram_disable",
        "/channels_facebook_enable", "/channels_facebook_disable",
        "/channels_microsoft365_enable", "/channels_microsoft365_disable",
        "/channels_google_rollback_migration", "/channels_microsoft365_rollback_migration",
        "/channels/admin/whatsapp/preload",
        "/integration/ldap/discover", "/integration/ldap/bind",
        "/integration/ldap/job_try", "/integration/ldap/job_start",
        "/monitoring/health_check", "/monitoring/token", "/monitoring/restart_failed_jobs",
        "/system_report",
        "/object_manager_attributes_execute_migrations",
        "/tickets/selector",
        "/applications/token",
        "/settings/ticket_agent_default_notifications/apply_to_all",
        "/object_manager_attributes_discard_changes",
        "/users/import",
        "/organizations/import",
        "/calendars/timezones",
        "/audit_logs/search",
        "/knowledge_bases/init",
        "/knowledge_bases/manage/init",
        "/http_logs",
        "/proxy",
        "/reports/config",
        "/reports/generate",
    }
    external_credential_verify_path = bool(re.fullmatch(
        r"/external_credentials/(?:google|microsoft365|microsoft_graph|exchange)/app_verify", path,
    ))
    email_group_path = bool(re.fullmatch(r"/channels_email_group/\d+", path))
    whatsapp_action_path = bool(re.fullmatch(r"/channels/admin/whatsapp/\d+/(?:enable|disable)", path))
    microsoft365_group_path = bool(re.fullmatch(r"/channels_microsoft365_group/\d+", path))
    microsoft_graph_action_path = bool(re.fullmatch(r"/channels/admin/microsoft_graph/\d+/(?:enable|disable)", path))
    microsoft_graph_group_path = bool(re.fullmatch(r"/channels/admin/microsoft_graph/group/\d+", path))
    microsoft365_verify_path = bool(re.fullmatch(r"/channels_microsoft365_verify/\d+", path))
    microsoft_graph_verify_path = bool(re.fullmatch(r"/channels/admin/microsoft_graph/verify/\d+", path))
    microsoft365_inbound_path = bool(re.fullmatch(r"/channels_microsoft365_inbound/\d+", path))
    microsoft_graph_inbound_path = bool(re.fullmatch(r"/channels/admin/microsoft_graph/inbound/\d+", path))
    google_action_path = path in {"/channels_google_enable", "/channels_google_disable"}
    google_group_path = bool(re.fullmatch(r"/channels_google_group/\d+", path))
    google_verify_path = bool(re.fullmatch(r"/channels_google_verify/\d+", path))
    google_inbound_path = bool(re.fullmatch(r"/channels_google_inbound/\d+", path))
    for item in _RESOURCES.values():
        allowed.add(item.path)
    item_path = any(
        path.startswith(spec.path + "/")
        and path[len(spec.path) + 1 :].isdigit()
        and int(path[len(spec.path) + 1 :]) > 0
        for spec in _RESOURCES.values()
    )
    knowledge_base_path = bool(re.fullmatch(r"/knowledge_bases/\d+(?:/(?:answers|categories)(?:/\d+)?|/permissions|/categories/\d+/permissions)", path))
    knowledge_base_create_path = path == "/knowledge_bases/manage"
    knowledge_base_settings_path = bool(re.fullmatch(r"/knowledge_bases/manage/\d+", path))
    knowledge_base_server_snippets_path = bool(re.fullmatch(r"/knowledge_bases/manage/\d+/server_snippets", path))
    knowledge_base_feed_token_path = bool(re.fullmatch(r"/knowledge_bases/\d+/feed_tokens", path))
    knowledge_base_lifecycle_path = bool(re.fullmatch(r"/knowledge_bases/manage/\d+/(?:activate|deactivate)", path))
    knowledge_base_menu_path = bool(re.fullmatch(r"/knowledge_bases/manage/\d+/update_menu_items", path))
    knowledge_base_order_path = bool(re.fullmatch(
        r"/knowledge_bases/\d+/categories/(?:reorder_root_categories|\d+/(?:reorder_categories|reorder_answers))",
        path,
    ))
    knowledge_base_publication_path = bool(re.fullmatch(
        r"/knowledge_bases/\d+/answers/\d+/(?:internal|publish|archive|unarchive|has_publishing_update)",
        path,
    ))
    knowledge_base_attachment_path = bool(re.fullmatch(
        r"/knowledge_bases/\d+/answers/\d+/attachments(?:/\d+)?", path,
    ))
    translation_search_path = bool(re.fullmatch(r"/translations/search/[a-zA-Z0-9-]{2,35}", path))
    translation_item_path = bool(re.fullmatch(r"/translations/\d+", path))
    translation_reset_path = bool(re.fullmatch(r"/translations/reset/\d+", path))
    translation_upsert_path = path == "/translations/upsert"
    settings_image_path = bool(re.fullmatch(r"/settings/image/\d+", path))
    settings_reset_path = bool(re.fullmatch(r"/settings/reset/\d+", path))
    ticket_item_path = bool(re.fullmatch(r"/tickets/\d+", path))
    ticket_selector_path = path == "/tickets/selector"
    oauth_application_token_path = path == "/applications/token"
    time_accounting_report_path = bool(re.fullmatch(r"/time_accounting/log/(?:by_activity|by_ticket|by_customer|by_organization)/\d{4}/\d{1,2}", path))
    user_unlock_path = bool(re.fullmatch(r"/users/unlock/\d+", path))
    user_history_path = bool(re.fullmatch(r"/users/history/\d+", path))
    organization_history_path = bool(re.fullmatch(r"/organizations/history/\d+", path))
    audit_log_item_path = bool(re.fullmatch(r"/audit_logs/\d+", path))
    audit_log_search_path = path == "/audit_logs/search"
    user_two_factor_path = bool(re.fullmatch(r"/users/\d+/admin_two_factor/(?:enabled_authentication_methods|remove_authentication_method|remove_all_authentication_methods)", path))
    http_log_facility_path = path in _HTTP_LOG_FACILITY_PATHS.values()
    fixed_special_paths = (
        external_credential_verify_path,
        email_group_path, whatsapp_action_path, microsoft365_group_path,
        microsoft_graph_action_path, microsoft_graph_group_path, microsoft365_verify_path,
        microsoft_graph_verify_path, microsoft365_inbound_path, microsoft_graph_inbound_path,
        google_action_path, google_group_path, google_verify_path, google_inbound_path,
        settings_image_path, settings_reset_path, item_path, knowledge_base_path, knowledge_base_create_path,
        knowledge_base_settings_path, knowledge_base_lifecycle_path, knowledge_base_menu_path,
        knowledge_base_server_snippets_path, knowledge_base_feed_token_path,
        knowledge_base_order_path,
        knowledge_base_publication_path,
        knowledge_base_attachment_path,
        translation_search_path, translation_item_path,
        translation_reset_path, translation_upsert_path,
        ticket_item_path, ticket_selector_path, oauth_application_token_path,
        time_accounting_report_path,
        user_unlock_path, user_two_factor_path, user_history_path, organization_history_path,
        http_log_facility_path,
        audit_log_item_path,
        bool(re.fullmatch(r"/integration/pgp/key/\d+", path)),
    )
    crypto_routes = {
        ("GET", "/integration/pgp/status"), ("GET", "/integration/pgp/key"),
        ("POST", "/integration/pgp/key"), ("GET", "/integration/smime/certificate"),
        ("POST", "/integration/smime/certificate"), ("DELETE", "/integration/smime/certificate"),
        ("POST", "/integration/smime/private_key"), ("DELETE", "/integration/smime/private_key"),
    }
    pgp_item_route = bool(re.fullmatch(r"/integration/pgp/key/\d+", path))
    if path not in allowed and not any(fixed_special_paths) and (method, path) not in crypto_routes:
        raise ValueError("Unsupported Zammad API resource")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Unsupported Zammad API method")
    if path == "/reports/config" and method != "GET":
        raise ValueError("Report configuration is available through GET only")
    if path == "/reports/generate" and method != "POST":
        raise ValueError("Report generation is available through POST only")
    if external_credential_verify_path and method != "POST":
        raise ValueError("External credential app verification supports POST only")
    if ticket_item_path and method != "GET":
        raise ValueError("Ticket deletion previews support GET only")
    if ticket_selector_path and method != "POST":
        raise ValueError("Ticket selector previews support POST only")
    if oauth_application_token_path and method != "POST":
        raise ValueError("OAuth application token issuance supports POST only")
    if time_accounting_report_path and method != "GET":
        raise ValueError("Time accounting reports support GET only")
    if path == "/audit_logs" and method != "GET":
        raise ValueError("Audit logs are available as read-only records")
    if audit_log_item_path and method != "GET":
        raise ValueError("Audit log entries are available as read-only records")
    if audit_log_search_path and method not in {"GET", "POST"}:
        raise ValueError("Audit log search supports GET or POST only")
    if audit_log_search_path and method == "POST" and (
        not isinstance(payload, Mapping)
        or set(payload) - {"query", "with_total_count"}
        or not isinstance(payload.get("query"), str)
        or ("with_total_count" in payload and not isinstance(payload["with_total_count"], bool))
    ):
        raise ValueError("Audit log search accepts only a query and optional total-count flag")
    if path == "/settings/ticket_agent_default_notifications/apply_to_all" and method != "POST":
        raise ValueError("Applying ticket agent notification defaults supports POST only")
    if path == "/object_manager_attributes_discard_changes" and method != "POST":
        raise ValueError("Discarding queued object manager changes supports POST only")
    if path == "/users/import" and method != "POST":
        raise ValueError("User CSV imports support POST only")
    if path == "/organizations/import" and method != "POST":
        raise ValueError("Organization CSV imports support POST only")
    if path == "/calendars/timezones" and method != "GET":
        raise ValueError("Calendar timezone lookup supports GET only")
    if knowledge_base_create_path and method != "POST":
        raise ValueError("Knowledge Base creation supports POST only")
    if knowledge_base_server_snippets_path and method != "GET":
        raise ValueError("Knowledge Base server snippets support GET only")
    if knowledge_base_feed_token_path and method not in {"GET", "PATCH"}:
        raise ValueError("Knowledge Base feed tokens support only token retrieval or rotation")
    if path == _EXCHANGE_INTEGRATION_INDEX_PATH and method != "GET":
        raise ValueError("Exchange integration status supports GET only")
    if path in {_EXCHANGE_AUTODISCOVER_PATH, _EXCHANGE_FOLDERS_PATH, _EXCHANGE_MAPPING_PATH} and method != "POST":
        raise ValueError("Exchange connection checks support POST only")
    if path == _EXCHANGE_IMPORT_DRY_RUN_PATH and method not in {"GET", "POST"}:
        raise ValueError("Exchange dry-run jobs support GET status and POST submission only")
    if path == _EXCHANGE_IMPORT_START_PATH and method not in {"GET", "POST"}:
        raise ValueError("Exchange import jobs support GET status and POST submission only")
    if path == "/knowledge_bases/init" and method != "POST":
        raise ValueError("Knowledge Base inventory uses its read-only initialization route")
    if path == "/knowledge_bases/manage/init" and method != "GET":
        raise ValueError("Knowledge Base manager inventory supports GET only")
    if knowledge_base_lifecycle_path and method != "PATCH":
        raise ValueError("Knowledge Base lifecycle actions support PATCH only")
    if knowledge_base_menu_path and method != "PATCH":
        raise ValueError("Knowledge Base menu updates support PATCH only")
    if knowledge_base_order_path and method != "PATCH":
        raise ValueError("Knowledge Base ordering actions support PATCH only")
    if knowledge_base_publication_path and method != "POST":
        raise ValueError("Knowledge Base publication actions support POST only")
    if knowledge_base_attachment_path:
        attachment_item = re.fullmatch(r"/knowledge_bases/\d+/answers/\d+/attachments/\d+", path) is not None
        if (attachment_item and method != "DELETE") or (not attachment_item and method != "POST"):
            raise ValueError("Knowledge Base attachments support only nested upload and deletion")
        if not attachment_item and (files is None or set(files) != {"file"}):
            raise ValueError("Knowledge Base attachment uploads require one file field")
        if attachment_item and files is not None:
            raise ValueError("Multipart data is supported only for Knowledge Base attachment uploads")
    if (path == "/http_logs" or http_log_facility_path) and method != "GET":
        raise ValueError("HTTP logs are available as read-only metadata")
    if path == "/proxy" and method != "POST":
        raise ValueError("Proxy connectivity checks support POST only")
    if user_unlock_path and method != "PUT":
        raise ValueError("User unlock supports PUT only")
    if user_history_path and method != "GET":
        raise ValueError("User history supports GET only")
    if organization_history_path and method != "GET":
        raise ValueError("Organization history supports GET only")
    if user_two_factor_path:
        expected_method = "GET" if path.endswith("/enabled_authentication_methods") else "DELETE"
        if method != expected_method:
            raise ValueError("Administrative two-factor methods support only their Zammad route method")
    if pgp_item_route and method not in {"GET", "DELETE"}:
        raise ValueError("PGP key item routes support only GET and DELETE")
    if path in {route for _, route in crypto_routes} and (method, path) not in crypto_routes:
        raise ValueError("Unsupported Zammad integration route method")
    return await _send_api_request(
        method, path, payload, params,
        files=files,
        accept_package_redirect=accept_package_redirect,
    )


async def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    return await _request("GET", path, params=params)


@mcp.tool()
async def zammad_server_version() -> str:
    """Read the version of the connected Zammad instance."""
    return _json(await _get("/version"))


@mcp.tool()
async def zammad_get_exchange_integration_status() -> str:
    """Show whether an Exchange OAuth record and an application registration are present."""
    result = await _get(_EXCHANGE_INTEGRATION_INDEX_PATH)
    return _json(project_exchange_integration_status(result))


@mcp.tool()
async def zammad_get_exchange_import_status(action: Literal["dry_run", "start"]) -> str:
    """Read Exchange import job status and aggregate counts without returning job payloads or contact data."""
    path = _EXCHANGE_IMPORT_DRY_RUN_PATH if action == "dry_run" else _EXCHANGE_IMPORT_START_PATH
    params = {"finished": "true"} if action == "dry_run" else None
    job = await _get(path, params)
    return _json(project_exchange_import_status(job, action))


@mcp.tool()
async def zammad_prepare_exchange_connection_action(
    action: Literal["autodiscover", "folders", "mapping"],
    data: dict[str, Any],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a bounded Exchange connection check without contacting Exchange."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Exchange connection checks require acknowledge_high_impact=true")
    if action not in {"autodiscover", "folders", "mapping"}:
        raise ValueError("Unsupported Exchange connection action")
    materialized, safe_input = _materialize_secret_values(data)
    payload = validate_exchange_connection_action(action, materialized)
    preview = validate_exchange_connection_action(action, safe_input)

    oauth_snapshot: dict[str, Any] = {}
    auth_type = payload.get("auth_type")
    if auth_type == "oauth":
        oauth_snapshot = await _exchange_oauth_snapshot()
        access_token = oauth_snapshot.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ValueError("The Exchange OAuth connection does not have an access token")

    if action == "autodiscover":
        domain = payload["user"].rsplit("@", 1)[1].lower()
        preview_after = {
            "action": action,
            "mail_domain": domain,
            "credentials_configured": bool(preview.get("password")),
            "credentials_returned": False,
        }
        effects = ["Connect from Zammad to the Exchange Autodiscover service for the email domain"]
    else:
        preview_after = {
            "action": action,
            "endpoint_host": exchange_endpoint_host(payload["endpoint"]),
            "auth_type": auth_type,
            "credentials_configured": bool(preview.get("password")) or auth_type == "oauth",
            "credentials_returned": False,
            "tls_certificate_verification": "disabled" if payload["disable_ssl_verify"] else "enabled",
        }
        if action == "mapping":
            preview_after["selected_folder_count"] = len(payload["folders"])
            preview_after["contact_values_returned"] = False
        effects = ["Connect from Zammad to the configured Exchange endpoint"]
    if payload.get("disable_ssl_verify") is True:
        effects.append("The request will disable TLS certificate verification")
    if any(isinstance(value, str) and value == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]" for value in safe_input.values()):
        effects.append("Use credentials from the MCP process environment without returning them")

    fingerprint = _crypto_digest(oauth_snapshot) if oauth_snapshot else None
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__exchange_connection_action__",
        "operation": action,
        "data": payload,
        "fingerprint": fingerprint,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    return _json({
        "plan_id": plan_id,
        "resource": "exchange_connection_tests",
        "operation": action,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": fingerprint,
        "after": preview_after,
        "risk": "Applying this plan sends an outbound Exchange connection request; returned data is limited to configuration metadata.",
        "write_effects": effects,
        "approval_required": True,
        "note": "No Exchange connection request was sent. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_exchange_import_action(
    action: Literal["dry_run", "start"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an Exchange dry run or import job; neither starts until the plan is applied."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if action not in {"dry_run", "start"}:
        raise ValueError("Unsupported Exchange import action")
    if not acknowledge_high_impact:
        raise ValueError("Exchange import actions require acknowledge_high_impact=true")

    snapshot = await _exchange_import_snapshot()
    if action == "start" and snapshot["enabled"] is not True:
        raise ValueError("The Exchange integration must be enabled before starting an import")
    if await _exchange_import_pending("dry_run") or await _exchange_import_pending("start"):
        raise ValueError("An Exchange job is already queued or running")

    validated_payload = prepare_exchange_dry_run_payload(snapshot["config"])
    oauth_access_token = snapshot["oauth"].get("access_token")
    if validated_payload["auth_type"] == "oauth" and (not isinstance(oauth_access_token, str) or not oauth_access_token):
        raise ValueError("The Exchange OAuth connection does not have an access token")
    payload = validated_payload if action == "dry_run" else {}
    config_summary = {
        "endpoint_host": exchange_endpoint_host(validated_payload["endpoint"]),
        "selected_folder_count": len(validated_payload["folders"]),
        "mapped_attribute_count": len(validated_payload["attributes"]),
        "tls_certificate_verification": "disabled" if validated_payload["disable_ssl_verify"] else "enabled",
    }
    fingerprint = _crypto_digest(snapshot)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__exchange_import_action__",
        "operation": action,
        "data": payload,
        "fingerprint": fingerprint,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    if action == "dry_run":
        side_effects = [
            "Connect to the configured Exchange service and read selected mailbox folders",
            "Create a persistent Zammad dry-run ImportJob",
            "Do not apply the imported user changes",
        ]
        risk = "The dry run reads real mailbox contact data and stores an asynchronous ImportJob in Zammad."
        after = {
            "action": action,
            **config_summary,
            "credentials_returned": False,
        }
    else:
        side_effects = [
            "Queue an Exchange import job",
            "The importer may create or update Zammad user records using Exchange mailbox data",
        ]
        risk = "The background import may create or update Zammad users from Exchange mailbox data."
        after = {"action": action, **config_summary, "credentials_returned": False}
    if validated_payload["disable_ssl_verify"]:
        side_effects.append("The saved Exchange configuration disables TLS certificate verification")

    return _json({
        "plan_id": plan_id,
        "resource": "exchange_import_actions",
        "operation": action,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": fingerprint,
        "before": {
            "integration_enabled": snapshot["enabled"],
            "job_pending": False,
        },
        "after": after,
        "risk": risk,
        "write_effects": side_effects,
        "approval_required": True,
        "note": "No Exchange job was submitted. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_list_calendar_timezones() -> str:
    """List timezone choices used by Zammad calendar configuration."""
    result = await _get("/calendars/timezones")
    timezones = result.get("timezones") if isinstance(result, Mapping) else None
    if not isinstance(timezones, Mapping) or any(
        not isinstance(name, str) or isinstance(offset, bool) or not isinstance(offset, int)
        for name, offset in timezones.items()
    ):
        raise RuntimeError("Zammad did not return calendar timezones")
    return _json({"timezones": timezones})


@mcp.tool()
async def zammad_get_report_configuration() -> str:
    """Read report metrics, backends, and profiles available to the current Zammad user."""
    try:
        config = await _request("GET", "/reports/config")
    except Exception:
        raise RuntimeError("Zammad report configuration could not be read") from None
    return _json(project_report_config(config))


@mcp.tool()
async def zammad_generate_report_aggregates(
    profile_id: int,
    metric: str,
    backends: list[str],
    time_range: Literal["realtime", "day", "week", "month", "year"],
    year: int | None = None,
    month: int | None = None,
    day: int | None = None,
    week: int | None = None,
    timezone: str | None = None,
) -> str:
    """Read bounded report time-series aggregates without returning ticket records."""
    try:
        current = project_report_config(await _request("GET", "/reports/config"))
        payload, max_buckets, backend_labels = validate_report_request(
            current,
            profile_id=profile_id,
            metric=metric,
            backends=backends,
            time_range=time_range,
            year=year,
            month=month,
            day=day,
            week=week,
            timezone=timezone,
        )
    except ValueError:
        raise
    except Exception:
        raise RuntimeError("Zammad report configuration could not be validated") from None
    try:
        raw = await _request("POST", "/reports/generate", payload)
        series = project_report_aggregates(
            raw,
            selected_backends=backends,
            max_buckets=max_buckets,
            metric=metric,
        )
    except Exception:
        raise RuntimeError("Zammad report aggregates could not be generated; detailed diagnostics were withheld") from None
    selected_profile = next(item for item in current["profiles"] if item["id"] == profile_id)
    return _json({
        "profile": {"id": profile_id, "name": selected_profile["name"]},
        "metric": metric,
        "time_range": time_range,
        "timezone": timezone or "Zammad default",
        "series": [
            {"name": name, "display": backend_labels[name], "values": values}
            for name, values in series.items()
        ],
        "ticket_ids_returned": False,
        "ticket_assets_returned": False,
    })


@mcp.tool()
async def zammad_get_time_accounting_report(
    report: Literal["by_activity", "by_ticket", "by_customer", "by_organization"],
    year: int,
    month: int,
    limit: int = 21,
) -> str:
    """Read a bounded, privacy-projected Time Accounting Admin report for one month."""
    validate_time_accounting_report_request(report, year, month, limit)
    result = await _get(f"/time_accounting/log/{report}/{year}/{month}", {"limit": limit})
    return _json(project_time_accounting_report(report, result))


async def _ticket_agent_notification_setting_snapshot() -> Mapping[str, Any]:
    settings = await _get("/settings")
    if not isinstance(settings, list):
        raise RuntimeError("Zammad did not return its settings list")
    matches = [
        item for item in settings
        if isinstance(item, Mapping) and item.get("name") == "ticket_agent_default_notifications"
    ]
    if len(matches) != 1:
        raise RuntimeError("Zammad did not return exactly one ticket agent notification setting")
    return matches[0]


def _project_user_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in ("id", "firstname", "lastname", "login", "email")
        if key in value
    }


async def _user_unlock_snapshot(user_id: int) -> dict[str, Any]:
    user = await _get(f"/users/{user_id}")
    settings = await _get("/settings")
    if not isinstance(user, Mapping) or user.get("id") != user_id:
        raise RuntimeError("Zammad did not return the selected user")
    if not isinstance(settings, list):
        raise RuntimeError("Zammad did not return security settings")
    matches = [
        item for item in settings
        if isinstance(item, Mapping) and item.get("name") == "password_max_login_failed"
    ]
    current = matches[0].get("state_current") if len(matches) == 1 else None
    limit = current.get("value") if isinstance(current, Mapping) else None
    failed = user.get("login_failed")
    if isinstance(limit, bool) or not isinstance(limit, int) or isinstance(failed, bool) or not isinstance(failed, int):
        raise RuntimeError("Zammad did not return the account lockout state")
    if failed <= limit:
        raise ValueError("The selected user is not locked by the configured failed-login threshold")
    return {
        "user": {**_project_user_identity(user), "login_failed": failed},
        "password_max_login_failed": limit,
    }


async def _user_two_factor_snapshot(user_id: int) -> dict[str, Any]:
    user = await _get(f"/users/{user_id}")
    methods = await _get(f"/users/{user_id}/admin_two_factor/enabled_authentication_methods")
    if not isinstance(user, Mapping) or user.get("id") != user_id or not isinstance(methods, list):
        raise RuntimeError("Zammad did not return the selected user and two-factor methods")
    names = []
    for item in methods:
        if not isinstance(item, Mapping) or not isinstance(item.get("method"), str):
            raise RuntimeError("Zammad returned an invalid two-factor method")
        names.append(item["method"])
    if len(names) != len(set(names)):
        raise RuntimeError("Zammad returned duplicate two-factor methods")
    return {"user": _project_user_identity(user), "methods": names}


@mcp.tool()
async def zammad_get_user_two_factor_methods(user_id: int) -> str:
    """Read enabled two-factor method names for one user without credential details."""
    user_id = _validate_id(user_id)
    snapshot = await _user_two_factor_snapshot(user_id)
    return _json({"user": snapshot["user"], "enabled_methods": snapshot["methods"]})


@mcp.tool()
async def zammad_get_user_history(user_id: int, limit: int = 100) -> str:
    """Read recent account history with secret-like field values redacted and related assets omitted."""
    user_id = _validate_id(user_id)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be an integer between 1 and 500")
    history = await _get(f"/users/history/{user_id}")
    return _json({"user_id": user_id, **project_user_history(history, limit)})


@mcp.tool()
async def zammad_get_organization_history(organization_id: int, limit: int = 100) -> str:
    """Read recent organization history with secret-like field values redacted."""
    organization_id = _validate_id(organization_id)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be an integer between 1 and 500")
    history = await _get(f"/organizations/history/{organization_id}")
    return _json({"organization_id": organization_id, **project_organization_history(history, limit)})


@mcp.tool()
async def zammad_prepare_user_two_factor_change(
    user_id: int,
    operation: Literal["remove_method", "remove_all"],
    method: str | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview removal of one or all of a user's configured two-factor methods."""
    global _PLAN_CLEANER
    user_id = _validate_id(user_id)
    if not acknowledge_high_impact:
        raise ValueError("Removing two-factor authentication is high impact; set acknowledge_high_impact=true")
    snapshot = await _user_two_factor_snapshot(user_id)
    if operation == "remove_method":
        if not isinstance(method, str) or method not in snapshot["methods"]:
            raise ValueError("method must identify an enabled two-factor method for this user")
        after_methods = [item for item in snapshot["methods"] if item != method]
    else:
        if method is not None:
            raise ValueError("remove_all does not accept method")
        if not snapshot["methods"]:
            raise ValueError("The selected user has no configured two-factor methods")
        after_methods = []
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__user_two_factor_action__",
        "operation": operation,
        "object_id": user_id,
        "data": {"method": method} if method is not None else {},
        "fingerprint": _digest(snapshot),
        "before": snapshot,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "user_two_factor_authentication",
        "operation": operation,
        "user": snapshot["user"],
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Removing methods can reduce or remove this user's two-factor sign-in protection; the user may need to configure methods again.",
        "before": {"enabled_methods": snapshot["methods"]},
        "after": {"enabled_methods": after_methods},
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_user_unlock(
    user_id: int,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview unlocking a user whose failed-login count exceeds Zammad's configured threshold."""
    global _PLAN_CLEANER
    user_id = _validate_id(user_id)
    if not acknowledge_high_impact:
        raise ValueError("Unlocking an account is high impact; set acknowledge_high_impact=true to prepare it")
    snapshot = await _user_unlock_snapshot(user_id)
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__user_unlock__",
        "operation": "unlock",
        "object_id": user_id,
        "data": {},
        "fingerprint": _digest(snapshot),
        "before": snapshot,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "user_unlock",
        "operation": "unlock",
        "user": {key: value for key, value in snapshot["user"].items() if key != "login_failed"},
        "failed_login_count": snapshot["user"]["login_failed"],
        "configured_limit": snapshot["password_max_login_failed"],
        "after": {"login_failed": 0, "authentication_allowed": True},
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Allows the locked account to authenticate again.",
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_proxy_test(
    proxy: str,
    proxy_username: str | None = None,
    proxy_password: dict[str, Any] | None = None,
    proxy_no: str | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview an outbound proxy connectivity check; it does not save proxy settings."""
    global _PLAN_CLEANER
    if not acknowledge_high_impact:
        raise ValueError("A proxy check makes an outbound HTTP request; set acknowledge_high_impact=true to prepare it")
    if not isinstance(proxy, str) or not proxy.strip() or len(proxy) > 2048:
        raise ValueError("proxy must be a non-empty proxy address of at most 2048 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in proxy):
        raise ValueError("proxy must not contain control characters")
    if "@" in proxy:
        raise ValueError("proxy must not contain embedded credentials")
    if "://" in proxy:
        parsed_proxy = urlsplit(proxy)
        if parsed_proxy.scheme not in {"http", "https"} or not parsed_proxy.hostname or parsed_proxy.query or parsed_proxy.fragment:
            raise ValueError("proxy URL must be HTTP(S), include a host, and omit query and fragment")
    if proxy_username is not None and (
        not isinstance(proxy_username, str) or len(proxy_username) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in proxy_username)
    ):
        raise ValueError("proxy_username must be a string of at most 512 characters")
    if proxy_no is not None and (
        not isinstance(proxy_no, str) or len(proxy_no) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in proxy_no)
    ):
        raise ValueError("proxy_no must be a string of at most 4096 characters")
    if (proxy_username is None) != (proxy_password is None):
        raise ValueError("proxy_username and proxy_password must be supplied together")

    requested: dict[str, Any] = {"proxy": proxy.strip()}
    if proxy_username is not None:
        requested["proxy_username"] = proxy_username
        requested["proxy_password"] = proxy_password
    if proxy_no is not None:
        requested["proxy_no"] = proxy_no
    data, preview_data = _materialize_secret_values(requested)
    if "proxy_password" in data and not isinstance(data["proxy_password"], str):
        raise ValueError("proxy_password must be a process environment secret reference")
    if "proxy_password" in data and not data["proxy_password"]:
        raise ValueError("The referenced proxy password is empty")

    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__proxy_test__",
        "operation": "test",
        "object_id": None,
        "data": data,
        "fingerprint": _proxy_test_fingerprint(data),
        "before": None,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "proxy_test",
        "operation": "test",
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "proxy": {"address": preview_data["proxy"], "username_configured": "proxy_username" in preview_data,
                  "password_configured": "proxy_password" in preview_data,
                  "bypass_list_configured": bool(preview_data.get("proxy_no"))},
        "request_target": "http://zammad.org",
        "risk": "Apply sends an outbound HTTP request from Zammad through the selected proxy and may disclose proxy credentials to that proxy. No Zammad settings are saved.",
        "approval_required": True,
        "note": "No request was sent. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_ticket_agent_notification_apply(
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview the asynchronous action that applies default notifications to all agents."""
    global _PLAN_CLEANER
    if not acknowledge_high_impact:
        raise ValueError("This action affects every ticket agent; set acknowledge_high_impact=true to prepare it")
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    before = await _ticket_agent_notification_setting_snapshot()
    setting_id = _validate_id(before.get("id"))
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__ticket_notification_reset__",
        "operation": "apply_to_all",
        "object_id": setting_id,
        "data": {},
        "fingerprint": _digest(before),
        "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    safe_setting = _project_admin_settings(before)
    state_current = safe_setting.get("state_current") if isinstance(safe_setting, Mapping) else None
    matrix = state_current.get("value") if isinstance(state_current, Mapping) else None
    return _json({
        "plan_id": plan_id,
        "resource": "ticket_agent_notifications",
        "operation": "apply_to_all",
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Queues a background job that replaces notification preferences for every Zammad user with the ticket.agent permission.",
        "before": safe_setting,
        "after": {
            "notification_matrix_applied_to_each_agent": matrix,
            "target": "users with ticket.agent permission when the job runs",
            "job": "ResetNotificationsPreferencesJob",
            "asynchronous": True,
        },
        "approval_required": True,
        "note": "No write was performed. Explicit user approval is required before apply. The target user set and setting value are read by the background job at execution time.",
    })


@mcp.tool()
async def zammad_get_pgp_status() -> str:
    """Check whether Zammad reports its PGP integration as available."""
    status = await _get("/integration/pgp/status")
    return _json({"available": isinstance(status, Mapping) and "error" not in status})


@mcp.tool()
async def zammad_get_pgp_key(object_id: int) -> str:
    """Read safe metadata for one PGP key without returning key material or passphrases."""
    key = await _get(f"/integration/pgp/key/{_validate_id(object_id)}")
    return _json(project_pgp_key(key))


@mcp.tool()
async def zammad_list_admin_resources() -> str:
    """List API-backed administration resource names supported by this server."""
    resources = {name: {"operations": ["read", *sorted(spec.operations)], "risk": spec.risk} for name, spec in _RESOURCES.items()} | {
        _SPECIAL_CHANNEL: {"operations": ["read", "configure"], "risk": "Read returns sanitized notification channel metadata; configure sends a real test email and saves the active notification channel."},
        _EMAIL_ACCOUNT_RESOURCE: {"operations": ["configure"], "risk": "Verifies inbound/outbound mail, sends a test message, saves the mailbox, and starts mail fetching."},
        "email_channels": {"operations": ["read", "enable", "disable", "delete", "reassign"], "risk": "Lists email metadata; writes change inbound mailbox state and can alter ticket creation."},
        _MESSAGING_CHANNELS_RESOURCE: {"operations": ["read"], "risk": "Read-only sanitized inventory of non-email messaging channels from the shared channel endpoint."},
        "exchange_integration": {"operations": ["read"], "risk": "Shows whether Exchange OAuth data and application registration exist."},
        "exchange_connection_tests": {"operations": ["autodiscover", "folders", "mapping"], "risk": "Sends an approved outbound Exchange request; mapping reads contact-derived attributes but never returns example values."},
        "exchange_import_actions": {"operations": ["read_status", "dry_run", "start"], "risk": "Dry run reads real Exchange mailbox contacts and creates a persistent job; start may create or update Zammad users."},
        "knowledge_base_settings": {"operations": ["update"], "risk": "Preview/apply by knowledge_base_id; explicit confirmation required."},
        "knowledge_base_lifecycle": {"operations": ["activate", "deactivate"], "risk": "Changes public Knowledge Base availability; preview/apply and explicit confirmation required."},
        "knowledge_base_menu_items": {"operations": ["read", "update"], "risk": "Changes public navigation items for every Knowledge Base locale; complete preview and explicit confirmation required."},
        "knowledge_base_ordering": {"operations": ["read", "reorder"], "risk": "Changes public category or answer order; complete sibling preview and explicit confirmation required."},
        "knowledge_base_attachments": {"operations": ["read", "upload", "delete"], "risk": "Reads attachment metadata or changes files attached to a Knowledge Base answer; upload and deletion require explicit confirmation."},
        "knowledge_base_manager": {"operations": ["create", "delete"], "risk": "Creates an active Knowledge Base or permanently removes one and its content."},
        "knowledge_base_translations": {"operations": ["read", "update"], "risk": "Changes the Knowledge Base title or footer for one locale."},
        "knowledge_base_server_snippets": {"operations": ["read"], "risk": "Returns generated web server configuration snippets for one Knowledge Base."},
        "knowledge_base_feed_tokens": {"operations": ["ensure", "rotate"], "risk": "Ensuring may create a persistent private-feed token; rotation invalidates existing feed URLs. Secrets are stored locally and never returned."},
        "knowledge_base_publication": {"operations": ["read", "transition", "schedule"], "risk": "Changes internal or public answer visibility and can update the global public Knowledge Base setting; staged preview and explicit confirmation required."},
        "knowledge_bases": {"operations": ["read"], "risk": "Returns Knowledge Base metadata and content IDs available to the authenticated Zammad user; answer bodies are omitted."},
        "http_logs": {"operations": ["read"], "risk": "Returns recent integration log metadata; URLs and request/response payloads are omitted."},
        "knowledge_base_permissions": {"operations": ["read", "update"], "risk": "Changes role access to public Knowledge Base content; explicit confirmation required."},
        "knowledge_base_category_permissions": {"operations": ["read", "update"], "risk": "Changes inherited role access for a category and can affect descendant categories; explicit confirmation required."},
        "knowledge_base_answers": {"operations": ["read", "create", "update", "delete"], "risk": "Content writes are high impact and require explicit confirmation."},
        "knowledge_base_categories": {"operations": ["read", "create", "update", "delete"], "risk": "Content writes are high impact and require explicit confirmation."},
        "ldap_connection_tests": {"operations": ["discover", "bind"], "risk": "Connects from Zammad to the configured LDAP host; bind credentials are secret-safe and every action requires approval."},
        "ldap_import_actions": {"operations": ["dry_run", "sync"], "risk": "Dry-run reads all active LDAP directories and records aggregate results; sync may create, update, or deactivate Zammad users."},
        "data_privacy_tasks": {"operations": ["read", "queue_deletion"], "risk": "Queues asynchronous, irreversible user or ticket deletion; task impact may change before background execution."},
        "oauth_applications": {"operations": ["read", "create", "update", "delete", "issue_token"], "risk": "Changes OAuth client credentials or issues a bearer token for the current Zammad user."},
        "time_accounting_reports": {"operations": ["read"], "risk": "Returns up to 1000 redacted Time Accounting rows for one month."},
        "reports": {"operations": ["read_config", "generate_aggregates"], "risk": "Returns scoped report profile metadata and bounded aggregate time series; the report drilldown endpoint is not used."},
        "calendar_timezones": {"operations": ["read"], "risk": "Returns available timezone choices for calendar configuration."},
        "ticket_agent_notifications": {"operations": ["apply_to_all"], "risk": "Queues a background job that replaces notification preferences for every Zammad user with the ticket.agent permission."},
        "user_imports": {"operations": ["prepare", "apply"], "risk": "Creates or updates users in bulk; imports can change user identity, organization, and role assignments."},
        "organization_imports": {"operations": ["prepare", "apply"], "risk": "Creates or updates organizations in bulk and may change names, domains, sharing, or notes."},
        "user_history": {"operations": ["read"], "risk": "Returns recent account change metadata; secret-like field values are redacted and related user assets are omitted."},
        "organization_history": {"operations": ["read"], "risk": "Returns recent organization change metadata; secret-like field values are redacted and related assets are omitted."},
        "user_unlock": {"operations": ["unlock"], "risk": "Allows a user whose failed-login count exceeds the configured threshold to authenticate again."},
        "user_two_factor_authentication": {"operations": ["read", "remove_method", "remove_all"], "risk": "Removes one or all configured two-factor methods from a user and can weaken sign-in protection."},
        "proxy_test": {"operations": ["test"], "risk": "Sends an outbound HTTP request from Zammad through the selected proxy; does not save settings."},
        "pgp_keys": {"operations": ["read", "create", "delete"], "risk": "Manages PGP private keys; key material and passphrases are never returned."},
        "smime_certificates": {"operations": ["read", "create", "delete"], "risk": "Manages S/MIME certificates; deletion also removes an associated private key."},
        "smime_private_keys": {"operations": ["read", "create", "delete"], "risk": "Manages S/MIME private keys; key material and passphrases are never returned."},
    }
    return json.dumps(resources, ensure_ascii=False, indent=2, sort_keys=True)


@mcp.tool()
async def zammad_search_audit_logs(query: str, page: int = 1, per_page: int = 100) -> str:
    """Search the read-only Zammad security audit history."""
    if not isinstance(query, str) or not query.strip() or len(query) > 5000:
        raise ValueError("query must contain 1 to 5000 characters")
    if isinstance(page, bool) or not isinstance(page, int) or page < 1:
        raise ValueError("page must be a positive integer")
    if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= 100:
        raise ValueError("per_page must be between 1 and 100")
    params = {"page": page, "per_page": per_page}
    try:
        if len(query) <= 1500:
            result = await _get("/audit_logs/search", {**params, "query": query})
        else:
            result = await _request("POST", "/audit_logs/search", {"query": query}, params)
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            raise RuntimeError("The connected Zammad instance does not expose the audit-log API.") from exc
        raise
    return _json(project_audit_logs(result))


@mcp.tool()
async def zammad_prepare_user_import(
    csv_data: str,
    separator: str = ",",
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a Zammad user CSV import without returning imported user data."""
    global _PLAN_CLEANER
    if not acknowledge_high_impact:
        raise ValueError("User imports can create or update many accounts and roles; set acknowledge_high_impact=true to prepare")
    csv_data, separator = validate_user_import_input(csv_data, separator)
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())

    before = await _user_import_inventory_snapshot()
    preview = await _run_user_import(csv_data, separator, dry_run=True)
    after = await _user_import_inventory_snapshot()
    if before["fingerprint"] != after["fingerprint"]:
        raise RuntimeError("The user inventory changed during CSV preview; no import plan was created")
    if preview["result"] != "success":
        return _json({
            "resource": "user_imports",
            "plan_created": False,
            "preview": preview,
            "note": "Zammad's CSV dry-run did not succeed. No import plan was created and imported records were omitted.",
        })

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__user_import__",
        "operation": "import",
        "data": {"csv_data": csv_data, "separator": separator},
        "fingerprint": before["fingerprint"],
        "before": {"user_count": before["count"]},
        "import_preview": preview,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if any(item.get("resource") == "__user_import__" for item in _PLANS.values()):
            raise ValueError("Only one user CSV import plan can be active at a time")
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "user_imports",
        "operation": "import",
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "user_count_at_preview": before["count"],
        "preview": preview,
        "risk": "Applying this plan can create or update multiple user accounts, identities, organizations, and role assignments.",
        "approval_required": True,
        "note": "Zammad's dry-run rolled back its database transaction. The CSV is held only in the MCP process plan for up to five minutes; it is not returned or written to disk. Apply rechecks the user inventory and dry-run summary before importing.",
    })


@mcp.tool()
async def zammad_prepare_organization_import(
    csv_data: str,
    separator: str = ",",
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a Zammad organization CSV import without returning imported organization data."""
    global _PLAN_CLEANER
    if not acknowledge_high_impact:
        raise ValueError("Organization imports can create or update organizations in bulk; set acknowledge_high_impact=true to prepare")
    csv_data, separator = validate_user_import_input(csv_data, separator)
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())

    before = await _organization_import_inventory_snapshot()
    preview = await _run_organization_import(csv_data, separator, dry_run=True)
    after = await _organization_import_inventory_snapshot()
    if before["fingerprint"] != after["fingerprint"]:
        raise RuntimeError("The organization inventory changed during CSV preview; no import plan was created")
    if preview["result"] != "success":
        return _json({
            "resource": "organization_imports",
            "plan_created": False,
            "preview": preview,
            "note": "Zammad's CSV dry-run did not succeed. No import plan was created and imported records were omitted.",
        })

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__organization_import__",
        "operation": "import",
        "data": {"csv_data": csv_data, "separator": separator},
        "fingerprint": before["fingerprint"],
        "before": {"organization_count": before["count"]},
        "import_preview": preview,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if any(item.get("resource") == "__organization_import__" for item in _PLANS.values()):
            raise ValueError("Only one organization CSV import plan can be active at a time")
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "organization_imports",
        "operation": "import",
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "organization_count_at_preview": before["count"],
        "preview": preview,
        "risk": "Applying this plan can create or update multiple organization records and their attributes.",
        "approval_required": True,
        "note": "Zammad's dry-run rolled back its database transaction. The CSV is held only in the MCP process plan for up to five minutes; it is not returned or written to disk. Apply rechecks the organization inventory and dry-run summary before importing.",
    })


@mcp.tool()
async def zammad_list_http_logs(
    facility: Literal[
        "AI::Provider", "check_mk", "clearbit", "cti", "EWS", "GitHub", "GitLab", "idoit", "ldap",
        "MicrosoftGraph", "PGP", "placetel", "S/MIME", "SAML", "sipagte.io", "sipgate.io",
        "webhook", "WhatsApp::Business",
    ] | None = None,
    limit: int = 50,
) -> str:
    """List recent permitted integration HTTP logs without URLs or request/response payloads."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer between 1 and 100")
    if facility is not None and facility not in _HTTP_LOG_FACILITY_PATHS:
        raise ValueError("facility must be one of the supported Zammad HTTP log facilities")
    path = _HTTP_LOG_FACILITY_PATHS.get(facility, "/http_logs")
    items = project_http_logs(await _get(path, {"limit": limit}))
    return _json({
        "facility_filter": facility,
        "limit": limit,
        "returned": len(items),
        "items": items,
        "urls_returned": False,
        "request_and_response_payloads_returned": False,
    })


@mcp.tool()
async def zammad_list_admin_resource(resource: str, page: int = 1, per_page: int = 100, area: str | None = None) -> str:
    """List an administration resource, optionally filtering settings by Zammad area."""
    if isinstance(page, bool) or page < 1:
        raise ValueError("page must be a positive integer")
    if isinstance(per_page, bool) or not 1 <= per_page <= 100:
        raise ValueError("per_page must be between 1 and 100")
    if area is not None and resource != "settings":
        raise ValueError("area is supported only for settings")
    if area is not None and (not isinstance(area, str) or not re.fullmatch(r"[A-Za-z0-9_:.-]{1,120}", area)):
        raise ValueError("area must be a valid Zammad settings area name")
    params = {"page": page, "per_page": per_page}
    if resource == "audit_logs":
        params.update({"sort_by": "id", "order_by": "DESC"})
    if resource == "pgp_keys":
        return _json(project_pgp_collection(await _get("/integration/pgp/key")))
    if resource == "smime_certificates":
        return _json(project_smime_collection(await _get("/integration/smime/certificate")))
    if resource == "smime_private_keys":
        return _json(project_smime_private_key_collection(await _get("/integration/smime/certificate")))
    if resource in {_SPECIAL_CHANNEL, "email_channels", _MESSAGING_CHANNELS_RESOURCE}:
        channel_data = await _get(_SPECIAL_READ_PATH, params)
        if resource == _MESSAGING_CHANNELS_RESOURCE:
            return _json(_project_messaging_channels(channel_data))
        return _json(_project_email_channels(channel_data))
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        return _json(_project_messaging_channels(await _get(_resource(resource).path, params)))
    if resource == "facebook_channels":
        return _json(_project_messaging_channels(await _get(_resource(resource).path, params)))
    if resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        return _json(_project_messaging_channels(await _get(_resource(resource).path, params)))
    if resource == "product_logo":
        settings = _project_settings(await _get("/settings"))
        return _json([item for item in settings if isinstance(item, Mapping) and item.get("name") == "product_logo"] if isinstance(settings, list) else [])
    if resource == "ssl_certificates":
        return _json(project_ssl_certificate_collection(await _get("/ssl_certificates")))
    if resource == "monitoring":
        return await zammad_get_monitoring_health()
    if resource == "packages":
        return _json(await _package_inventory_snapshot())
    if resource == "system_report":
        return _json(project_system_report_summary(await _get("/system_report")))
    if resource in {"ai_agents", "ai_text_tools"}:
        return _json(project_ai_collection(resource, await _get(_resource(resource).path, params)))
    if resource == "ai_agent_types":
        return _json(project_agent_types(await _get(_resource(resource).path)))
    if resource == "sessions":
        return _json(project_sessions(await _get("/sessions")))
    if resource == "data_privacy_tasks":
        return _json(project_data_privacy_tasks(await _get("/data_privacy_tasks", params)))
    if resource == "oauth_applications":
        return _json(project_oauth_applications(await _get("/applications", {**params, "full": True})))
    if resource == "time_accounting_types":
        return _json(project_time_accounting_types(await _get(_resource(resource).path, params)))
    if resource == "audit_logs":
        try:
            return _json(project_audit_logs(await _get("/audit_logs", params)))
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                raise RuntimeError("The connected Zammad instance does not expose the audit-log API.") from exc
            raise
    spec = _resource(resource)
    result = await _get(spec.path, params)
    if resource == "settings":
        result = _project_admin_settings(result)
        if area is not None:
            result = [item for item in result if isinstance(item, Mapping) and item.get("area") == area] if isinstance(result, list) else []
    return _json(result)


async def _ssl_certificate_snapshot(certificate_id: int | None = None) -> Any:
    certificates = project_ssl_certificate_collection(await _get("/ssl_certificates"))
    if certificate_id is None:
        return sorted(certificates, key=lambda item: item.get("id", 0))
    matches = [item for item in certificates if item.get("id") == certificate_id]
    if len(matches) > 1:
        raise RuntimeError("Zammad returned duplicate SSL certificate IDs")
    return matches[0] if matches else None


async def _package_inventory_snapshot() -> dict[str, Any]:
    return project_package_inventory(await _get("/packages"))


async def _object_manager_migration_snapshot() -> list[Mapping[str, Any]]:
    attributes = await _get("/object_manager_attributes")
    if not isinstance(attributes, list) or any(not isinstance(item, Mapping) for item in attributes):
        raise RuntimeError("Zammad did not return object manager attributes")
    return [
        item for item in attributes
        if any(item.get(flag) is True for flag in ("to_create", "to_migrate", "to_delete", "to_config"))
    ]


async def _session_snapshot(session_id: int) -> tuple[Mapping[str, Any], dict[str, Any]] | None:
    response = await _get("/sessions")
    if not isinstance(response, Mapping) or not isinstance(response.get("sessions"), list):
        raise RuntimeError("Zammad did not return its active sessions")
    matches = [item for item in response["sessions"] if isinstance(item, Mapping) and item.get("id") == session_id]
    if len(matches) > 1:
        raise RuntimeError("Zammad returned duplicate session IDs")
    if not matches:
        return None
    projected = project_sessions(response)
    projected_matches = [item for item in projected if item.get("id") == session_id]
    if len(projected_matches) != 1:
        raise RuntimeError("Zammad session projection did not identify exactly one session")
    return matches[0], projected_matches[0]


async def _oauth_application_snapshot(application_id: int) -> Mapping[str, Any]:
    collection = await _get("/applications", {"full": True})
    assets = collection.get("assets") if isinstance(collection, Mapping) else None
    applications = assets.get("Application") if isinstance(assets, Mapping) else None
    application = applications.get(str(_validate_id(application_id))) if isinstance(applications, Mapping) else None
    if not isinstance(application, Mapping) or application.get("id") != application_id:
        raise RuntimeError("Zammad did not return the selected OAuth application")
    return application


async def _data_privacy_deletion_snapshot(kind: str, object_id: int, delete_organization: bool) -> dict[str, Any]:
    target = await _get(f"/{'users' if kind == 'User' else 'tickets'}/{object_id}")
    if not isinstance(target, Mapping) or target.get("id") != object_id:
        raise RuntimeError("Zammad did not return the selected deletion target")
    snapshot: dict[str, Any] = {"target": target}
    if kind == "User":
        for field, condition in (
            ("customer_tickets", {"ticket.customer_id": {"operator": "is", "pre_condition": "specific", "value": object_id}}),
            ("owner_tickets", {"ticket.owner_id": {"operator": "is", "pre_condition": "specific", "value": object_id}}),
        ):
            selector = await _request("POST", "/tickets/selector", {"condition": condition})
            snapshot[field] = project_data_privacy_selector(selector)
        organization_id = target.get("organization_id")
        if delete_organization:
            if isinstance(organization_id, bool) or not isinstance(organization_id, int) or organization_id <= 0:
                raise ValueError("delete_organization requires the selected user to belong to an organization")
            organization = await _get(f"/organizations/{organization_id}")
            members = organization.get("member_ids") if isinstance(organization, Mapping) else None
            if not isinstance(members, list) or object_id not in members:
                raise RuntimeError("Zammad did not return a verifiable organization membership list")
            if len(members) != 1:
                raise ValueError("The organization can be included only when the selected user is its sole member")
            snapshot["organization"] = organization
    return snapshot


async def _user_import_inventory_snapshot() -> dict[str, Any]:
    users: list[Mapping[str, Any]] = []
    page = 1
    while True:
        batch = await _get("/users", {"page": page, "per_page": 100})
        if not isinstance(batch, list) or any(not isinstance(item, Mapping) for item in batch):
            raise RuntimeError("Zammad did not return a valid user inventory")
        users.extend(batch)
        if len(batch) < 100:
            break
        if len(users) >= 100_000:
            raise RuntimeError("User inventory is too large to stage a safe CSV import")
        page += 1
    return {"count": len(users), "fingerprint": _crypto_digest(users)}


async def _organization_import_inventory_snapshot() -> dict[str, Any]:
    organizations: list[Mapping[str, Any]] = []
    page = 1
    while True:
        batch = await _get("/organizations", {"page": page, "per_page": 100})
        if not isinstance(batch, list) or any(not isinstance(item, Mapping) for item in batch):
            raise RuntimeError("Zammad did not return a valid organization inventory")
        organizations.extend(batch)
        if len(batch) < 100:
            break
        if len(organizations) >= 100_000:
            raise RuntimeError("Organization inventory is too large to stage a safe CSV import")
        page += 1
    return {"count": len(organizations), "fingerprint": _crypto_digest(organizations)}


async def _run_user_import(csv_data: str, separator: str, *, dry_run: bool) -> dict[str, Any]:
    try:
        result = await _request(
            "POST",
            "/users/import",
            {"data": csv_data, "col_sep": separator},
            {"try": "true" if dry_run else "false"},
        )
    except RuntimeError:
        raise RuntimeError("Zammad rejected the user CSV import request; details were withheld") from None
    projected = project_user_import_result(result)
    if projected["dry_run"] is not dry_run:
        raise RuntimeError("Zammad did not confirm the requested user import mode")
    return projected


async def _run_organization_import(csv_data: str, separator: str, *, dry_run: bool) -> dict[str, Any]:
    try:
        result = await _request(
            "POST",
            "/organizations/import",
            {"data": csv_data, "col_sep": separator},
            {"try": "true" if dry_run else "false"},
        )
    except RuntimeError:
        raise RuntimeError("Zammad rejected the organization CSV import request; details were withheld") from None
    projected = project_organization_import_result(result, "organization")
    if projected["dry_run"] is not dry_run:
        raise RuntimeError("Zammad did not confirm the requested organization import mode")
    return projected


def _data_privacy_deletion_preview(kind: str, snapshot: Mapping[str, Any], delete_organization: bool) -> dict[str, Any]:
    result = {
        "target": project_deletion_target(kind, snapshot.get("target")),
        "asynchronous_execution": True,
        "ticket_deletion_counts": {
            key.removesuffix("_tickets"): snapshot[key]["object_count"]
            for key in ("customer_tickets", "owner_tickets") if key in snapshot
        },
        "ticket_id_samples": {
            key.removesuffix("_tickets"): snapshot[key]["sample_ids"]
            for key in ("customer_tickets", "owner_tickets") if key in snapshot
        },
        "delete_organization": delete_organization,
    }
    if "organization" in snapshot:
        organization = snapshot["organization"]
        result["organization"] = {
            key: organization[key] for key in ("id", "name") if key in organization
        } if isinstance(organization, Mapping) else None
    return result


def _object_manager_migration_preview(attributes: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    fields = ("id", "object", "name", "display", "data_type", "to_create", "to_migrate", "to_delete", "to_config")
    return [{key: item[key] for key in fields if key in item} for item in attributes]


def _register_legacy_list_tool(resource: str) -> None:
    """Keep stable names from the original read-only tool set."""
    async def list_resource() -> str:
        return _json(await _get(_resource(resource).path))

    list_resource.__name__ = f"zammad_list_{resource}"
    list_resource.__doc__ = f"List configured Zammad {resource.replace('_', ' ')}. Read-only."
    mcp.tool(name=list_resource.__name__)(list_resource)


for _legacy_resource in ("groups", "roles", "calendars", "slas", "triggers", "ticket_states"):
    _register_legacy_list_tool(_legacy_resource)


@mcp.tool()
async def zammad_list_roles_expanded() -> str:
    """List roles with related permissions expanded where supported."""
    return _json(await _get("/roles?expand=true"))


@mcp.tool()
async def zammad_get_admin_object(resource: str, object_id: int) -> str:
    """Read one object from a Zammad administration resource."""
    spec = _resource(resource)
    if not spec.item:
        raise ValueError("This resource does not support item reads")
    object_id = _validate_id(object_id)
    if resource == "oauth_applications":
        result = await _oauth_application_snapshot(object_id)
    elif resource == "time_accounting_types":
        result = await _time_accounting_type_snapshot(object_id)
    elif resource == "ai_agents":
        result = project_agent_snapshot(await _get(f"{spec.path}/{object_id}", {"full": True}))
    elif resource == "audit_logs":
        try:
            result = project_audit_log(await _get(f"{spec.path}/{object_id}"))
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                raise RuntimeError("The connected Zammad instance does not expose the audit-log API.") from exc
            raise
    else:
        result = await _get(f"{spec.path}/{object_id}")
    if result is None:
        raise ValueError("No matching object was returned by Zammad")
    if resource in {"settings", "product_logo"}:
        result = _project_admin_settings(result) if resource == "settings" else _project_settings(result)
    if resource == "ai_text_tools":
        result = project_ai_object(resource, result)
    if resource == "oauth_applications":
        result = project_oauth_application(result)
    return _json(result)


@mcp.tool()
async def zammad_prepare_ldap_import_action(
    action: Literal["dry_run", "sync"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an LDAP dry-run import or full synchronization without starting it."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("LDAP import actions require acknowledge_high_impact=true")
    if action not in {"dry_run", "sync"}:
        raise ValueError("Unsupported LDAP import action")
    sources = await _ldap_sources_snapshot()
    active_count = sum(source.get("active") is True for source in sources)
    if active_count == 0:
        raise ValueError("At least one active LDAP source is required")
    if await _ldap_import_pending(action):
        raise ValueError(f"An LDAP {action.replace('_', ' ')} job is already queued or running")
    dependencies: list[dict[str, str]] = []
    integration_enabled: bool | None = None
    if action == "sync":
        setting = await _ldap_integration_setting_snapshot()
        integration_enabled = True
        dependencies.append({"path": f"/settings/{setting['id']}", "fingerprint": _digest(setting)})
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__ldap_import_action__", "operation": action, "object_id": None,
        "data": {}, "fingerprint": _digest(sources),
        "before": {"active_source_count": active_count, "total_source_count": len(sources)},
        "dependencies": dependencies, "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    if action == "dry_run":
        effects = [
            f"Read all {active_count} active LDAP sources and their directories",
            "Create an ImportJob dry-run record and store aggregate import results",
            "Do not save, update, or deactivate Zammad users or roles",
        ]
    else:
        effects = [
            f"Queue a background sync across all {active_count} active LDAP sources",
            "The sync may create, update, or deactivate Zammad users and update role assignments",
        ]
    return _json({
        "plan_id": plan_id,
        "resource": "ldap_import_actions",
        "operation": action,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "before": {"active_source_count": active_count, "total_source_count": len(sources), "ldap_integration_enabled": integration_enabled},
        "after": {"action": action},
        "write_effects": effects,
        "approval_required": True,
        "note": "No import job was created. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_get_ldap_import_status(
    action: Literal["dry_run", "sync"],
    include_completed: bool = True,
) -> str:
    """Read LDAP import progress and aggregate counts without exposing payloads or directory records."""
    if action == "dry_run":
        params = {"finished": "true" if include_completed else "false"}
        job = await _get("/integration/ldap/job_try", params)
    else:
        job = await _get("/integration/ldap/job_start")
    return _json(_ldap_import_status_summary(job, action))


@mcp.tool()
async def zammad_prepare_ldap_connection_action(
    action: Literal["discover", "bind"],
    data: dict[str, Any],
    source_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an LDAP discovery or bind check without contacting the directory."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("LDAP connection actions require acknowledge_high_impact=true")
    if action not in {"discover", "bind"}:
        raise ValueError("Unsupported LDAP connection action")
    if not isinstance(data, dict):
        raise ValueError("data must be a JSON object")
    if action == "discover" and source_id is not None:
        raise ValueError("discover does not accept source_id")
    if action == "bind" and source_id is None and data.get("bind_pw") == "**********":
        raise ValueError("A masked bind password can only be reused when source_id identifies its existing LDAP source")
    if action == "bind" and source_id is not None:
        source_id = _validate_id(source_id)
        source_before = await _get(f"/ldap_sources/{source_id}")
        if not isinstance(source_before, Mapping):
            raise RuntimeError("The Zammad API did not return an LDAP source snapshot")
        data = retain_ldap_action_values(data, source_before)
    validate_ldap_action_payload(action, data)
    data, preview_data = materialize_ldap_action(data)
    before = source_before if action == "bind" and source_id is not None else None
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__ldap_connection_action__", "operation": action, "object_id": source_id,
        "data": data, "fingerprint": _digest(before) if before is not None else None,
        "before": before, "dependencies": [], "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    write_effects = ["Connect from Zammad to the LDAP host when this plan is applied"]
    if action == "bind" and isinstance(preview_data.get("bind_pw"), str) and preview_data["bind_pw"] == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]":
        write_effects.append("Use the supplied process-environment bind password without returning it")
    elif action == "bind" and preview_data.get("bind_pw") == "[EXISTING SECRET RETAINED]":
        write_effects.append("Use the existing bind password without returning it")
    return _json({
        "plan_id": plan_id,
        "resource": "ldap_connection_tests",
        "operation": action,
        "object_id": source_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Contacts the configured LDAP server and may reveal directory naming contexts, attributes, or group names.",
        "before": _scrub(before),
        "after": {"action": action, "request": preview_data},
        "write_effects": write_effects,
        "approval_required": True,
        "note": "No LDAP request was sent. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_list_knowledge_bases() -> str:
    """Discover Knowledge Bases and translated category/answer titles without returning answer bodies."""
    assets = await _request("POST", "/knowledge_bases/init", {})
    return _json(project_knowledge_base_inventory(assets))


async def _knowledge_base_translation_snapshot(knowledge_base_id: int, kb_locale_id: int) -> dict[str, Any]:
    inventory = project_knowledge_base_inventory(await _request("POST", "/knowledge_bases/init", {}))
    return project_knowledge_base_translation_snapshot(inventory, knowledge_base_id, kb_locale_id)


async def _knowledge_base_menu_snapshot(knowledge_base_id: int, location: str) -> dict[str, Any]:
    assets = await _get("/knowledge_bases/manage/init")
    return project_knowledge_base_menu_snapshot(assets, knowledge_base_id, location)


@mcp.tool()
async def zammad_get_knowledge_base_menu_items(
    knowledge_base_id: int,
    location: Literal["header", "footer"],
) -> str:
    """Read all public menu items for one Knowledge Base location and every locale."""
    kb_id = _validate_id(knowledge_base_id)
    snapshot = await _knowledge_base_menu_snapshot(kb_id, location)
    return _json(snapshot)


async def _knowledge_base_order_snapshot(
    knowledge_base_id: int,
    kind: Literal["root_categories", "categories", "answers"],
    category_id: int | None,
) -> dict[str, Any]:
    assets = await _request("POST", "/knowledge_bases/init", {})
    inventory = project_knowledge_base_inventory(assets)
    return project_knowledge_base_siblings(inventory, knowledge_base_id, kind, category_id)


def _knowledge_base_order_path(knowledge_base_id: int, kind: str, category_id: int | None) -> str:
    if kind == "root_categories":
        return f"/knowledge_bases/{knowledge_base_id}/categories/reorder_root_categories"
    if category_id is None:
        raise ValueError("category_id is required for child category and answer ordering")
    action = "reorder_categories" if kind == "categories" else "reorder_answers"
    return f"/knowledge_bases/{knowledge_base_id}/categories/{category_id}/{action}"


@mcp.tool()
async def zammad_get_knowledge_base_order(
    knowledge_base_id: int,
    kind: Literal["root_categories", "categories", "answers"],
    category_id: int | None = None,
) -> str:
    """Read ordered sibling IDs for a Knowledge Base category or answer collection."""
    kb_id = _validate_id(knowledge_base_id)
    parent_id = _validate_id(category_id) if category_id is not None else None
    snapshot = await _knowledge_base_order_snapshot(kb_id, kind, parent_id)
    return _json(snapshot)


async def _knowledge_base_publication_snapshot(knowledge_base_id: int, answer_id: int) -> dict[str, Any]:
    answer_value = await _get(f"/knowledge_bases/{knowledge_base_id}/answers/{answer_id}")
    assets = answer_value.get("assets") if isinstance(answer_value, Mapping) else None
    answer_assets = assets.get("KnowledgeBaseAnswer") if isinstance(assets, Mapping) else None
    answer = answer_assets.get(str(answer_id)) if isinstance(answer_assets, Mapping) else None
    category_id = answer.get("category_id") if isinstance(answer, Mapping) else None
    category_id = _validate_id(category_id)
    category_value = await _get(f"/knowledge_bases/{knowledge_base_id}/categories/{category_id}")
    return project_knowledge_base_publication_snapshot(
        answer_value, knowledge_base_id, answer_id, category_value
    )


async def _knowledge_base_attachments_snapshot(knowledge_base_id: int, answer_id: int) -> dict[str, Any]:
    answer_value = await _get(f"/knowledge_bases/{knowledge_base_id}/answers/{answer_id}")
    assets = answer_value.get("assets") if isinstance(answer_value, Mapping) else None
    answer_assets = assets.get("KnowledgeBaseAnswer") if isinstance(assets, Mapping) else None
    answer = answer_assets.get(str(answer_id)) if isinstance(answer_assets, Mapping) else None
    category_id = _validate_id(answer.get("category_id")) if isinstance(answer, Mapping) else None
    if category_id is None:
        raise RuntimeError("Zammad did not return the Knowledge Base answer category")
    category = await _get(f"/knowledge_bases/{knowledge_base_id}/categories/{category_id}")
    return project_knowledge_base_attachments_snapshot(answer_value, knowledge_base_id, answer_id, category)


async def _knowledge_base_deletion_snapshot(knowledge_base_id: int) -> dict[str, Any]:
    knowledge_base = await _get(f"/knowledge_bases/{knowledge_base_id}")
    inventory = project_knowledge_base_inventory(await _request("POST", "/knowledge_bases/init", {}))
    preliminary_categories = {
        item["id"] for item in inventory["categories"]
        if isinstance(item, Mapping) and item.get("knowledge_base_id") == knowledge_base_id
    }
    preliminary_answer_ids = {
        item["id"] for item in inventory["answers"]
        if isinstance(item, Mapping) and item.get("category_id") in preliminary_categories
    }
    content_ids = sorted({
        _validate_id(item.get("content_id"))
        for item in inventory["answer_translations"]
        if isinstance(item, Mapping) and item.get("answer_id") in preliminary_answer_ids
    })
    if content_ids:
        inventory = project_knowledge_base_inventory(await _request(
            "POST", "/knowledge_bases/init", {"answer_translation_content_ids": content_ids}
        ))
    header_menu = await _knowledge_base_menu_snapshot(knowledge_base_id, "header")
    footer_menu = await _knowledge_base_menu_snapshot(knowledge_base_id, "footer")
    permissions = await _get(f"/knowledge_bases/{knowledge_base_id}/permissions")
    categories = [
        item for item in inventory["categories"]
        if isinstance(item, Mapping) and item.get("knowledge_base_id") == knowledge_base_id
    ]
    categories_by_id = {item["id"]: item for item in categories}
    category_permissions = {}
    for category in categories:
        category_id = _validate_id(category.get("id"))
        category_permissions[category_id] = await _get(
            f"/knowledge_bases/{knowledge_base_id}/categories/{category_id}/permissions"
        )
    answers = [
        item for item in inventory["answers"]
        if isinstance(item, Mapping)
        and any(category.get("id") == item.get("category_id") for category in categories)
    ]
    answer_attachments = {}
    for answer in answers:
        answer_id = _validate_id(answer.get("id"))
        answer_value = await _get(f"/knowledge_bases/{knowledge_base_id}/answers/{answer_id}")
        answer_assets = answer_value.get("assets") if isinstance(answer_value, Mapping) else None
        answer_records = answer_assets.get("KnowledgeBaseAnswer") if isinstance(answer_assets, Mapping) else None
        answer_record = answer_records.get(str(answer_id)) if isinstance(answer_records, Mapping) else None
        category_id = _validate_id(answer_record.get("category_id")) if isinstance(answer_record, Mapping) else None
        category = categories_by_id.get(category_id)
        if category is None:
            raise RuntimeError("Zammad returned an answer outside the selected Knowledge Base")
        answer_attachments[answer_id] = project_knowledge_base_attachments_snapshot(
            answer_value, knowledge_base_id, answer_id, category
        )
    return project_knowledge_base_deletion_snapshot(
        knowledge_base_id, knowledge_base, inventory, header_menu, footer_menu,
        permissions, category_permissions, answer_attachments,
    )


@mcp.tool()
async def zammad_get_knowledge_base_attachments(knowledge_base_id: int, answer_id: int) -> str:
    """Read file names, sizes, and content types attached to one Knowledge Base answer."""
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(answer_id)
    return _json(await _knowledge_base_attachments_snapshot(kb_id, item_id))


@mcp.tool()
async def zammad_get_knowledge_base_publication_state(
    knowledge_base_id: int,
    answer_id: int,
) -> str:
    """Read a Knowledge Base answer's scheduled publication timestamps and current state."""
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(answer_id)
    snapshot = await _knowledge_base_publication_snapshot(kb_id, item_id)
    return _json({**snapshot, "state": knowledge_base_publication_state(snapshot)})


@mcp.tool()
async def zammad_get_knowledge_base(knowledge_base_id: int) -> str:
    """Read one Knowledge Base configuration object by its Zammad ID."""
    return _json(await _get(f"/knowledge_bases/{_validate_id(knowledge_base_id)}"))


@mcp.tool()
async def zammad_get_knowledge_base_server_snippets(knowledge_base_id: int) -> str:
    """Read generated Nginx and Apache snippets for one Knowledge Base."""
    kb_id = _validate_id(knowledge_base_id)
    result = await _get(f"/knowledge_bases/manage/{kb_id}/server_snippets")
    return _json(project_knowledge_base_server_snippets(result))


@mcp.tool()
async def zammad_get_knowledge_base_translation(
    knowledge_base_id: int,
    kb_locale_id: int,
) -> str:
    """Read one Knowledge Base title and footer for its configured locale."""
    kb_id = _validate_id(knowledge_base_id)
    locale_id = _validate_id(kb_locale_id)
    snapshot = await _knowledge_base_translation_snapshot(kb_id, locale_id)
    return _json(snapshot)


@mcp.tool()
async def zammad_list_knowledge_base_categories(knowledge_base_id: int) -> str:
    """List category IDs and parent/child relationships for one Knowledge Base."""
    kb_id = _validate_id(knowledge_base_id)
    knowledge_base = await _get(f"/knowledge_bases/{kb_id}")
    if not isinstance(knowledge_base, Mapping):
        raise RuntimeError("Zammad did not return the Knowledge Base snapshot")
    try:
        snapshot_kb_id = _validate_id(knowledge_base.get("id"))
    except ValueError as exc:
        raise RuntimeError("Zammad returned an invalid Knowledge Base snapshot") from exc
    if snapshot_kb_id != kb_id:
        raise RuntimeError("Zammad returned a different Knowledge Base")
    raw_category_ids = knowledge_base.get("category_ids")
    if not isinstance(raw_category_ids, list):
        raise RuntimeError("Zammad did not return the Knowledge Base category IDs")

    category_ids = [_validate_id(item) for item in raw_category_ids]
    if len(category_ids) != len(set(category_ids)):
        raise RuntimeError("Zammad returned duplicate Knowledge Base category IDs")
    semaphore = asyncio.Semaphore(8)

    async def read_category(category_id: int) -> dict[str, Any]:
        async with semaphore:
            value = await _get(f"/knowledge_bases/{kb_id}/categories/{category_id}")
        if not isinstance(value, Mapping):
            raise RuntimeError("Zammad did not return a category record")
        try:
            item_id = _validate_id(value.get("id"))
            item_kb_id = _validate_id(value.get("knowledge_base_id"))
            parent_raw = value.get("parent_id")
            parent_id = _validate_id(parent_raw) if parent_raw is not None else None
            child_ids_raw = value.get("child_ids")
            if not isinstance(child_ids_raw, list):
                raise ValueError("child_ids must be a list")
            child_ids = [_validate_id(child_id) for child_id in child_ids_raw]
            if len(child_ids) != len(set(child_ids)):
                raise ValueError("child_ids must not repeat")
            translation_ids_raw = value.get("translation_ids")
            if not isinstance(translation_ids_raw, list):
                raise ValueError("translation_ids must be a list")
            translation_ids = [_validate_id(translation_id) for translation_id in translation_ids_raw]
            if len(translation_ids) != len(set(translation_ids)):
                raise ValueError("translation_ids must not repeat")
        except ValueError as exc:
            raise RuntimeError("Zammad returned an invalid Knowledge Base category") from exc
        if item_id != category_id or item_kb_id != kb_id:
            raise RuntimeError("Zammad returned a category outside the selected Knowledge Base")
        return {
            "category_id": item_id,
            "parent_category_id": parent_id,
            "child_category_ids": sorted(child_ids),
            "translation_ids": sorted(translation_ids),
            "category_icon": value.get("category_icon"),
        }

    categories = await asyncio.gather(*(read_category(category_id) for category_id in category_ids))
    categories_by_id = {item["category_id"]: item for item in categories}
    for item in categories:
        parent_id = item["parent_category_id"]
        if parent_id is not None:
            parent = categories_by_id.get(parent_id)
            if parent is None or item["category_id"] not in parent["child_category_ids"]:
                raise RuntimeError("Zammad returned inconsistent Knowledge Base category relationships")
        for child_id in item["child_category_ids"]:
            child = categories_by_id.get(child_id)
            if child is None or child["parent_category_id"] != item["category_id"]:
                raise RuntimeError("Zammad returned inconsistent Knowledge Base category relationships")
        visited = {item["category_id"]}
        ancestor_id = parent_id
        while ancestor_id is not None:
            if ancestor_id in visited:
                raise RuntimeError("Zammad returned a cyclic Knowledge Base category tree")
            visited.add(ancestor_id)
            ancestor_id = categories_by_id[ancestor_id]["parent_category_id"]

    return _json({"knowledge_base_id": kb_id, "categories": sorted(categories, key=lambda item: item["category_id"])})


@mcp.tool()
async def zammad_get_knowledge_base_permissions(knowledge_base_id: int) -> str:
    """Read the role permissions configured for one Knowledge Base."""
    return _json(await _get(f"/knowledge_bases/{_validate_id(knowledge_base_id)}/permissions"))


@mcp.tool()
async def zammad_get_knowledge_base_category_permissions(knowledge_base_id: int, category_id: int) -> str:
    """Read configured and inherited role access for one Knowledge Base category."""
    kb_id = _validate_id(knowledge_base_id)
    category = _validate_id(category_id)
    category_snapshot = await _get(f"/knowledge_bases/{kb_id}/categories/{category}")
    if not isinstance(category_snapshot, Mapping):
        raise RuntimeError("Zammad did not return the Knowledge Base category snapshot")
    try:
        snapshot_category_id = _validate_id(category_snapshot.get("id"))
        snapshot_kb_id = _validate_id(category_snapshot.get("knowledge_base_id"))
    except ValueError as exc:
        raise RuntimeError("Zammad returned an invalid Knowledge Base category snapshot") from exc
    if snapshot_category_id != category or snapshot_kb_id != kb_id:
        raise ValueError("category_id does not identify a category in the selected Knowledge Base")
    return _json(await _get(f"/knowledge_bases/{kb_id}/categories/{category}/permissions"))


def _validate_translation_locale(locale: str) -> str:
    if not isinstance(locale, str) or not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", locale):
        raise ValueError("locale must be a locale code such as de-de or en-us")
    return locale.lower()


async def _translation_upsert_snapshot(locale: str, source: str) -> Mapping[str, Any] | None:
    customized = await _get("/translations/customized")
    if not isinstance(customized, list) or any(not isinstance(item, Mapping) for item in customized):
        raise RuntimeError("Zammad did not return customized translations")
    customized_matches = [
        item for item in customized
        if item.get("locale") == locale and item.get("source") == source
    ]
    if len(customized_matches) > 1:
        raise RuntimeError("Zammad returned duplicate customized translations")
    if customized_matches:
        return customized_matches[0]

    response = await _get(f"/translations/search/{locale}", {"query": source})
    items = response.get("items") if isinstance(response, Mapping) else None
    total_count = response.get("total_count") if isinstance(response, Mapping) else None
    if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
        raise RuntimeError("Zammad did not return translation search results")
    if isinstance(total_count, bool) or not isinstance(total_count, int) or total_count < len(items):
        raise RuntimeError("Zammad returned an invalid translation search count")
    matches = [
        item for item in items
        if item.get("source") == source and isinstance(item.get("id"), int) and not isinstance(item.get("id"), bool)
    ]
    if len(matches) > 1:
        raise RuntimeError("Zammad returned duplicate exact translation sources")
    if not matches and isinstance(total_count, int) and total_count > len(items):
        raise RuntimeError("The translation search results were truncated; narrow the source text and prepare again")
    return matches[0] if matches else None


@mcp.tool()
async def zammad_list_customized_translations() -> str:
    """List custom or changed translation entries from Zammad."""
    return _json(await _get("/translations/customized"))


@mcp.tool()
async def zammad_search_translation_suggestions(locale: str, query: str) -> str:
    """Search system and custom translation suggestions for one locale."""
    locale = _validate_translation_locale(locale)
    if not isinstance(query, str):
        raise ValueError("query must be a string")
    return _json(await _get(f"/translations/search/{locale}", {"query": query}))


async def _monitoring_health_snapshot() -> Mapping[str, Any]:
    health = await _get("/monitoring/health_check")
    if not isinstance(health, Mapping) or not isinstance(health.get("issues"), list):
        raise RuntimeError("Zammad did not return a monitoring health snapshot")
    failed_issues = sorted(
        issue for issue in health["issues"]
        if isinstance(issue, str) and issue.startswith("Failed to run scheduled job '")
    )
    return {
        "healthy": health.get("healthy") is True,
        "issue_count": len(health["issues"]),
        "failed_job_count": len(failed_issues),
        "failed_jobs_fingerprint": _digest(failed_issues),
    }


async def _monitoring_token_setting_snapshot() -> Mapping[str, Any]:
    settings = _project_settings(await _get("/settings"))
    candidates = [item for item in settings if isinstance(item, Mapping) and item.get("name") == "monitoring_token"] if isinstance(settings, list) else []
    if len(candidates) != 1:
        raise RuntimeError("The monitoring token setting is missing or ambiguous")
    state = candidates[0].get("state_current")
    if not isinstance(state, Mapping):
        raise RuntimeError("Zammad did not return monitoring token state metadata")
    return {
        "id": candidates[0].get("id"),
        "name": "monitoring_token",
        "configured": state.get("value_configured") is True,
    }


@mcp.tool()
async def zammad_get_monitoring_health() -> str:
    """Read a redacted monitoring summary without returning the monitoring token or issue details."""
    health = await _monitoring_health_snapshot()
    return _json({
        "healthy": health["healthy"],
        "issue_count": health["issue_count"],
        "failed_job_count": health["failed_job_count"],
        "can_restart_failed_jobs": health["failed_job_count"] > 0,
        "issue_details_returned": False,
        "monitoring_token_returned": False,
    })


@mcp.tool()
async def zammad_prepare_monitoring_action(
    operation: Literal["rotate_token", "restart_failed_jobs"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a monitoring token rotation or failed-job restart."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Monitoring actions require acknowledge_high_impact=true")

    if operation == "rotate_token":
        before = await _monitoring_token_setting_snapshot()
        after = {"token_rotated": True, "token_value_returned": False, "secure_storage": "owner-only local file"}
    else:
        before = await _monitoring_health_snapshot()
        if before["failed_job_count"] == 0:
            raise ValueError("There are no failed monitoring jobs to restart")
        after = {"failed_jobs_reactivated": before["failed_job_count"]}

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__monitoring_action__", "operation": operation,
        "object_id": None, "data": {}, "fingerprint": _digest(before),
        "before": before, "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    risk = (
        "Replaces the monitoring token used by external health checks; current consumers must be updated."
        if operation == "rotate_token"
        else "Reactivates every failed scheduler job so Zammad may retry it."
    )
    return _json({
        "plan_id": plan_id, "resource": "monitoring", "operation": operation,
        "expires_in_seconds": _PLAN_TTL_SECONDS, "snapshot_fingerprint": plan["fingerprint"],
        "risk": risk, "before": before, "after": after,
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_object_manager_migrations(acknowledge_high_impact: bool = False) -> str:
    """Preview all queued object manager migrations, including permanent data loss from field removal."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Object manager migrations require acknowledge_high_impact=true")
    pending = await _object_manager_migration_snapshot()
    if not pending:
        raise ValueError("There are no queued object manager migrations")
    preview = _object_manager_migration_preview(pending)
    removed = [item for item in preview if item.get("to_delete") is True]
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__object_manager_migrations__", "operation": "execute_migrations",
        "data": {}, "fingerprint": _digest(pending), "before": preview,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    risk = "Executes every currently queued object manager change against the database. Removal migrations permanently drop their custom attribute columns and all values stored in those columns." if removed else "Executes every currently queued object manager change against the database. Review each pending create, conversion, and configuration change before approval."
    return _json({
        "plan_id": plan_id, "resource": "object_manager_attributes", "operation": "execute_migrations",
        "expires_in_seconds": _PLAN_TTL_SECONDS, "snapshot_fingerprint": plan["fingerprint"],
        "risk": risk, "pending_changes": preview, "removed_attributes": removed,
        "approval_required": True,
        "note": "No migration was executed. The plan covers all pending object manager changes and is rejected if that queue changes before apply.",
    })


@mcp.tool()
async def zammad_prepare_object_manager_discard_changes(acknowledge_high_impact: bool = False) -> str:
    """Preview discarding all queued object manager changes without reversing completed migrations."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Discarding object manager changes requires acknowledge_high_impact=true")
    pending = await _object_manager_migration_snapshot()
    if not pending:
        raise ValueError("There are no queued object manager changes to discard")
    preview = _object_manager_migration_preview(pending)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__object_manager_discard_changes__",
        "operation": "discard_changes",
        "data": {},
        "fingerprint": _digest(pending),
        "before": preview,
        "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "object_manager_attributes",
        "operation": "discard_changes",
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "pending_changes": preview,
        "risk": "Discards every currently queued object manager change. New, not-yet-migrated attributes are removed and pending change flags are cleared. Completed migrations are not reversed.",
        "approval_required": True,
        "note": "No changes were discarded. The plan is rejected if the pending object manager queue changes before apply.",
    })


@mcp.tool()
async def zammad_prepare_session_action(
    operation: Literal["delete"],
    session_id: int,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview ending one active Zammad user session; the user will need to sign in again."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if operation != "delete":
        raise ValueError("Sessions support only the delete operation")
    _validate_id(session_id)
    if not acknowledge_high_impact:
        raise ValueError("Ending an active session requires acknowledge_high_impact=true")
    current_snapshot = await _session_snapshot(session_id)
    if current_snapshot is None:
        raise ValueError("session_id must identify an active Zammad session")
    current, preview = current_snapshot
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__session_action__", "operation": operation,
        "object_id": session_id, "data": {}, "fingerprint": _digest(current),
        "before": preview, "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "sessions", "operation": operation,
        "object_id": session_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "The selected user will be signed out and must authenticate again. The session cookie identifier is never returned.",
        "before": plan["before"], "after": {"session_terminated": True},
        "approval_required": True, "note": "No session was ended. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_data_privacy_deletion(
    object_type: Literal["User", "Ticket"],
    object_id: int,
    confirmation: Literal["DELETE"],
    delete_organization: bool = False,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview one asynchronous Zammad user or ticket deletion task; no task is queued until apply."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    object_id = _validate_id(object_id)
    if confirmation != "DELETE":
        raise ValueError('confirmation must be the exact text "DELETE"')
    if not isinstance(delete_organization, bool):
        raise ValueError("delete_organization must be a boolean")
    if delete_organization and object_type != "User":
        raise ValueError("delete_organization is supported only for a user deletion")
    if not acknowledge_high_impact:
        raise ValueError("Data Privacy deletions require acknowledge_high_impact=true")
    snapshot = await _data_privacy_deletion_snapshot(object_type, object_id, delete_organization)
    before = _data_privacy_deletion_preview(object_type, snapshot, delete_organization)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__data_privacy_deletion__", "operation": "delete",
        "object_id": object_id, "object_type": object_type,
        "data": {"delete_organization": delete_organization},
        "fingerprint": _digest(snapshot), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "data_privacy_tasks", "operation": "delete",
        "object_type": object_type, "object_id": object_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS, "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Apply queues an irreversible account or ticket deletion. Zammad processes Data Privacy tasks asynchronously, normally within the next 10-minute job interval; it recalculates its ticket preview when execution begins. A user deletion can also remove a sole-member organization if explicitly selected.",
        "before": before, "after": {"deletion_task_queued": True},
        "approval_required": True,
        "note": "No task was queued. Apply requires separate explicit user approval and acknowledge_high_impact=true. Zammad revalidates system-user, current-user, last-admin, and duplicate-task restrictions when the task is created.",
    })


@mcp.tool()
async def zammad_prepare_oauth_application_token(
    application_id: int,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview issuing a bearer token for the current Zammad user to one OAuth application."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    application_id = _validate_id(application_id)
    if not acknowledge_high_impact:
        raise ValueError("OAuth application token issuance requires acknowledge_high_impact=true")
    application = await _oauth_application_snapshot(application_id)
    preview = project_oauth_application(application)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__oauth_application_token__", "operation": "issue_token",
        "object_id": application_id, "data": {}, "fingerprint": _digest(application),
        "before": preview, "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "oauth_applications", "operation": "issue_token",
        "object_id": application_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"], "before": preview,
        "after": {"bearer_token_issued": True, "resource_owner": "current Zammad user", "token_value_returned": False},
        "risk": "The token grants the selected application access as the current Zammad user. Its bearer credential will be stored in the owner-only local secret store and must be shared with the application operator through a secure channel.",
        "approval_required": True,
        "note": "No token was issued. Apply requires separate explicit user approval and stores the one-time token outside the repository.",
    })


def _package_post_install_commands(inventory: Mapping[str, Any]) -> list[str]:
    commands: list[str] = []
    if inventory.get("package_installation") is True:
        if inventory.get("local_gemfiles") is True:
            commands.extend([
                "zammad config:set BUNDLE_DEPLOYMENT=0",
                "zammad run bundle config set --local deployment false",
                "zammad run bundle install",
            ])
        commands.append("zammad run rake zammad:package:post_install")
    else:
        if inventory.get("local_gemfiles") is True:
            commands.append("bundle install")
        commands.append("rake zammad:package:post_install")
    commands.append("systemctl restart zammad")
    return commands


@mcp.tool()
async def zammad_prepare_package_change(
    operation: Literal["install", "uninstall"],
    package_data: dict[str, Any] | None = None,
    package_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a Zammad package install or removal; install can write executable application code."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Package changes require acknowledge_high_impact=true")

    inventory = await _package_inventory_snapshot()
    if operation == "install":
        if package_id is not None or not isinstance(package_data, dict):
            raise ValueError("install requires package_data and does not accept package_id")
        prepared, package_preview = validate_package_install_payload(package_data)
        existing = [item for item in inventory["packages"] if item.get("name") == package_preview["name"]]
        if any(item.get("version") == package_preview["version"] for item in existing):
            raise ValueError("This package name and version are already present")
        before = inventory
        before_preview: Any = existing
        after_preview = {
            **package_preview,
            "replaces_existing_package": bool(existing),
            "application_code_write": True,
            "requires_follow_up": _package_post_install_commands(inventory),
        }
        data = {"package_data": prepared}
        object_id = None
    else:
        if package_data is not None or package_id is None:
            raise ValueError("uninstall requires package_id and does not accept package_data")
        object_id = _validate_id(package_id)
        matches = [item for item in inventory["packages"] if item.get("id") == object_id]
        if len(matches) != 1:
            raise ValueError("package_id must identify exactly one installed Zammad package")
        selected = matches[0]
        if selected.get("state") not in {"installed", "deactivate"}:
            raise ValueError("Only installed packages can be removed")
        before = inventory
        before_preview = selected
        after_preview = {
            "removed": True,
            "package_name": selected.get("name"),
            "reverse_migrations": True,
            "package_files_removed": True,
            "package_data_rollback_available": False,
            "requires_follow_up": _package_post_install_commands(inventory),
        }
        data = {}

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__package_change__", "operation": operation,
        "object_id": object_id, "data": data,
        "preview_after": after_preview,
        "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    risk = (
        "Installs a trusted package that writes files into the Zammad application and can execute arbitrary code in its context. Follow-up dependency/migration commands and a service restart are required."
        if operation == "install"
        else "Uninstalls a package, reverses its database migrations, and removes its files without a package-data rollback. Follow-up package commands and a service restart are required."
    )
    return _json({
        "plan_id": plan_id, "resource": "packages", "operation": operation,
        "object_id": object_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"], "risk": risk,
        "before": before_preview, "after": after_preview,
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval. Follow-up commands are shown but will not be run by the MCP.",
    })


@mcp.tool()
async def zammad_prepare_ssl_certificate_change(
    operation: Literal["create", "delete"],
    certificate: str | None = None,
    certificate_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview an SSL certificate import or removal without writing to Zammad."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("SSL certificate changes require acknowledge_high_impact=true")

    if operation == "create":
        if certificate_id is not None:
            raise ValueError("certificate import does not accept certificate_id")
        data, after = validate_ssl_certificate_payload({"certificate": certificate})
        before = await _ssl_certificate_snapshot()
        if any(item.get("fingerprint") == after["sha1_fingerprint"] for item in before):
            raise ValueError("This SSL certificate is already present")
        object_id = None
        preview_before = before
        preview_after = after
    else:
        if certificate is not None or certificate_id is None:
            raise ValueError("certificate removal requires certificate_id and does not accept certificate data")
        object_id = _validate_id(certificate_id)
        before = await _ssl_certificate_snapshot(object_id)
        if not isinstance(before, Mapping):
            raise ValueError("certificate_id must identify an existing trusted certificate")
        data = {}
        preview_before = before
        preview_after = None

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__ssl_certificates__", "operation": operation,
        "object_id": object_id, "data": data,
        "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    return _json({
        "plan_id": plan_id, "resource": "ssl_certificates", "operation": operation,
        "object_id": object_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes the certificates trusted by Zammad integrations. Removing a certificate may break TLS connections; Zammad validates certificate suitability when importing.",
        "before": preview_before, "after": preview_after,
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_crypto_material_change(
    resource: Literal["pgp_keys", "smime_certificates", "smime_private_keys"],
    operation: Literal["create", "delete"],
    data: dict[str, Any] | None = None,
    object_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview PGP or S/MIME material changes; secret inputs must use process environment references."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Cryptographic material changes require acknowledge_high_impact=true")
    if operation == "create":
        if object_id is not None or not isinstance(data, dict):
            raise ValueError("create requires data and does not accept object_id")
        if resource == "pgp_keys":
            submitted, _ = validate_pgp_create(data)
            submitted_key = submitted.pop("private_key")
            if isinstance(submitted_key, Mapping):
                materialized, _ = _materialize_secret_values({**submitted, "private_key": submitted_key})
                data = materialized
            else:
                materialized, _ = _materialize_secret_values(submitted)
                data = {**materialized, "private_key": submitted_key}
            validate_pgp_material(data["private_key"])
            key_type = "private" if "-----BEGIN PGP PRIVATE KEY BLOCK-----" in data["private_key"] else "public"
            if "passphrase" in materialized and not isinstance(materialized["passphrase"], str):
                raise ValueError("passphrase must be text")
            preview_after = {
                "domain_alias": data.get("domain_alias"), "key_type": key_type,
                "passphrase_provided": bool(data.get("passphrase")), "key_material_returned": False,
            }
        elif resource == "smime_certificates":
            if set(data) != {"certificate"}:
                raise ValueError("S/MIME certificate creation accepts only certificate PEM text")
            data, preview_after = validate_smime_certificate(data.get("certificate"))
        else:
            submitted, _ = validate_smime_private_key(data)
            materialized, _ = _materialize_secret_values(submitted)
            validate_materialized_private_key(materialized, "private_key")
            if "secret" in materialized and not isinstance(materialized["secret"], str):
                raise ValueError("secret must be text")
            data = materialized
            preview_after = {"private_key_provided": True, "passphrase_provided": bool(data.get("secret")), "key_material_returned": False}
        object_id = None
        raw_before = await _crypto_material_snapshot(resource)
        if resource == "pgp_keys":
            before = project_pgp_collection(raw_before)
        else:
            before = project_smime_collection(raw_before)
    else:
        if data is not None or object_id is None:
            raise ValueError("delete requires object_id and does not accept data")
        object_id = _validate_id(object_id)
        raw_before = await _crypto_material_snapshot(resource, object_id)
        if resource == "pgp_keys":
            before = project_pgp_key(raw_before)
            if not before.get("private_key_configured"):
                raise ValueError("object_id must identify an existing PGP key")
        else:
            before = project_smime_certificate(raw_before)
            has_material = before.get("id") == object_id and (
                resource == "smime_certificates" or before.get("private_key_configured")
            )
            if not has_material:
                raise ValueError("object_id must identify an existing S/MIME certificate or private key")
        data = {}
        preview_after = None

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__crypto_material__", "crypto_resource": resource,
        "operation": operation, "object_id": object_id, "data": data,
        "fingerprint": _crypto_digest(raw_before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": resource, "operation": operation,
        "object_id": object_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes cryptographic material used for message signing, encryption, or decryption. Removing a certificate also removes its paired private key.",
        "before": before, "after": preview_after, "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval; key and passphrase values are withheld from this preview.",
    })


@mcp.tool()
async def zammad_prepare_translation_change(
    operation: Literal["upsert", "reset", "delete"],
    data: dict[str, str] | None = None,
    translation_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a translation change; apply requires a separate explicit approval."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    if not acknowledge_high_impact:
        raise ValueError("Translation changes require acknowledge_high_impact=true")

    if operation == "upsert":
        if translation_id is not None or not isinstance(data, dict) or set(data) != {"locale", "source", "target"}:
            raise ValueError("upsert requires exactly locale, source, and target and does not accept translation_id")
        locale = _validate_translation_locale(data["locale"])
        source = data["source"]
        target = data["target"]
        if not isinstance(source, str) or not source.strip() or not isinstance(target, str) or not target.strip():
            raise ValueError("source and target must be non-empty strings")
        data = {"locale": locale, "source": source, "target": target}
        before = await _translation_upsert_snapshot(locale, source)
        preview_before = before
        preview_after = {
            "id": before.get("id") if isinstance(before, Mapping) else None,
            "locale": locale,
            "source": source,
            "target": target,
            "action": "update existing entry" if isinstance(before, Mapping) else "create or set entry",
        }
    else:
        if data not in (None, {}) or translation_id is None:
            raise ValueError(f"{operation} requires translation_id and does not accept data")
        translation_id = _validate_id(translation_id)
        before = await _get(f"/translations/{translation_id}")
        if not isinstance(before, Mapping):
            raise RuntimeError("Zammad did not return the translation snapshot")
        synchronized = before.get("is_synchronized_from_codebase")
        if operation == "delete" and synchronized is not False:
            raise ValueError("Only custom translations can be deleted")
        if operation == "reset" and synchronized is not True:
            raise ValueError("Only codebase translations can be reset")
        data = {}
        preview_before = {
            key: before.get(key)
            for key in ("id", "locale", "source", "target", "target_initial", "is_synchronized_from_codebase")
            if key in before
        }
        preview_after = (
            {**preview_before, "target": before.get("target_initial")}
            if operation == "reset" else None
        )

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__translation_change__", "operation": operation,
        "object_id": translation_id, "data": data,
        "snapshot_path": None,
        "translation_locale": data.get("locale") if operation == "upsert" else None,
        "translation_source": data.get("source") if operation == "upsert" else None,
        "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    return _json({
        "plan_id": plan_id, "resource": "translations", "operation": operation,
        "object_id": translation_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes user-visible translated text in Zammad for the selected locale.",
        "before": preview_before, "after": preview_after,
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


async def _prepare_knowledge_base_permissions_change(
    knowledge_base_id: int,
    category_id: int | None,
    permissions: dict[str, str],
    acknowledge_high_impact: bool = False,
) -> str:
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    category = _validate_id(category_id) if category_id is not None else None
    permission_path = (
        f"/knowledge_bases/{kb_id}/permissions"
        if category is None
        else f"/knowledge_bases/{kb_id}/categories/{category}/permissions"
    )
    category_path = f"/knowledge_bases/{kb_id}/categories/{category}" if category is not None else None
    category_snapshot: Mapping[str, Any] | None = None
    if category is not None:
        category_value = await _get(category_path)
        if not isinstance(category_value, Mapping):
            raise RuntimeError("Zammad did not return the Knowledge Base category snapshot")
        try:
            snapshot_category_id = _validate_id(category_value.get("id"))
            snapshot_kb_id = _validate_id(category_value.get("knowledge_base_id"))
        except ValueError as exc:
            raise RuntimeError("Zammad returned an invalid Knowledge Base category snapshot") from exc
        if snapshot_category_id != category or snapshot_kb_id != kb_id:
            raise ValueError("category_id does not identify a category in the selected Knowledge Base")
        category_snapshot = category_value
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base access changes require acknowledge_high_impact=true")
    if not isinstance(permissions, dict) or not permissions:
        raise ValueError("permissions must map every eligible role ID to editor, reader, or none")

    normalized: dict[str, str] = {}
    for role_id, access in permissions.items():
        if not isinstance(role_id, str) or not role_id.isdigit() or int(role_id) <= 0:
            raise ValueError("permission keys must be positive role IDs encoded as strings")
        if not isinstance(access, str) or access not in {"editor", "reader", "none"}:
            raise ValueError("permission values must be editor, reader, or none")
        normalized_role_id = str(int(role_id))
        if normalized_role_id in normalized:
            raise ValueError("permission keys must not repeat a role ID")
        normalized[normalized_role_id] = access

    before = await _get(permission_path)
    if not isinstance(before, Mapping):
        raise RuntimeError("Zammad did not return the Knowledge Base permission snapshot")
    roles_editor = before.get("roles_editor")
    roles_reader = before.get("roles_reader")
    if not isinstance(roles_editor, list) or not isinstance(roles_reader, list):
        raise RuntimeError("Zammad did not return eligible Knowledge Base roles")

    role_access: dict[str, tuple[str, str]] = {}
    eligible_roles = [(role, "editor") for role in roles_editor]
    eligible_roles.extend((role, "reader") for role in roles_reader)
    for role, default_access in eligible_roles:
        if not isinstance(role, Mapping) or isinstance(role.get("id"), bool) or not isinstance(role.get("id"), int) or not isinstance(role.get("name"), str):
            raise RuntimeError("Zammad returned an invalid Knowledge Base role")
        role_key = str(role["id"])
        if role_key in role_access:
            raise RuntimeError("Zammad returned a duplicate Knowledge Base role")
        role_access[role_key] = (role["name"], default_access)
    if set(normalized) != set(role_access):
        raise ValueError("permissions must include exactly every role currently eligible for Knowledge Base access")

    effective_items = before.get("permissions")
    if not isinstance(effective_items, list) or any(not isinstance(item, Mapping) for item in effective_items):
        raise RuntimeError("Zammad returned an invalid effective Knowledge Base permission list")
    explicit: dict[str, str] = {}
    for item in effective_items:
        role_id = item.get("role_id")
        access = item.get("access")
        if isinstance(role_id, bool) or not isinstance(role_id, int) or role_id <= 0 or not isinstance(access, str):
            raise RuntimeError("Zammad returned an invalid effective Knowledge Base permission")
        role_key = str(role_id)
        if role_key in explicit:
            raise RuntimeError("Zammad returned duplicate effective Knowledge Base permissions")
        explicit[role_key] = access

    inherited_items = before.get("inherited", []) if category is not None else []
    if not isinstance(inherited_items, list) or any(not isinstance(item, Mapping) for item in inherited_items):
        raise RuntimeError("Zammad returned an invalid inherited Knowledge Base permission list")
    inherited: dict[str, str] = {}
    for item in inherited_items:
        role_id = item.get("role_id")
        access = item.get("access")
        if (
            isinstance(role_id, bool) or not isinstance(role_id, int) or role_id <= 0
            or not isinstance(access, str) or access not in {"editor", "reader", "none"}
        ):
            raise RuntimeError("Zammad returned an invalid inherited Knowledge Base permission")
        role_key = str(role_id)
        if role_key in inherited:
            raise RuntimeError("Zammad returned duplicate inherited Knowledge Base permissions")
        inherited[role_key] = access

    before_access: dict[str, str] = {}
    after_access: dict[str, str] = {}
    for role_id, (name, default_access) in role_access.items():
        current_access = explicit.get(role_id, default_access)
        requested_access = normalized[role_id]
        allowed = {"editor", "reader", "none"} if default_access == "editor" else {"reader", "none"}
        if current_access not in allowed or requested_access not in allowed:
            raise ValueError(f"Role {name!r} has an access level that is invalid for its current permissions")
        parent_access = inherited.get(role_id)
        if category is not None and parent_access in {"editor", "none"} and requested_access != parent_access:
            raise ValueError(f"Role {name!r} must retain {parent_access} access inherited from its parent")
        before_access[role_id] = current_access
        after_access[role_id] = requested_access

    dependencies: list[dict[str, Any]] = []
    affected_descendants: list[int] = []
    if category is not None:
        target_children = category_snapshot.get("child_ids")
        if not isinstance(target_children, list):
            raise RuntimeError("Zammad did not return the selected category's child IDs")
        dependencies.append({"path": category_path, "fingerprint": _digest(category_snapshot)})
        pending = [(child_id, category) for child_id in target_children]
        seen = {category}
        while pending:
            descendant_id, expected_parent_id = pending.pop()
            try:
                descendant_id = _validate_id(descendant_id)
            except ValueError as exc:
                raise RuntimeError("Zammad returned an invalid child category ID") from exc
            if descendant_id in seen:
                raise RuntimeError("Zammad returned a cyclic Knowledge Base category tree")
            seen.add(descendant_id)
            affected_descendants.append(descendant_id)
            descendant_path = f"/knowledge_bases/{kb_id}/categories/{descendant_id}"
            descendant_snapshot = await _get(descendant_path)
            if not isinstance(descendant_snapshot, Mapping):
                raise RuntimeError("Zammad did not return a descendant category snapshot")
            try:
                descendant_snapshot_id = _validate_id(descendant_snapshot.get("id"))
                descendant_kb_id = _validate_id(descendant_snapshot.get("knowledge_base_id"))
                descendant_parent_id = _validate_id(descendant_snapshot.get("parent_id"))
            except ValueError as exc:
                raise RuntimeError("Zammad returned an invalid descendant category relationship") from exc
            if (
                descendant_snapshot_id != descendant_id or descendant_kb_id != kb_id
                or descendant_parent_id != expected_parent_id
            ):
                raise RuntimeError("Zammad returned a descendant outside the selected category tree")
            child_ids = descendant_snapshot.get("child_ids")
            if not isinstance(child_ids, list):
                raise RuntimeError("Zammad did not return descendant category child IDs")
            pending.extend((child_id, descendant_id) for child_id in child_ids)

            descendant_permissions_path = f"{descendant_path}/permissions"
            descendant_permissions = await _get(descendant_permissions_path)
            if not isinstance(descendant_permissions, Mapping):
                raise RuntimeError("Zammad did not return a descendant permission snapshot")
            dependencies.extend((
                {"path": descendant_path, "fingerprint": _digest(descendant_snapshot)},
                {"path": descendant_permissions_path, "fingerprint": _digest(descendant_permissions)},
            ))

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_category_permissions__" if category is not None else "__knowledge_base_permissions__",
        "operation": "update", "object_id": kb_id, "category_id": category,
        "data": {"permissions_dialog": {"permissions": normalized}},
        "snapshot_path": permission_path, "write_path": permission_path, "dependencies": dependencies,
        "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan

    def entries(access_map: Mapping[str, str]) -> list[dict[str, Any]]:
        return [
            {"role_id": int(role_id), "role": role_access[role_id][0], "access": access_map[role_id]}
            for role_id in sorted(role_access, key=int)
        ]

    return _json({
        "plan_id": plan_id,
        "resource": "knowledge_base_category_permissions" if category is not None else "knowledge_base_permissions",
        "operation": "update", "object_id": kb_id, "category_id": category,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes role access to public Knowledge Base content. A category change can also alter inherited access in descendant categories; those descendant records are recalculated by Zammad when the change is applied. Zammad prevents the acting user from removing their own editor access.",
        "before": entries(before_access), "after": entries(after_access),
        "inherited": inherited_items,
        "affected_descendant_category_ids": affected_descendants,
        "approval_required": True,
        "note": "No write was performed. Zammad may clean up inherited permission overrides in the listed descendant categories. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_permissions_change(
    knowledge_base_id: int,
    permissions: dict[str, str],
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a full Knowledge Base role-access change; this tool never writes."""
    return await _prepare_knowledge_base_permissions_change(knowledge_base_id, None, permissions, acknowledge_high_impact)


@mcp.tool()
async def zammad_prepare_knowledge_base_category_permissions_change(
    knowledge_base_id: int,
    category_id: int,
    permissions: dict[str, str],
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a full role-access change for one category; this tool never writes."""
    return await _prepare_knowledge_base_permissions_change(knowledge_base_id, category_id, permissions, acknowledge_high_impact)


@mcp.tool()
async def zammad_get_knowledge_base_record(
    knowledge_base_id: int,
    kind: Literal["answers", "categories"],
    record_id: int,
    translation_id: int | None = None,
) -> str:
    """Read one Knowledge Base answer or full category; answer content is optional by translation ID."""
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(record_id)
    path = f"/knowledge_bases/{kb_id}/{kind}/{item_id}"
    if kind == "categories":
        if translation_id is not None:
            raise ValueError("translation_id can only be used with Knowledge Base answers")
        params = {"full": True}
    else:
        params = {"include_contents": _validate_id(translation_id)} if translation_id is not None else None
    return _json(await _get(path, params))


async def _snapshot(resource: str, operation: str, object_id: int | None) -> Any:
    if resource == "external_credentials" and operation == "verify":
        return await _get(_resource(resource).path)
    if resource in {_SPECIAL_CHANNEL, _EMAIL_ACCOUNT_RESOURCE, "email_channels"}:
        return await _get(_SPECIAL_READ_PATH)
    if resource == "facebook_channels":
        collection = await _get(_resource(resource).path)
        assets = collection.get("assets", {}) if isinstance(collection, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        channel = channel_assets.get(str(_validate_id(object_id))) if isinstance(channel_assets, Mapping) else None
        return {"assets": {"Channel": {str(object_id): channel}}} if isinstance(channel, Mapping) else {"assets": {"Channel": {}}}
    if resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        collection = await _get(_resource(resource).path)
        assets = collection.get("assets", {}) if isinstance(collection, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        channel = channel_assets.get(str(_validate_id(object_id))) if isinstance(channel_assets, Mapping) else None
        email_assets = assets.get("EmailAddress", {}) if isinstance(assets, Mapping) else {}
        related_addresses = {
            str(address_id): address
            for address_id, address in email_assets.items()
            if isinstance(address, Mapping) and str(address.get("channel_id")) == str(object_id)
        } if isinstance(email_assets, Mapping) else {}
        return {"assets": {"Channel": {str(object_id): channel}, "EmailAddress": related_addresses}} if isinstance(channel, Mapping) else {"assets": {"Channel": {}}}
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        return await _get(_resource(resource).path)
    if resource == "__knowledge_base_settings__":
        return await _get(f"/knowledge_bases/{_validate_id(object_id)}")
    if resource == "oauth_applications":
        if operation == "create":
            return await _get("/applications", {"full": True})
        return await _oauth_application_snapshot(_validate_id(object_id))
    if resource == "time_accounting_types" and operation != "create":
        return await _time_accounting_type_snapshot(_validate_id(object_id))
    spec = _resource(resource)
    if operation == "create":
        return await _get(spec.path)
    if resource == "ai_agents":
        return project_agent_snapshot(
            await _get(f"{spec.path}/{_validate_id(object_id)}", {"full": True})
        )
    return await _get(f"{spec.path}/{_validate_id(object_id)}")


async def _time_accounting_type_snapshot(type_id: int | None = None) -> Any:
    rows: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        batch = await _get(_resource("time_accounting_types").path, {"page": page, "per_page": 100})
        if not isinstance(batch, list) or any(not isinstance(item, Mapping) for item in batch):
            raise RuntimeError("Zammad did not return activity types")
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise RuntimeError("Activity type inventory exceeds the supported snapshot size")
    if type_id is None:
        return rows
    matches = [item for item in rows if item.get("id") == type_id]
    if len(matches) > 1:
        raise RuntimeError("Zammad returned duplicate activity type IDs")
    return matches[0] if matches else None


async def _ldap_sources_snapshot() -> list[Mapping[str, Any]]:
    sources: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        rows = await _get("/ldap_sources", {"page": page, "per_page": 100})
        if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
            raise RuntimeError("Zammad did not return an LDAP source list")
        sources.extend(rows)
        if len(rows) < 100:
            return sources
    raise RuntimeError("LDAP source inventory exceeds the supported snapshot size")


async def _ldap_integration_setting_snapshot() -> Mapping[str, Any]:
    settings = await _get("/settings")
    if not isinstance(settings, list):
        raise RuntimeError("Zammad did not return the settings list")
    candidates = [item for item in settings if isinstance(item, Mapping) and item.get("name") == "ldap_integration"]
    if len(candidates) != 1:
        raise RuntimeError("The LDAP integration setting is missing or ambiguous")
    setting_id = _validate_id(candidates[0].get("id"))
    setting = await _get(f"/settings/{setting_id}")
    if not isinstance(setting, Mapping) or setting.get("name") != "ldap_integration":
        raise RuntimeError("Zammad did not return the LDAP integration setting")
    state = setting.get("state_current")
    if not isinstance(state, Mapping) or state.get("value") is not True:
        raise ValueError("LDAP integration must be enabled before starting a sync")
    return setting


async def _setting_snapshot_by_name(name: str) -> Mapping[str, Any]:
    settings = await _get("/settings")
    if not isinstance(settings, list):
        raise RuntimeError("Zammad did not return the settings list")
    candidates = [item for item in settings if isinstance(item, Mapping) and item.get("name") == name]
    if len(candidates) != 1:
        raise RuntimeError(f"The {name} setting is missing or ambiguous")
    setting_id = _validate_id(candidates[0].get("id"))
    setting = await _get(f"/settings/{setting_id}")
    if not isinstance(setting, Mapping) or setting.get("name") != name:
        raise RuntimeError(f"Zammad did not return the {name} setting")
    return setting


async def _exchange_import_snapshot() -> dict[str, Any]:
    config_setting = await _setting_snapshot_by_name("exchange_config")
    integration_setting = await _setting_snapshot_by_name("exchange_integration")
    exchange_index = await _get(_EXCHANGE_INTEGRATION_INDEX_PATH)
    config_state = config_setting.get("state_current")
    integration_state = integration_setting.get("state_current")
    config = config_state.get("value") if isinstance(config_state, Mapping) else None
    enabled = integration_state.get("value") if isinstance(integration_state, Mapping) else None
    oauth = exchange_index.get("oauth") if isinstance(exchange_index, Mapping) else None
    if not isinstance(config, Mapping):
        raise ValueError("Exchange connection settings are not configured")
    if not isinstance(enabled, bool):
        raise RuntimeError("Zammad returned an invalid Exchange integration setting")
    if oauth is None:
        oauth = {}
    if not isinstance(oauth, Mapping):
        raise RuntimeError("Zammad returned invalid Exchange OAuth state")
    return {"config": dict(config), "enabled": enabled, "oauth": dict(oauth)}


async def _exchange_oauth_snapshot() -> dict[str, Any]:
    response = await _get(_EXCHANGE_INTEGRATION_INDEX_PATH)
    oauth = response.get("oauth") if isinstance(response, Mapping) else None
    if oauth is None:
        return {}
    if not isinstance(oauth, Mapping):
        raise RuntimeError("Zammad returned invalid Exchange OAuth state")
    return dict(oauth)


async def _exchange_import_pending(action: str) -> bool:
    path = _EXCHANGE_IMPORT_DRY_RUN_PATH if action == "dry_run" else _EXCHANGE_IMPORT_START_PATH
    params = {"finished": "false"} if action == "dry_run" else None
    job = await _get(path, params)
    return project_exchange_import_status(job, action)["status"] in {"queued", "running"}


async def _ldap_import_pending(action: str) -> bool:
    if action == "dry_run":
        job = await _get("/integration/ldap/job_try", {"finished": "false"})
    else:
        job = await _get("/integration/ldap/job_start")
    return isinstance(job, Mapping) and bool(job) and job.get("finished_at") is None


def _ldap_import_status_summary(job: Any, action: str) -> dict[str, Any]:
    if not isinstance(job, Mapping) or not job:
        return {"action": action, "status": "not_found"}
    result = job.get("result") if isinstance(job.get("result"), Mapping) else {}
    counts = {
        key: result[key]
        for key in ("sum", "total", "created", "updated", "unchanged", "skipped", "failed", "deactivated")
        if isinstance(result.get(key), int) and not isinstance(result.get(key), bool) and result[key] >= 0
    }
    finished = bool(job.get("finished_at"))
    status = "failed" if result.get("error") else "finished" if finished else "running" if job.get("started_at") else "queued"
    return {
        "action": action,
        "status": status,
        "job_id": job.get("id") if isinstance(job.get("id"), int) else None,
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "counts": counts,
        "has_error_detail": bool(result.get("error")),
        "has_info_detail": bool(result.get("info")),
    }


@mcp.tool()
async def zammad_prepare_knowledge_base_translation_change(
    knowledge_base_id: int,
    kb_locale_id: int,
    data: dict[str, Any],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a Knowledge Base title or footer update for one locale."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    locale_id = _validate_id(kb_locale_id)
    updates = validate_knowledge_base_translation_update(data)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base translation changes require acknowledge_high_impact=true")
    before = await _knowledge_base_translation_snapshot(kb_id, locale_id)
    after = preview_knowledge_base_translation_after(before, updates)
    if after["title"] == before["translation"]["title"] and after["footer_note"] == before["translation"]["footer_note"]:
        raise ValueError("Knowledge Base translation already matches the requested values")
    request_data = {
        "translations_attributes": [{"id": before["translation"]["id"], **updates}]
    }
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_translation__", "operation": "update",
        "object_id": kb_id, "kb_locale_id": locale_id, "data": request_data,
        "fingerprint": _digest(before), "before": before,
        "updated_fields": sorted(updates), "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "knowledge_base_translations",
        "operation": "update",
        "knowledge_base_id": kb_id,
        "kb_locale_id": locale_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "before": before,
        "after": after,
        "risk": "Changes the Knowledge Base title or footer displayed to users in the selected locale.",
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_feed_token_change(
    knowledge_base_id: int,
    action: Literal["ensure", "rotate"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Stage creation/retrieval or rotation of a private Knowledge Base feed token."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    if action not in {"ensure", "rotate"}:
        raise ValueError("Knowledge Base feed token action must be ensure or rotate")
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base feed token changes require acknowledge_high_impact=true")
    before = await _get(f"/knowledge_bases/{kb_id}")
    if not isinstance(before, Mapping) or before.get("id") != kb_id:
        raise RuntimeError("Zammad did not return the requested Knowledge Base")
    before_preview = {
        "knowledge_base_id": kb_id,
        "active": before.get("active") if isinstance(before.get("active"), bool) else None,
        "private_feed_token_action": action,
    }
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_feed_token__", "operation": action,
        "object_id": kb_id, "data": {}, "fingerprint": _digest(before),
        "snapshot_path": f"/knowledge_bases/{kb_id}", "before": before,
        "preview_before": before_preview, "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    impact = (
        "May create a persistent private-feed token if none exists; the token will only be saved in the protected local token store."
        if action == "ensure"
        else "Invalidates the current private-feed token and its existing feed URLs; the replacement will only be saved in the protected local token store."
    )
    return _json({
        "plan_id": plan_id,
        "resource": "knowledge_base_feed_tokens",
        "operation": action,
        "knowledge_base_id": kb_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "before": before_preview,
        "after": {"token_value_returned": False, "stored_in_protected_local_store": True},
        "risk": impact,
        "approval_required": True,
        "note": "No token request was sent. Apply only after explicit approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_settings_change(
    knowledge_base_id: int,
    data: dict[str, Any],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a Knowledge Base settings update without writing it."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    allowed_fields = {
        "iconset", "color_highlight", "color_header", "color_header_link",
        "homepage_layout", "category_layout", "active", "show_feed_icon", "custom_address",
    }
    if not isinstance(data, dict) or not data:
        raise ValueError("data must be a non-empty JSON object")
    unknown = sorted(set(data) - allowed_fields)
    if unknown:
        raise ValueError(f"Unsupported Knowledge Base settings fields: {', '.join(unknown)}")
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base changes require acknowledge_high_impact=true")

    before = await _get(f"/knowledge_bases/{kb_id}")
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_settings__", "operation": "update", "object_id": kb_id,
        "data": data, "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda k: _PLANS[k]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_settings", "operation": "update",
        "object_id": kb_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes Knowledge Base settings and public presentation.",
        "before": before, "after": _merge_preview(before, data), "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_lifecycle_change(
    knowledge_base_id: int,
    action: Literal["activate", "deactivate"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an explicitly approved Knowledge Base activation change."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base lifecycle changes require acknowledge_high_impact=true")
    before = await _get(f"/knowledge_bases/{kb_id}")
    if not isinstance(before, Mapping) or before.get("id") != kb_id or not isinstance(before.get("active"), bool):
        raise RuntimeError("Zammad did not return a valid Knowledge Base lifecycle snapshot")
    desired_active = action == "activate"
    if before["active"] == desired_active:
        raise ValueError(f"Knowledge Base is already {'active' if desired_active else 'inactive'}")
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_lifecycle__", "operation": action,
        "object_id": kb_id, "data": {"active": desired_active},
        "snapshot_path": f"/knowledge_bases/{kb_id}", "fingerprint": _digest(before),
        "before": before, "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_lifecycle", "operation": action,
        "object_id": kb_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes whether this Knowledge Base is publicly available.",
        "before": {"id": kb_id, "active": before["active"]},
        "after": {"id": kb_id, "active": desired_active},
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_creation(
    system_locale_id: int,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare creation of an active Knowledge Base in one primary locale."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    data = knowledge_base_create_payload(system_locale_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base creation requires acknowledge_high_impact=true")

    inventory = project_knowledge_base_inventory(await _request("POST", "/knowledge_bases/init", {}))
    organization = await _setting_snapshot_by_name("organization")
    product_name = await _setting_snapshot_by_name("product_name")

    def setting_value(snapshot: Mapping[str, Any]) -> str:
        state = snapshot.get("state_current")
        value = state.get("value") if isinstance(state, Mapping) else None
        return value if isinstance(value, str) else ""

    title_base = setting_value(organization).strip() or setting_value(product_name).strip() or "Zammad"
    title = f"{title_base} Knowledge Base"
    footer_note = f"© {title_base}"
    dependencies = [
        {"path": f"/settings/{_validate_id(setting['id'])}", "fingerprint": _digest(setting)}
        for setting in (organization, product_name)
    ]
    before_ids = [item["id"] for item in inventory["knowledge_bases"]]
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_create__", "operation": "create",
        "object_id": None, "data": data,
        "fingerprint": _digest(inventory), "before_ids": before_ids,
        "dependencies": dependencies, "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
        "preview_after": {
            "active": True,
            "system_locale_id": system_locale_id,
            "primary_locale": True,
            "default_title": title,
            "default_footer_note": footer_note,
            "category_count": 0,
            "answer_count": 0,
        },
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id,
        "resource": "knowledge_base_manager",
        "operation": "create",
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "before": {"knowledge_base_ids": before_ids},
        "after": plan["preview_after"],
        "risk": "Creates an active, initially empty Knowledge Base and a primary locale. Zammad will make it visible according to its current Knowledge Base access settings.",
        "write_effects": [
            "Create one Knowledge Base with Zammad's configured default title and style values",
            "Create the selected System Locale as its primary locale",
        ],
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_deletion(
    knowledge_base_id: int,
    confirmation_phrase: str,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare permanent deletion of a Knowledge Base, its content, and attached files."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    if confirmation_phrase != f"DELETE KNOWLEDGE BASE {kb_id}":
        raise ValueError(f"confirmation_phrase must exactly equal DELETE KNOWLEDGE BASE {kb_id}")
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base deletion requires acknowledge_high_impact=true")
    before = await _knowledge_base_deletion_snapshot(kb_id)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_deletion__", "operation": "delete",
        "object_id": kb_id, "before": before, "fingerprint": _digest(before),
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    preview = preview_knowledge_base_deletion(before, kb_id)
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_manager", "operation": "delete",
        "knowledge_base_id": kb_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Irreversibly deletes the Knowledge Base, all categories and answers, translations, locales, menus, role permissions, and attached files.",
        "before": preview, "after": {"deleted": True, "knowledge_base_id": kb_id},
        "approval_required": True,
        "note": "No write was performed. The stale check is immediately before DELETE but is not atomic with changes made directly in Zammad. Zammad's file storage may delete file bytes outside the database transaction; there is no MCP rollback.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_menu_change(
    knowledge_base_id: int,
    location: Literal["header", "footer"],
    menu_items_sets: list[dict[str, Any]],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a complete public Knowledge Base menu update for every locale."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    if not acknowledge_high_impact:
        raise ValueError("Public Knowledge Base menu changes require acknowledge_high_impact=true")
    before = await _knowledge_base_menu_snapshot(kb_id, location)
    normalized = validate_knowledge_base_menu_update(menu_items_sets, before)
    after = preview_knowledge_base_menu_after(before, normalized)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_menu__", "operation": "update",
        "object_id": kb_id, "location": location,
        "data": {"menu_items_sets": normalized}, "before": before,
        "fingerprint": _digest(before), "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_menu_items", "operation": "update",
        "object_id": kb_id, "location": location,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes public navigation links and their order for every Knowledge Base locale.",
        "before": before, "after": after, "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_order_change(
    knowledge_base_id: int,
    kind: Literal["root_categories", "categories", "answers"],
    ordered_ids: list[int],
    category_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a complete Knowledge Base sibling reorder without writing."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    parent_id = _validate_id(category_id) if category_id is not None else None
    if kind == "root_categories" and parent_id is not None:
        raise ValueError("root_categories does not accept category_id")
    if kind != "root_categories" and parent_id is None:
        raise ValueError("category_id is required for child category and answer ordering")
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base ordering changes require acknowledge_high_impact=true")
    before = await _knowledge_base_order_snapshot(kb_id, kind, parent_id)
    normalized = validate_knowledge_base_order(ordered_ids, before)
    after = preview_knowledge_base_order_after(before, normalized)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_order__", "operation": "reorder",
        "object_id": parent_id, "parent_id": kb_id, "kind": kind,
        "write_path": _knowledge_base_order_path(kb_id, kind, parent_id),
        "data": {"ordered_ids": normalized}, "before": before,
        "fingerprint": _digest(before), "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_ordering", "operation": "reorder",
        "knowledge_base_id": kb_id, "category_id": parent_id, "kind": kind,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes the public order of every sibling in the selected category or answer collection.",
        "before": before, "after": after, "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_attachment_upload(
    knowledge_base_id: int,
    answer_id: int,
    filename: str,
    content_type: str,
    content_base64: str,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare an attachment upload of at most 10 MiB to a Knowledge Base answer."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(answer_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base attachment uploads require acknowledge_high_impact=true")
    data, after = validate_knowledge_base_attachment_upload(filename, content_type, content_base64)
    before = await _knowledge_base_attachments_snapshot(kb_id, item_id)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_attachment_upload__", "operation": "create",
        "object_id": item_id, "parent_id": kb_id, "data": data, "before": before,
        "fingerprint": _digest(before), "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        active_uploads = sum(
            pending.get("resource") == "__knowledge_base_attachment_upload__"
            for pending in _PLANS.values()
        )
        if active_uploads >= _MAX_KNOWLEDGE_BASE_ATTACHMENT_UPLOAD_PLANS:
            raise ValueError("Too many pending Knowledge Base attachment uploads; apply or let an existing plan expire")
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_attachments", "operation": "upload",
        "knowledge_base_id": kb_id, "answer_id": item_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Adds a file to a Knowledge Base answer; file contents are sent to Zammad only when this plan is applied.",
        "before": before, "after": after, "approval_required": True,
        "note": "No write was performed. File contents are omitted from the preview and held only by the short-lived plan until it expires or is used.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_attachment_delete(
    knowledge_base_id: int,
    answer_id: int,
    attachment_id: int,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare deletion of one file from a Knowledge Base answer."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(answer_id)
    file_id = _validate_id(attachment_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base attachment deletion requires acknowledge_high_impact=true")
    before = await _knowledge_base_attachments_snapshot(kb_id, item_id)
    selected = next((item for item in before["attachments"] if item["id"] == file_id), None)
    if selected is None:
        raise ValueError("attachment_id must identify a file attached to this answer")
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_attachment_delete__", "operation": "delete",
        "object_id": file_id, "parent_id": kb_id, "answer_id": item_id,
        "before": before, "selected": selected, "expires_at": now + _PLAN_TTL_SECONDS,
        "fingerprint": _digest(before), "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_attachments", "operation": "delete",
        "knowledge_base_id": kb_id, "answer_id": item_id, "attachment": selected,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Permanently removes this file from the selected Knowledge Base answer.",
        "before": before, "after": {**before, "attachments": [item for item in before["attachments"] if item["id"] != file_id]},
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_publication_transition(
    knowledge_base_id: int,
    answer_id: int,
    action: Literal["internal", "publish", "archive", "unarchive"],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare one Zammad-supported Knowledge Base answer visibility transition."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(answer_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base publication transitions require acknowledge_high_impact=true")
    before = await _knowledge_base_publication_snapshot(kb_id, item_id)
    state_before = knowledge_base_publication_state(before)
    state_after = validate_knowledge_base_publication_transition(before, action)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_publication_transition__", "operation": action,
        "object_id": item_id, "parent_id": kb_id, "before": before,
        "state_before": state_before, "state_after": state_after,
        "fingerprint": _digest(before), "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_publication", "operation": action,
        "knowledge_base_id": kb_id, "answer_id": item_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes internal or public article visibility; Zammad recalculates the active-public-Knowledge-Base setting and scheduled touches.",
        "before": {**before, "state": state_before},
        "after": {"state": state_after, "action": action},
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_publication_schedule(
    knowledge_base_id: int,
    answer_id: int,
    updates: dict[str, str | None],
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare timestamp or timer changes for internal, public, and archived visibility."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    item_id = _validate_id(answer_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base publication scheduling requires acknowledge_high_impact=true")
    before = await _knowledge_base_publication_snapshot(kb_id, item_id)
    normalized, after = validate_knowledge_base_schedule_updates(updates, before)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    state_before = knowledge_base_publication_state(before)
    state_after = knowledge_base_publication_state(after)
    plan = {
        "resource": "__knowledge_base_publication_schedule__", "operation": "schedule",
        "object_id": item_id, "parent_id": kb_id, "data": normalized,
        "before": before, "state_before": state_before,
        "fingerprint": _digest(before), "expires_at": now + _PLAN_TTL_SECONDS,
        "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda key: _PLANS[key]["expires_at"]), None)
        _PLANS[plan_id] = plan
    return _json({
        "plan_id": plan_id, "resource": "knowledge_base_publication", "operation": "schedule",
        "knowledge_base_id": kb_id, "answer_id": item_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes scheduled article visibility and may alter public access; Zammad updates actor references, scheduled touches, and the active-public-Knowledge-Base setting.",
        "before": {**before, "state": state_before},
        "after": {**after, "state": state_after},
        "write_payload": normalized,
        "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


@mcp.tool()
async def zammad_prepare_knowledge_base_record_change(
    knowledge_base_id: int,
    kind: Literal["answers", "categories"],
    operation: Literal["create", "update", "delete"],
    data: dict[str, Any] | None = None,
    record_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Prepare a Knowledge Base answer/category change; no write happens until apply."""
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())
    kb_id = _validate_id(knowledge_base_id)
    if not acknowledge_high_impact:
        raise ValueError("Knowledge Base content changes require acknowledge_high_impact=true")
    if operation in {"create", "update"} and (not isinstance(data, dict) or not data):
        raise ValueError("create and update require a non-empty JSON object in data")
    if operation == "delete" and data:
        raise ValueError("delete does not accept data")
    if operation == "create" and record_id is not None:
        raise ValueError("create does not accept record_id")
    if operation in {"update", "delete"}:
        record_id = _validate_id(record_id)

    collection_path = f"/knowledge_bases/{kb_id}/{kind}"
    if operation == "create":
        snapshot_path = f"/knowledge_bases/{kb_id}"
        write_path = collection_path
        method = "POST"
    else:
        snapshot_path = f"{collection_path}/{record_id}"
        write_path = snapshot_path
        method = "PATCH" if operation == "update" else "DELETE"
    before = await _get(snapshot_path)
    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": "__knowledge_base_record__", "operation": operation,
        "object_id": record_id, "parent_id": kb_id, "kind": kind, "data": data,
        "snapshot_path": snapshot_path, "write_path": write_path, "write_method": method,
        "fingerprint": _digest(before), "before": before,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": True,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            _PLANS.pop(min(_PLANS, key=lambda k: _PLANS[k]["expires_at"]), None)
        _PLANS[plan_id] = plan
    after = data if operation == "create" else (_merge_preview(before, data or {}) if operation == "update" else None)
    return _json({
        "plan_id": plan_id, "resource": f"knowledge_base_{kind}", "operation": operation,
        "parent_id": kb_id, "object_id": record_id, "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": "Changes or deletes customer-facing Knowledge Base content.",
        "before": before, "after": after, "approval_required": True,
        "note": "No write was performed. Apply only after explicit user approval.",
    })


def _merge_preview(before: Any, patch: Mapping[str, Any]) -> Any:
    merged = dict(before) if isinstance(before, Mapping) else {}
    merged.update(patch)
    return merged


def _project_email_channels(value: Any) -> dict[str, Any]:
    """Expose email configuration while omitting linked people and diagnostic logs."""
    if not isinstance(value, Mapping):
        return {}
    assets = value.get("assets", {})
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    address_assets = assets.get("EmailAddress", {}) if isinstance(assets, Mapping) else {}
    channel_fields = {
        "id", "name", "area", "active", "group_id", "options", "preferences",
        "status_in", "status_out", "created_at", "updated_at",
    }
    address_fields = {
        "id", "email", "realname", "name", "channel_id", "active", "group_id",
        "preferences", "created_at", "updated_at",
    }

    def select(source: Any, fields: set[str]) -> dict[str, Any]:
        if not isinstance(source, Mapping):
            return {}
        return {
            str(key): {field: item[field] for field in fields if field in item}
            for key, item in source.items() if isinstance(item, Mapping)
        }

    fixed = value.get("accounts_fixed", [])
    return {
        "account_channel_ids": value.get("account_channel_ids", []),
        "notification_channel_ids": value.get("notification_channel_ids", []),
        "email_address_ids": value.get("email_address_ids", []),
        "not_used_email_address_ids": value.get("not_used_email_address_ids", []),
        "accounts_fixed": [
            {field: item[field] for field in address_fields if field in item}
            for item in fixed if isinstance(item, Mapping)
        ] if isinstance(fixed, list) else [],
        "assets": {
            "Channel": {
                channel_id: channel for channel_id, channel in select(channel_assets, channel_fields).items()
                if channel.get("area") in {"Email::Account", "Email::Notification"}
            },
            "EmailAddress": select(address_assets, address_fields),
        },
        "channel_driver": value.get("channel_driver", {}),
        "config": value.get("config", {}),
    }


def _project_messaging_channels(value: Any) -> dict[str, Any]:
    """Return non-email channel configuration without linked person assets or diagnostic logs."""
    projected = _project_email_channels(value)
    assets = value.get("assets", {}) if isinstance(value, Mapping) else {}
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    fields = {
        "id", "name", "area", "active", "group_id", "options", "preferences",
        "status_in", "status_out", "created_at", "updated_at",
    }

    def safe_value(item: Any, key: str | None = None) -> Any:
        if key == "callback_url":
            return "[REDACTED]" if item not in (None, "", False) else item
        if key == "gateway" and isinstance(item, str):
            parsed = urlsplit(item)
            hostname = parsed.hostname or ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = f"[{hostname}]"
            netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
            return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
        if isinstance(item, Mapping):
            return {str(nested_key): safe_value(nested_value, str(nested_key)) for nested_key, nested_value in item.items()}
        if isinstance(item, list):
            return [safe_value(nested) for nested in item]
        return item

    channels = {
        str(channel_id): {
            field: safe_value(item[field], field) if field == "options" else item[field]
            for field in fields if field in item
        }
        for channel_id, item in channel_assets.items()
        if isinstance(item, Mapping) and item.get("area") not in {"Email::Account", "Email::Notification"}
    } if isinstance(channel_assets, Mapping) else {}
    return {"channel_ids": sorted(channels, key=lambda item: int(item) if item.isdigit() else float("inf")), "channels": channels}


def _email_account_preview(before: Any, data: Mapping[str, Any]) -> dict[str, Any]:
    channel_id = data.get("channel_id")
    projected = _project_email_channels(before)
    assets = projected.get("assets", {})
    channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
    current = None
    if channel_id is not None and isinstance(channel_assets, Mapping):
        current = channel_assets.get(str(channel_id), channel_assets.get(channel_id))
    summary = {
        "account_channel_ids": projected.get("account_channel_ids", []),
        "notification_channel_ids": projected.get("notification_channel_ids", []),
        "current_channel": current,
    }
    return {"before": summary, "after": dict(data)}


def _validate_email_account_payload(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError("email_account configure requires a JSON object")
    required = {"inbound", "outbound", "group_id"}
    allowed = required | {"channel_id", "email", "meta", "group_email_address", "group_email_address_id", "subject"}
    if not required.issubset(data) or set(data) - allowed:
        raise ValueError("email_account requires inbound, outbound, and group_id; only documented channel fields are accepted")
    _validate_id(data["group_id"])
    if data.get("channel_id") is not None:
        _validate_id(data["channel_id"])
    for direction in ("inbound", "outbound"):
        config = data[direction]
        if not isinstance(config, dict) or set(config) != {"adapter", "options"}:
            raise ValueError(f"{direction} must contain exactly adapter and options")
        if not isinstance(config.get("adapter"), str) or not config["adapter"].strip():
            raise ValueError(f"{direction}.adapter must be a non-empty string")
        if not isinstance(config.get("options"), dict):
            raise ValueError(f"{direction}.options must be a JSON object")
    meta = data.get("meta")
    if not isinstance(meta, dict) or not isinstance(meta.get("email"), str) or not isinstance(meta.get("realname"), str):
        raise ValueError("meta must include email and realname strings")
    if data.get("email", meta["email"]) != meta["email"]:
        raise ValueError("email and meta.email must match")
    if data.get("group_email_address") is not None and not isinstance(data["group_email_address"], bool):
        raise ValueError("group_email_address must be a boolean")
    if data.get("group_email_address_id") is not None:
        _validate_id(data["group_email_address_id"])
    if data.get("subject") is not None and not isinstance(data["subject"], str):
        raise ValueError("subject must be a string")


def _expire_plans(now: float) -> None:
    for key in [k for k, v in _PLANS.items() if v["expires_at"] <= now]:
        _PLANS.pop(key, None)


async def _clean_expired_plans() -> None:
    while True:
        await asyncio.sleep(30)
        async with _PLAN_LOCK:
            _expire_plans(time.time())


@mcp.tool()
async def zammad_prepare_admin_change(
    resource: str,
    operation: Literal["create", "update", "delete", "configure", "enable", "disable", "reassign", "test", "preload", "rollback_migration", "reset", "verify"],
    data: dict[str, Any] | None = None,
    object_id: int | None = None,
    acknowledge_high_impact: bool = False,
) -> str:
    """Preview a Zammad admin change. This tool never writes to Zammad.

    After showing the preview, obtain explicit user approval in conversation before calling
    zammad_apply_admin_change. The MCP host must not treat the plan identifier as approval.
    Secret values must be supplied by a process environment reference, for example
    {"$secret_env": "ZAMMAD_SECRET_IMAP_PASSWORD"}; inline secret literals are rejected.
    email_account configure plans send a test message and start mailbox polling when applied.
    """
    global _PLAN_CLEANER
    if _PLAN_CLEANER is None or _PLAN_CLEANER.done():
        _PLAN_CLEANER = asyncio.create_task(_clean_expired_plans())

    if resource == "translations":
        raise ValueError("Use zammad_prepare_translation_change for translation writes")
    if resource == "ssl_certificates":
        raise ValueError("Use zammad_prepare_ssl_certificate_change for certificate writes")
    if resource == "monitoring":
        raise ValueError("Use zammad_prepare_monitoring_action for monitoring changes")
    if resource == "packages":
        raise ValueError("Use zammad_prepare_package_change for package changes")
    if resource == "sessions":
        raise ValueError("Use zammad_prepare_session_action to end a session")
    if resource == _SPECIAL_CHANNEL:
        if operation != "configure":
            raise ValueError("email_notification supports only the configure operation")
        if not isinstance(data, dict) or not {"adapter", "options"}.issubset(data):
            raise ValueError("email_notification requires adapter and options")
        spec = Resource(_SPECIAL_PATH, frozenset({"configure"}), "Sends a real test email and saves the active notification configuration.", True, False)
    elif resource == _EMAIL_ACCOUNT_RESOURCE:
        if operation != "configure":
            raise ValueError("email_account supports only the configure operation")
        if object_id is not None:
            raise ValueError("email_account uses channel_id inside data and does not accept object_id")
        _validate_email_account_payload(data)
        spec = Resource(
            _EMAIL_ACCOUNT_VERIFY_PATH,
            frozenset({"configure"}),
            "Verifies inbound/outbound mail, sends a test message, saves the mailbox, and starts mail fetching.",
            True,
            False,
        )
    elif resource == "email_channels":
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError("email_channels supports enable, disable, delete, or reassign")
        object_id = _validate_id(object_id)
        if operation == "reassign":
            if not isinstance(data, dict) or set(data) != {"group_id"}:
                raise ValueError("reassign requires exactly a group_id field")
            _validate_id(data["group_id"])
        elif data:
            raise ValueError(f"{operation} does not accept data")
    elif resource == "facebook_channels":
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError("facebook_channels supports update, enable, disable, or delete")
        object_id = _validate_id(object_id)
        if operation == "update":
            validate_facebook_channel_payload(data)
        elif data:
            raise ValueError(f"{operation} does not accept data")
    elif resource == "product_logo":
        spec = _resource(resource)
        if operation != "update":
            raise ValueError("product_logo supports only update")
        object_id = _validate_id(object_id)
        if not isinstance(data, dict) or not data:
            raise ValueError("product_logo update requires image data")
    elif resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError(f"{resource} supports delete, enable, disable, reassign, configure, probe, or migration rollback")
        object_id = _validate_id(object_id)
        if operation == "reassign":
            data = {"group_id": validate_oauth_email_group_payload(data)}
        elif operation == "configure":
            data = validate_oauth_email_configure_payload(resource, data)
        elif operation == "probe":
            data = validate_oauth_email_probe_payload(resource, data)
        elif operation == "rollback_migration" and data:
            raise ValueError("rollback_migration does not accept data")
        elif data:
            raise ValueError(f"{operation} does not accept data")
    elif resource in _MESSAGE_CHANNEL_RESOURCES:
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError(f"Operation {operation!r} is not allowed for resource {resource!r}")
        if operation in {"create", "test", "preload"}:
            if object_id is not None:
                raise ValueError(f"{operation} does not accept object_id")
            if not isinstance(data, dict) or not data:
                raise ValueError(f"{operation} requires a non-empty JSON object in data")
        else:
            object_id = _validate_id(object_id)
            if operation == "update" and (not isinstance(data, dict) or not data):
                raise ValueError("update requires a non-empty JSON object in data")
            if operation != "update" and data:
                raise ValueError(f"{operation} does not accept data")
    else:
        spec = _resource(resource)
        if operation not in spec.operations:
            raise ValueError(f"Operation {operation!r} is not allowed for resource {resource!r}")
        if operation == "configure":
            raise ValueError("configure is only valid for email_notification")
        if resource == "settings" and operation == "reset":
            if data not in (None, {}):
                raise ValueError("settings reset does not accept data")
            data = {}
            object_id = _validate_id(object_id)
        if operation in {"create", "update"} and (not isinstance(data, dict) or not data):
            raise ValueError("create and update require a non-empty JSON object in data")
        if resource == "time_accounting_types" and operation in {"create", "update"}:
            data = validate_time_accounting_type_payload(operation, data)
        if resource == "settings" and operation == "update":
            if set(data) != {"name", "state_current"} or not isinstance(data.get("name"), str):
                raise ValueError("settings updates require exactly name and state_current fields")
            state_current = data.get("state_current")
            if not isinstance(state_current, dict) or set(state_current) != {"value"}:
                raise ValueError("settings state_current must contain exactly one value field")
            setting_value = state_current["value"]
            if data["name"] in {"auth_google_oauth2", "auth_saml", "auth_openid_connect", "auth_sso"} and not isinstance(setting_value, bool):
                raise ValueError(f"{data['name']} value must be a boolean")
            if data["name"] == "auth_sso_trusted_ips" and not isinstance(setting_value, str):
                raise ValueError("auth_sso_trusted_ips value must be a comma-separated IP/CIDR string")
            if data["name"] == "auth_sso_trusted_ips":
                _validate_sso_trusted_ip_ranges(setting_value)
            if not is_auth_credential_setting(data.get("name")):
                _validate_setting_secret_reference(data)
        if operation == "delete" and data:
            raise ValueError("delete does not accept data")
        if operation == "create" and object_id is not None:
            raise ValueError("create does not accept object_id")
        if operation in {"update", "delete"}:
            object_id = _validate_id(object_id)
        if resource == "user_access_tokens" and operation == "create":
            if object_id is not None:
                raise ValueError("Token creation does not accept object_id")
            if not isinstance(data, dict):
                raise ValueError("Token creation requires name and permission fields")
    if spec.high_impact and not acknowledge_high_impact:
        raise ValueError("This change is high impact; inspect the resource risk and set acknowledge_high_impact=true to prepare it")

    ldap_before = None
    auth_settings_before = None
    auth_write_effects: list[str] = []
    if resource == "ldap_sources" and operation == "update" and isinstance(data, Mapping) and "preferences" in data:
        ldap_before = await _snapshot(resource, operation, object_id)
        data = retain_ldap_secret(data, ldap_before)
    if resource == "settings" and operation == "update" and isinstance(data, Mapping) and is_auth_credential_setting(data.get("name")):
        auth_settings_before = await _snapshot(resource, operation, object_id)
        if not isinstance(auth_settings_before, Mapping) or auth_settings_before.get("id") != object_id or auth_settings_before.get("name") != data.get("name"):
            raise ValueError("settings name must match the selected authentication credential setting ID")
        data, preview_data, auth_write_effects = prepare_auth_setting_update(
            data, auth_settings_before, _materialize_secret_values
        )
    if resource == "ldap_sources" and operation in {"create", "update"}:
        if operation == "create" and isinstance(data.get("preferences"), Mapping) and data["preferences"].get("bind_pw") == "**********":
            raise ValueError("A masked bind password can only be reused when updating an existing LDAP source")
        validate_ldap_source_payload(operation, data)
        data, preview_data = materialize_ldap_source(data)
    elif resource == "external_credentials" and operation in {"create", "update"}:
        validate_external_credentials_payload(operation, data)
        data, preview_data = materialize_external_credentials(data)
    elif resource == "external_credentials" and operation == "verify":
        if object_id is not None:
            raise ValueError("external credential verification does not accept object_id")
        if not acknowledge_high_impact:
            raise ValueError("External credential verification requires acknowledge_high_impact=true")
        validate_external_credentials_payload("update", data)
        provider = data.get("name") if isinstance(data, Mapping) else None
        if provider not in {"google", "microsoft365", "microsoft_graph", "exchange"}:
            raise ValueError("verification supports only Google, Microsoft 365, Microsoft Graph, or Exchange")
        credentials = data.get("credentials")
        if isinstance(credentials, Mapping) and {"provider", "controller", "action"}.intersection(credentials):
            raise ValueError("provider, controller, and action cannot be set in verification credentials")
        data, preview_data = materialize_external_credentials(data)
    elif resource in {"ai_agents", "ai_text_tools"} and operation in {"create", "update"}:
        data, preview_data = validate_ai_payload(resource, operation, data)
    elif resource == "oauth_applications" and operation in {"create", "update"}:
        data, preview_data = validate_oauth_application_payload(operation, data)
    elif resource == "product_logo" and operation == "update":
        data, _ = _materialize_secret_values(data)
        preview_data = validate_product_logo_payload(data)
    elif resource == "settings" and operation == "update" and auth_settings_before is not None:
        pass
    else:
        data, preview_data = _materialize_secret_values(data) if data is not None else (None, None)
    if resource == "jobs" and operation in {"create", "update"}:
        validate_job_payload(operation, data)
    if resource in _MESSAGE_CHANNEL_RESOURCES:
        _validate_channel_payload(resource, operation, data)
    if resource == "public_links" and operation in {"create", "update"}:
        validate_public_link_payload(operation, data)
    if resource == "chats" and operation in {"create", "update"}:
        validate_chat_payload(operation, data)
    if resource == "postmaster_filters" and operation in {"create", "update"}:
        validate_postmaster_filter_payload(operation, data)

    before = ldap_before if ldap_before is not None else auth_settings_before if auth_settings_before is not None else await _snapshot(resource, operation, object_id)
    if resource == "external_credentials" and operation == "verify":
        assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
        credential_assets = assets.get("ExternalCredential", {}) if isinstance(assets, Mapping) else {}
        configured_providers = sorted(
            item.get("name") for item in credential_assets.values()
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        ) if isinstance(credential_assets, Mapping) else []
        before_preview = {"configured_providers": configured_providers}
    if resource == "settings" and operation == "reset":
        if not isinstance(before, Mapping) or not isinstance(before.get("name"), str):
            raise RuntimeError("The Zammad API did not return a setting snapshot")
        data = {"name": before["name"]}
        preview_data = {"name": before["name"]}
    if resource == "product_logo" and (not isinstance(before, Mapping) or before.get("name") != "product_logo"):
        raise ValueError("object_id must identify the product_logo setting")
    facebook_requested_pages: Mapping[str, Any] | None = None
    facebook_channel: Mapping[str, Any] | None = None
    if resource == "facebook_channels":
        assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        facebook_channel = channel_assets.get(str(object_id)) if isinstance(channel_assets, Mapping) else None
        if not isinstance(facebook_channel, Mapping) or facebook_channel.get("area") != "Facebook::Account":
            raise ValueError("object_id must identify an existing Facebook account channel")
        if operation == "update":
            requested_pages = preview_data["pages"]
            options = facebook_channel.get("options", {})
            existing_pages = options.get("pages", []) if isinstance(options, Mapping) else []
            page_ids = {
                str(page.get("id")) for page in existing_pages
                if isinstance(page, Mapping) and page.get("id") is not None
            } if isinstance(existing_pages, list) else set()
            if set(requested_pages) - page_ids:
                raise ValueError("pages must identify Facebook pages already linked to this channel")
            current_options = dict(options) if isinstance(options, Mapping) else {}
            current_sync = current_options.get("sync", {})
            sync = dict(current_sync) if isinstance(current_sync, Mapping) else {}
            current_page_settings = sync.get("pages", {})
            page_settings = dict(current_page_settings) if isinstance(current_page_settings, Mapping) else {}
            page_settings.update(requested_pages)
            sync["pages"] = page_settings
            current_options["sync"] = sync
            facebook_requested_pages = requested_pages
            data = {"id": object_id, "options": current_options}
            preview_data = {"pages": requested_pages}
    if resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        oauth_email_channel = channel_assets.get(str(object_id)) if isinstance(channel_assets, Mapping) else None
        expected_area = {
            "google_channels": "Google::Account",
            "microsoft365_channels": "Microsoft365::Account",
            "microsoft_graph_channels": "MicrosoftGraph::Account",
        }[resource]
        if not isinstance(oauth_email_channel, Mapping) or oauth_email_channel.get("area") != expected_area:
            raise ValueError("object_id must identify an existing channel of the selected OAuth email type")
        if operation == "rollback_migration":
            options = oauth_email_channel.get("options", {})
            backup = options.get("backup_imap_classic") if isinstance(options, Mapping) else None
            attributes = backup.get("attributes") if isinstance(backup, Mapping) else None
            if resource == "microsoft_graph_channels" or not isinstance(attributes, Mapping):
                raise ValueError("object_id must identify a Google or Microsoft 365 channel with an IMAP migration backup")
            rollback_area = attributes.get("area")
            if rollback_area != "Email::Account":
                raise ValueError("The stored migration backup does not identify a legacy inbound email channel")
            rollback_backup = backup
        if operation == "configure" and data.get("group_email_address") is True:
            email_assets = assets.get("EmailAddress", {}) if isinstance(assets, Mapping) else {}
            associated_email = None
            address_id = data.get("group_email_address_id")
            if not isinstance(email_assets, Mapping):
                raise ValueError("The Zammad API did not return associated email addresses")
            if address_id is not None:
                associated_email = email_assets.get(str(address_id))
                if not isinstance(associated_email, Mapping) or str(associated_email.get("channel_id")) != str(object_id):
                    raise ValueError("group_email_address_id must identify an email address attached to this channel")
            elif not any(isinstance(entry, Mapping) for entry in email_assets.values()):
                raise ValueError("This channel has no associated email address to assign to the destination group")
            if address_id is not None and not isinstance(associated_email, Mapping):
                raise ValueError("This channel has no associated email address to assign to the destination group")
            preview_data = dict(preview_data)
            preview_data["group_sender_address"] = (
                associated_email.get("email") if associated_email is not None
                else "channel-associated address (selected by Zammad)"
            )
    if resource in {"ai_agents", "ai_text_tools"}:
        if operation == "create":
            before_preview = project_ai_collection(resource, before)
            after = preview_data
        elif operation == "update":
            before_preview = project_ai_object(resource, before)
            after = _merge_preview(before_preview, preview_data or {})
        else:
            before_preview = project_ai_object(resource, before)
            after = None
    elif resource in _MESSAGE_CHANNEL_RESOURCES:
        before_preview = _project_messaging_channels(before)
        if operation in {"create", "update"}:
            after = preview_data
            if resource == "whatsapp_channels" and operation == "update":
                after = {
                    **preview_data,
                    "credential_handling": {
                        key: (
                            "set from process environment"
                            if preview_data.get(key) == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]"
                            else "existing credential retained"
                        )
                        for key in ("access_token", "app_secret")
                    },
                }
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        elif operation == "test":
            after = {
                "test_sms_to": preview_data["recipient"],
                "message": preview_data["message"],
                "side_effects_on_apply": ["send a real SMS; provider charges may apply"],
            }
        elif operation == "preload":
            after = {
                "provider_request": "retrieve WhatsApp phone-number options from Meta",
                "input": preview_data,
                "side_effects_on_apply": ["make an external request to Meta"],
            }
        else:
            after = None
    elif resource == "facebook_channels":
        before_preview = _project_messaging_channels(before)
        if operation == "update":
            after = {"id": object_id, "page_group_assignments": preview_data["pages"]}
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        else:
            after = None
    elif resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        before_preview = _project_messaging_channels(before)
        if operation == "rollback_migration":
            channel = next(iter(before.get("assets", {}).get("Channel", {}).values()), {})
            before_preview = {
                "id": object_id,
                "area": channel.get("area") if isinstance(channel, Mapping) else None,
                "active": channel.get("active") if isinstance(channel, Mapping) else None,
                "migration_backup_available": True,
            }
            backup_attributes = rollback_backup["attributes"]
            after = {
                "id": object_id,
                "restore_area": backup_attributes["area"],
                "restore_status": {key: backup_attributes.get(key) for key in ("status_in", "status_out")},
                "restore_configuration": "stored legacy IMAP snapshot",
                "secrets_returned": False,
            }
        elif operation == "configure":
            after = {"id": object_id, "requested_settings": preview_data,
                     "channel_status_after_save": {"status_in": "ok", "status_out": "ok", "logs_cleared": True},
                     "future_effects": ["Archive settings may change how subsequent mailbox fetching imports messages"]}
        elif operation == "probe":
            after = {
                "id": object_id,
                "probe": "refresh OAuth access and read the selected mailbox configuration",
                "request_options": preview_data.get("options", {}),
                "response_fields": ["success", "content_message_count"],
                "mail_content_returned": False,
            }
        elif operation == "reassign":
            after = {"id": object_id, "group_id": preview_data["group_id"]}
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        else:
            after = None
    elif resource == "user_access_tokens" and operation == "create":
        _validate_token_create_payload(data, before)
    dependencies: list[dict[str, str]] = []
    group_id = None
    if resource == "settings" and operation == "update" and isinstance(data, Mapping):
        setting_name = data.get("name")
        setting_state = data.get("state_current")
        setting_value = setting_state.get("value") if isinstance(setting_state, Mapping) else None
        related_setting_name = None
        if setting_name == "auth_sso" and setting_value is True:
            related_setting_name = "auth_sso_trusted_ips"
        elif setting_name == "auth_sso_trusted_ips":
            related_setting_name = "auth_sso"
        if related_setting_name is not None:
            related_setting = await _setting_snapshot_by_name(related_setting_name)
            dependencies.append({
                "path": f"/settings/{_validate_id(related_setting.get('id'))}",
                "fingerprint": _digest(related_setting),
            })
            related_state = related_setting.get("state_current")
            related_value = related_state.get("value") if isinstance(related_state, Mapping) else None
            if setting_name == "auth_sso" and (not isinstance(related_value, str) or not related_value.strip()):
                auth_write_effects.append(
                    "Enable proxy SSO with no trusted proxy IP ranges configured; authentication headers will be accepted from any source."
                )
            if setting_name == "auth_sso_trusted_ips" and related_value is True:
                networks = _validate_sso_trusted_ip_ranges(setting_value)
                if not networks:
                    auth_write_effects.append(
                        "Clear trusted proxy IP ranges while proxy SSO is enabled; authentication headers will be accepted from any source."
                    )
                elif any(network.prefixlen == 0 for network in networks):
                    auth_write_effects.append(
                        "Trust every IPv4/IPv6 source for proxy SSO because a universal network range is configured."
                    )
    if resource == _EMAIL_ACCOUNT_RESOURCE:
        group_id = data["group_id"]
    elif resource == "email_channels" and operation == "reassign":
        group_id = data["group_id"]
    elif resource in _MESSAGE_CHANNEL_RESOURCES and operation in {"create", "update"} and isinstance(data, Mapping):
        group_id = data.get("group_id")
    if group_id is not None:
        group_before = await _get(f"/groups/{_validate_id(group_id)}")
        dependencies.append({"path": f"/groups/{group_id}", "fingerprint": _digest(group_before)})
    if resource == "ldap_sources" and operation in {"create", "update"}:
        for role_id in sorted(ldap_role_ids(data)):
            role_before = await _get(f"/roles/{role_id}")
            if not isinstance(role_before, Mapping) or role_before.get("active") is not True:
                raise ValueError(f"group_role_map role {role_id} must identify an active role")
            dependencies.append({"path": f"/roles/{role_id}", "fingerprint": _digest(role_before)})
    if resource == "facebook_channels" and operation == "update" and facebook_requested_pages is not None:
        for assignment in facebook_requested_pages.values():
            group_id = assignment.get("group_id") if isinstance(assignment, Mapping) else None
            if group_id in (None, ""):
                continue
            group_before = await _get(f"/groups/{_validate_id(group_id)}")
            if not isinstance(group_before, Mapping) or group_before.get("active") is not True:
                raise ValueError(f"Facebook page group_id {group_id} must identify an active group")
            dependencies.append({"path": f"/groups/{group_id}", "fingerprint": _digest(group_before)})
    if resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"} and operation in {"reassign", "configure"} and "group_id" in preview_data:
        target_group_id = preview_data["group_id"]
        group_before = await _get(f"/groups/{target_group_id}")
        if not isinstance(group_before, Mapping) or group_before.get("active") is not True:
            raise ValueError(f"group_id {target_group_id} must identify an active group")
        dependencies.append({"path": f"/groups/{target_group_id}", "fingerprint": _digest(group_before)})
    if resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"} and operation == "configure":
        state_id = preview_data.get("options", {}).get("archive_state_id")
        if state_id is not None:
            state_before = await _get(f"/ticket_states/{state_id}")
            if not isinstance(state_before, Mapping) or state_before.get("active") is not True:
                raise ValueError("archive_state_id must identify an active ticket state")
            dependencies.append({"path": f"/ticket_states/{state_id}", "fingerprint": _digest(state_before)})
        address_id = data.get("group_email_address_id")
        if address_id is not None:
            address_before = await _get(f"/email_addresses/{address_id}")
            if not isinstance(address_before, Mapping) or str(address_before.get("channel_id")) != str(object_id):
                raise ValueError("group_email_address_id must identify an email address attached to this channel")
            dependencies.append({"path": f"/email_addresses/{address_id}", "fingerprint": _digest(address_before)})
    if resource == _EMAIL_ACCOUNT_RESOURCE and data.get("channel_id") is not None:
        current_ids = before.get("account_channel_ids", []) if isinstance(before, Mapping) else []
        if data["channel_id"] not in current_ids:
            raise ValueError("channel_id must identify an existing inbound email channel")
    if resource == _EMAIL_ACCOUNT_RESOURCE and data.get("group_email_address_id") is not None:
        email_ids = before.get("email_address_ids", []) if isinstance(before, Mapping) else []
        if data["group_email_address_id"] not in email_ids:
            raise ValueError("group_email_address_id must identify an existing sender address")
    if resource == "email_channels":
        current_ids = before.get("account_channel_ids", []) if isinstance(before, Mapping) else []
        if object_id not in current_ids:
            raise ValueError("object_id must identify an existing inbound email channel")
    if resource in _MESSAGE_CHANNEL_RESOURCES and operation in {"update", "delete", "enable", "disable"}:
        assets = before.get("assets", {}) if isinstance(before, Mapping) else {}
        channel_assets = assets.get("Channel", {}) if isinstance(assets, Mapping) else {}
        channel_ids = {int(value) for value in channel_assets if str(value).isdigit()} if isinstance(channel_assets, Mapping) else set()
        if object_id not in channel_ids:
            raise ValueError("object_id must identify an existing messaging channel")
    if operation in {"update", "delete"} and not isinstance(before, Mapping):
        raise RuntimeError("The Zammad API did not return an object snapshot")
    if resource == "settings" and operation == "update" and data.get("name") != before.get("name"):
        raise ValueError("settings name must match the selected setting ID")
    if resource == "user_access_tokens" and operation == "create":
        available_permissions = [
            item["name"] for item in before.get("permissions", [])
            if isinstance(item, Mapping) and item.get("active") is True and isinstance(item.get("name"), str)
        ] if isinstance(before, Mapping) else []
        before_preview = {
            "active_permission_count": len(available_permissions),
            "requested_permissions_are_active": True,
        }
        after = preview_data
    elif resource == "product_logo":
        current_value = before.get("state_current", {}) if isinstance(before, Mapping) else {}
        before_preview = {
            "id": object_id,
            "name": "product_logo",
            "custom_logo_configured": isinstance(current_value, Mapping) and current_value.get("value") not in (None, ""),
        }
        after = preview_data
    elif resource == "settings" and operation == "reset":
        before_preview = _project_settings(before)
        after = _project_settings({**before, "state_current": before.get("state_initial")})
    elif resource == "facebook_channels":
        before_preview = _project_messaging_channels(before)
        if operation == "update":
            after = {"id": object_id, "page_group_assignments": preview_data["pages"]}
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        else:
            after = None
    elif resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
        before_preview = _project_messaging_channels(before)
        if operation == "rollback_migration":
            channel = next(iter(before.get("assets", {}).get("Channel", {}).values()), {})
            before_preview = {
                "id": object_id,
                "area": channel.get("area") if isinstance(channel, Mapping) else None,
                "active": channel.get("active") if isinstance(channel, Mapping) else None,
                "migration_backup_available": True,
            }
            backup_attributes = rollback_backup["attributes"]
            after = {
                "id": object_id,
                "restore_area": backup_attributes["area"],
                "restore_status": {key: backup_attributes.get(key) for key in ("status_in", "status_out")},
                "restore_configuration": "stored legacy IMAP snapshot",
                "secrets_returned": False,
            }
        elif operation == "configure":
            after = {"id": object_id, "requested_settings": preview_data,
                     "channel_status_after_save": {"status_in": "ok", "status_out": "ok", "logs_cleared": True},
                     "future_effects": ["Archive settings may change how subsequent mailbox fetching imports messages"]}
        elif operation == "probe":
            after = {
                "id": object_id,
                "probe": "refresh OAuth access and read the selected mailbox configuration",
                "request_options": preview_data.get("options", {}),
                "response_fields": ["success", "content_message_count"],
                "mail_content_returned": False,
            }
        elif operation == "reassign":
            after = {"id": object_id, "group_id": preview_data["group_id"]}
        elif operation in {"enable", "disable"}:
            after = {"id": object_id, "active": operation == "enable"}
        else:
            after = None
    elif resource == "oauth_applications":
        if operation == "create":
            before_preview = project_oauth_applications(before)
            after = preview_data
        else:
            before_preview = project_oauth_application(before)
            after = project_oauth_application(_merge_preview(before, preview_data or {})) if operation == "update" else None
            if operation == "update" and isinstance(preview_data, Mapping) and preview_data.get("redirect_uri_warnings"):
                after["redirect_uri_warnings"] = preview_data["redirect_uri_warnings"]
    elif resource == "time_accounting_types":
        before_preview = project_time_accounting_types([before])[0] if isinstance(before, Mapping) else None
        after = preview_data if operation == "create" else project_time_accounting_types([_merge_preview(before, preview_data or {})])[0]
    elif operation == "create":
        after = preview_data
    elif resource == _EMAIL_ACCOUNT_RESOURCE:
        preview = _email_account_preview(before, preview_data)
        before_preview = preview["before"]
        after = preview["after"]
    elif resource == "email_channels":
        preview = _email_account_preview(before, {"channel_id": object_id})
        before_preview = preview["before"]
        if operation == "enable":
            after = {"id": object_id, "active": True}
        elif operation == "disable":
            after = {"id": object_id, "active": False}
        elif operation == "reassign":
            after = {"id": object_id, "group_id": preview_data["group_id"]}
        else:
            after = None
    elif resource == _SPECIAL_CHANNEL:
        before_preview = _project_email_channels(before)
        after = {
            "requested_configuration": preview_data,
            "side_effects_on_apply": ["send a real SMTP test email", "save the notification channel on success"],
        }
    elif resource == "external_credentials" and operation == "verify":
        provider = data["name"]
        after = {
            "provider": provider,
            "credential_fields": sorted(data["credentials"]),
            "secret_values_returned": False,
            "verification_scope": "Zammad checks required inputs and constructs OAuth authorization data; it does not authenticate an account.",
            "side_effects_on_apply": ["submit app configuration to Zammad; no credential is saved"],
        }
    elif operation in {"update", "configure"}:
        after = _merge_preview(before, preview_data or {})
    else:
        after = None
    if resource not in {_SPECIAL_CHANNEL, _EMAIL_ACCOUNT_RESOURCE, "email_channels", "facebook_channels", "product_logo", "google_channels", "microsoft365_channels", "microsoft_graph_channels", "time_accounting_types", *_MESSAGE_CHANNEL_RESOURCES} and not (
        resource == "user_access_tokens" and operation == "create"
    ) and not (resource == "external_credentials" and operation == "verify"):
        before_preview = before
    if resource == "settings":
        before_preview = _project_admin_settings(before_preview)
        after = _project_admin_settings(after)

    plan_id = secrets.token_urlsafe(24)
    now = time.time()
    plan = {
        "resource": resource, "operation": operation, "object_id": object_id,
        "data": data, "fingerprint": _snapshot_fingerprint(resource, before), "before": before,
        "dependencies": dependencies,
        "expires_at": now + _PLAN_TTL_SECONDS, "high_impact": spec.high_impact,
    }
    async with _PLAN_LOCK:
        _expire_plans(now)
        if len(_PLANS) >= _MAX_PLANS:
            oldest = min(_PLANS, key=lambda k: _PLANS[k]["expires_at"])
            _PLANS.pop(oldest, None)
        _PLANS[plan_id] = plan

    write_effects: list[str] = []
    if resource == "external_credentials" and operation in {"create", "update", "verify"} and isinstance(preview_data, Mapping):
        credentials_preview = preview_data.get("credentials")
        if isinstance(credentials_preview, Mapping):
            secret_present = any(
                value == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]"
                for key, value in credentials_preview.items()
                if key in {"client_secret", "application_secret"}
            )
            if secret_present:
                write_effects.append(
                    "Use the external provider secret from a process environment reference"
                    if operation == "verify"
                    else "Set the external provider secret from a process environment reference"
                )
    if resource == "ldap_sources" and operation in {"create", "update"} and isinstance(preview_data, Mapping):
        preferences_preview = preview_data.get("preferences")
        if isinstance(preferences_preview, Mapping):
            bind_password_preview = preferences_preview.get("bind_pw")
            if bind_password_preview == "[SECRET PROVIDED BY PROCESS ENVIRONMENT]":
                write_effects.append("Set the LDAP bind password from a process environment reference")
            elif bind_password_preview == "[EXISTING SECRET RETAINED]":
                write_effects.append("Retain the existing LDAP bind password")
            elif bind_password_preview in (None, ""):
                write_effects.append("Store no LDAP bind password")
    preview_response = {
        "plan_id": plan_id,
        "resource": resource,
        "operation": operation,
        "object_id": object_id,
        "expires_in_seconds": _PLAN_TTL_SECONDS,
        "snapshot_fingerprint": plan["fingerprint"],
        "risk": spec.risk,
        "before": before_preview,
        "after": after,
        "approval_required": True,
        "note": "No write was performed. A fresh read-before-write check runs during apply; use apply only after explicit user approval.",
    }
    if write_effects:
        preview_response["write_effects"] = write_effects
    if auth_write_effects:
        preview_response["write_effects"] = auth_write_effects
    return _json(preview_response)


@mcp.tool()
async def zammad_apply_admin_change(plan_id: str, acknowledge_high_impact: bool = False) -> str:
    """Apply a prepared change after explicit user approval; stale plans are rejected."""
    if not isinstance(plan_id, str) or not plan_id:
        raise ValueError("plan_id is required")
    async with _PLAN_LOCK:
        _expire_plans(time.time())
        plan = _PLANS.pop(plan_id, None)
    if plan is None:
        raise ValueError("Unknown, expired, or already used plan_id")
    if plan["high_impact"] and not acknowledge_high_impact:
        raise ValueError("This change is high impact; acknowledge_high_impact=true is required")

    async with _WRITE_LOCK:
        snapshot_path = plan.get("snapshot_path")
        if plan["resource"] == "__ldap_connection_action__":
            current = await _get(f"/ldap_sources/{plan['object_id']}") if plan["object_id"] is not None else None
            current_fingerprint = _digest(current) if plan["fingerprint"] is not None else None
        elif plan["resource"] == "__ldap_import_action__":
            current = await _ldap_sources_snapshot()
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__exchange_import_action__":
            current = await _exchange_import_snapshot()
            current_fingerprint = _crypto_digest(current)
        elif plan["resource"] == "__exchange_connection_action__":
            current = await _exchange_oauth_snapshot() if plan["fingerprint"] is not None else None
            current_fingerprint = _crypto_digest(current) if current is not None else None
        elif plan["resource"] == "__translation_change__":
            if plan["operation"] == "upsert":
                current = await _translation_upsert_snapshot(plan["translation_locale"], plan["translation_source"])
            else:
                current = await _get(f"/translations/{_validate_id(plan['object_id'])}")
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__ssl_certificates__":
            current = await _ssl_certificate_snapshot(
                plan["object_id"] if plan["operation"] == "delete" else None
            )
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__monitoring_action__":
            current = (
                await _monitoring_token_setting_snapshot()
                if plan["operation"] == "rotate_token"
                else await _monitoring_health_snapshot()
            )
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__package_change__":
            current = await _package_inventory_snapshot()
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__object_manager_migrations__":
            current = await _object_manager_migration_snapshot()
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__object_manager_discard_changes__":
            current = await _object_manager_migration_snapshot()
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__session_action__":
            current = await _session_snapshot(plan["object_id"])
            current_fingerprint = _digest(current[0]) if current is not None else None
        elif plan["resource"] == "__data_privacy_deletion__":
            current = await _data_privacy_deletion_snapshot(
                plan["object_type"], plan["object_id"], plan["data"]["delete_organization"]
            )
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__oauth_application_token__":
            current = await _oauth_application_snapshot(plan["object_id"])
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__ticket_notification_reset__":
            current = await _ticket_agent_notification_setting_snapshot()
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__user_two_factor_action__":
            current = await _user_two_factor_snapshot(plan["object_id"])
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__user_unlock__":
            current = await _user_unlock_snapshot(plan["object_id"])
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__proxy_test__":
            current = plan["data"]
            current_fingerprint = _proxy_test_fingerprint(current)
        elif plan["resource"] == "__crypto_material__":
            current = await _crypto_material_snapshot(plan["crypto_resource"], plan["object_id"])
            current_fingerprint = _crypto_digest(current)
        elif plan["resource"] == "__user_import__":
            current = await _user_import_inventory_snapshot()
            current_fingerprint = current["fingerprint"]
        elif plan["resource"] == "__organization_import__":
            current = await _organization_import_inventory_snapshot()
            current_fingerprint = current["fingerprint"]
        elif plan["resource"] == "__knowledge_base_menu__":
            current = await _knowledge_base_menu_snapshot(plan["object_id"], plan["location"])
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__knowledge_base_deletion__":
            current = await _knowledge_base_deletion_snapshot(plan["object_id"])
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__knowledge_base_create__":
            current = project_knowledge_base_inventory(await _request("POST", "/knowledge_bases/init", {}))
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__knowledge_base_translation__":
            current = await _knowledge_base_translation_snapshot(plan["object_id"], plan["kb_locale_id"])
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__knowledge_base_feed_token__":
            current = await _get(f"/knowledge_bases/{plan['object_id']}")
            current_fingerprint = _digest(current)
        elif plan["resource"] in {"__knowledge_base_attachment_upload__", "__knowledge_base_attachment_delete__"}:
            current = await _knowledge_base_attachments_snapshot(plan["parent_id"], plan.get("answer_id", plan["object_id"]))
            current_fingerprint = _digest(current)
        elif plan["resource"] == "__knowledge_base_order__":
            current = await _knowledge_base_order_snapshot(
                plan["parent_id"], plan["kind"], plan["object_id"]
            )
            current_fingerprint = _digest(current)
        elif plan["resource"] in {
            "__knowledge_base_publication_transition__",
            "__knowledge_base_publication_schedule__",
        }:
            current = await _knowledge_base_publication_snapshot(plan["parent_id"], plan["object_id"])
            current_fingerprint = _digest(current)
        else:
            current = await _get(snapshot_path) if snapshot_path else await _snapshot(plan["resource"], plan["operation"], plan["object_id"])
            current_fingerprint = _snapshot_fingerprint(plan["resource"], current)
        if current_fingerprint != plan["fingerprint"]:
            raise RuntimeError("The resource changed after preview; prepare a new plan")
        if (
            plan["resource"] in {
                "__knowledge_base_publication_transition__",
                "__knowledge_base_publication_schedule__",
            }
            and knowledge_base_publication_state(current) != plan["state_before"]
        ):
            raise RuntimeError("The Knowledge Base answer publication state changed after preview; prepare a new plan")
        for dependency in plan.get("dependencies", []):
            dependency_current = await _get(dependency["path"])
            if _digest(dependency_current) != dependency["fingerprint"]:
                raise RuntimeError("A related resource changed after preview; prepare a new plan")
        resource = plan["resource"]
        operation = plan["operation"]
        data = plan["data"]
        if resource == "external_credentials" and operation == "verify":
            provider = data["name"]
            verification = await _request(
                "POST", f"/external_credentials/{provider}/app_verify", data["credentials"],
            )
            accepted = isinstance(verification, Mapping) and isinstance(verification.get("attributes"), Mapping)
            result = {
                "provider": provider,
                "accepted_by_zammad": accepted,
                "provider_account_authenticated": False,
                "credential_values_returned": False,
                "diagnostics_returned": False,
            }
        elif resource == "__knowledge_base_create__":
            created = await _request("POST", "/knowledge_bases/manage", data)
            created_id = created.get("id") if isinstance(created, Mapping) else None
            if isinstance(created_id, bool) or not isinstance(created_id, int) or created_id <= 0:
                after_inventory = project_knowledge_base_inventory(await _request("POST", "/knowledge_bases/init", {}))
                new_ids = [
                    item["id"] for item in after_inventory["knowledge_bases"]
                    if item["id"] not in plan["before_ids"]
                ]
                if len(new_ids) != 1:
                    raise RuntimeError("Zammad may have created the Knowledge Base; inspect the inventory before retrying")
                created_id = new_ids[0]
            created_snapshot = await _get(f"/knowledge_bases/{created_id}")
            if not isinstance(created_snapshot, Mapping) or created_snapshot.get("id") != created_id:
                raise RuntimeError("Zammad created the Knowledge Base but its result could not be verified; inspect the inventory before retrying")
            result = {
                "created": True,
                "knowledge_base_id": created_id,
                "active": created_snapshot.get("active") if isinstance(created_snapshot.get("active"), bool) else True,
                "system_locale_id": data["kb_locales_attributes"][0]["system_locale_id"],
                "default_title": plan["preview_after"]["default_title"],
                "default_footer_note": plan["preview_after"]["default_footer_note"],
            }
        elif resource == "__knowledge_base_translation__":
            await _request("PATCH", f"/knowledge_bases/manage/{plan['object_id']}", data)
            result = {
                "updated": True,
                "knowledge_base_id": plan["object_id"],
                "kb_locale_id": plan["kb_locale_id"],
                "fields_updated": plan["updated_fields"],
            }
        elif resource == "__knowledge_base_feed_token__":
            kb_id = plan["object_id"]
            method = "GET" if operation == "ensure" else "PATCH"
            try:
                token_response = await _request(method, f"/knowledge_bases/{kb_id}/feed_tokens")
            except Exception:
                raise RuntimeError(
                    "The Knowledge Base feed token action failed. Inspect Zammad and the local token store before retrying."
                ) from None
            token_value = token_response.get("token") if isinstance(token_response, Mapping) else None
            if not isinstance(token_value, str) or not token_value:
                raise RuntimeError(
                    "Zammad completed a Knowledge Base feed token action without returning a retrievable token; inspect token access before retrying"
                )
            try:
                stored_path = _store_generated_token(
                    token_value,
                    {
                        "name": f"knowledge-base-{kb_id}-feed-token",
                        "purpose": "zammad-knowledge-base-private-feed",
                        "knowledge_base_id": kb_id,
                        "operation": operation,
                    },
                )
            except Exception:
                warning = (
                    "Zammad may have created a private-feed token but secure local storage failed; inspect the token store before retrying."
                    if operation == "ensure"
                    else "Zammad rotated the private-feed token but secure local storage failed; existing feed URLs are invalid. Inspect the token store before retrying."
                )
                raise RuntimeError(warning) from None
            result = {
                "knowledge_base_id": kb_id,
                "action": operation,
                "stored": True,
                "file_path": str(stored_path),
                "file_mode": "0600",
                "token_value_returned": False,
            }
        elif resource == "__user_import__":
            fresh_preview = await _run_user_import(data["csv_data"], data["separator"], dry_run=True)
            after_preview = await _user_import_inventory_snapshot()
            if after_preview["fingerprint"] != plan["fingerprint"]:
                raise RuntimeError("The user inventory changed during final import preview; prepare a new plan")
            if not equivalent_user_import_results(plan["import_preview"], fresh_preview):
                raise RuntimeError("The user import result changed after preview; prepare a new plan")
            result = await _run_user_import(data["csv_data"], data["separator"], dry_run=False)
        elif resource == "__organization_import__":
            fresh_preview = await _run_organization_import(data["csv_data"], data["separator"], dry_run=True)
            after_preview = await _organization_import_inventory_snapshot()
            if after_preview["fingerprint"] != plan["fingerprint"]:
                raise RuntimeError("The organization inventory changed during final import preview; prepare a new plan")
            if not equivalent_user_import_results(plan["import_preview"], fresh_preview):
                raise RuntimeError("The organization import result changed after preview; prepare a new plan")
            result = await _run_organization_import(data["csv_data"], data["separator"], dry_run=False)
        elif resource == "__ldap_connection_action__":
            path = "/integration/ldap/discover" if operation == "discover" else "/integration/ldap/bind"
            payload = dict(data)
            if operation == "bind" and plan["object_id"] is not None:
                payload["ldap_source_id"] = plan["object_id"]
            result = await _request("POST", path, payload)
        elif resource == "__ldap_import_action__":
            if await _ldap_import_pending(operation):
                raise RuntimeError("An LDAP import job was queued or started after preview; prepare a new plan")
            path = "/integration/ldap/job_try" if operation == "dry_run" else "/integration/ldap/job_start"
            result = await _request("POST", path, {})
        elif resource == "__exchange_import_action__":
            if operation == "start" and current["enabled"] is not True:
                raise RuntimeError("The Exchange integration was disabled after preview; prepare a new plan")
            if await _exchange_import_pending("dry_run") or await _exchange_import_pending("start"):
                raise RuntimeError("An Exchange import job was queued or started after preview; prepare a new plan")
            path = _EXCHANGE_IMPORT_DRY_RUN_PATH if operation == "dry_run" else _EXCHANGE_IMPORT_START_PATH
            submitted = await _request("POST", path, data)
            result = {"accepted": isinstance(submitted, Mapping) and submitted.get("result") == "ok"}
        elif resource == "__exchange_connection_action__":
            paths = {
                "autodiscover": _EXCHANGE_AUTODISCOVER_PATH,
                "folders": _EXCHANGE_FOLDERS_PATH,
                "mapping": _EXCHANGE_MAPPING_PATH,
            }
            submitted = await _request("POST", paths[operation], data)
            result = project_exchange_connection_result(operation, submitted)
        elif resource == _SPECIAL_CHANNEL:
            result = await _request("POST", _SPECIAL_PATH, data)
        elif resource == _EMAIL_ACCOUNT_RESOURCE:
            result = await _request("POST", _EMAIL_ACCOUNT_VERIFY_PATH, data)
        elif resource == "product_logo":
            logo_result = await _request("PUT", f"/settings/image/{plan['object_id']}", data)
            result = {
                "stored": isinstance(logo_result, Mapping) and logo_result.get("result") == "ok",
                "setting": "product_logo",
                "image_data_returned": False,
            }
        elif resource == "settings" and operation == "reset":
            result = await _request("POST", f"/settings/reset/{plan['object_id']}", {})
        elif resource == "email_channels":
            channel_id = plan["object_id"]
            if operation == "enable":
                result = await _request("POST", _EMAIL_CHANNEL_ENABLE_PATH, {"id": channel_id})
            elif operation == "disable":
                result = await _request("POST", _EMAIL_CHANNEL_DISABLE_PATH, {"id": channel_id})
            elif operation == "delete":
                result = await _request("DELETE", _SPECIAL_READ_PATH, {"id": channel_id})
            elif operation == "reassign":
                result = await _request("POST", f"{_EMAIL_CHANNEL_GROUP_PATH}/{channel_id}", data)
            else:
                raise ValueError("Unsupported email channel operation")
        elif resource == "facebook_channels":
            channel_id = plan["object_id"]
            if operation == "update":
                result = await _request("POST", f"/channels_facebook/{channel_id}", data)
            elif operation in {"enable", "disable"}:
                result = await _request("POST", f"/channels_facebook_{operation}", {"id": channel_id})
            elif operation == "delete":
                result = await _request("DELETE", "/channels_facebook", {"id": channel_id})
            else:
                raise ValueError("Unsupported Facebook channel operation")
        elif resource in {"google_channels", "microsoft365_channels", "microsoft_graph_channels"}:
            channel_id = plan["object_id"]
            if resource == "google_channels":
                if operation in {"enable", "disable"}:
                    result = await _request("POST", f"/channels_google_{operation}", {"id": channel_id})
                elif operation == "delete":
                    result = await _request("DELETE", "/channels_google", {"id": channel_id})
                elif operation == "reassign":
                    result = await _request("POST", f"/channels_google_group/{channel_id}", data)
                elif operation == "configure":
                    result = await _request("POST", f"/channels_google_verify/{channel_id}", data)
                elif operation == "probe":
                    probe_result = await _request("POST", f"/channels_google_inbound/{channel_id}", data)
                    count = probe_result.get("content_messages") if isinstance(probe_result, Mapping) else None
                    result = {
                        "success": isinstance(probe_result, Mapping) and probe_result.get("result") == "ok",
                        "content_message_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
                        "mail_content_returned": False,
                    }
                elif operation == "rollback_migration":
                    result = await _request("POST", "/channels_google_rollback_migration", {"id": channel_id})
                else:
                    raise ValueError("Unsupported Google channel operation")
            elif resource == "microsoft365_channels":
                if operation in {"enable", "disable"}:
                    result = await _request("POST", f"/channels_microsoft365_{operation}", {"id": channel_id})
                elif operation == "delete":
                    result = await _request("DELETE", "/channels_microsoft365", {"id": channel_id})
                elif operation == "reassign":
                    result = await _request("POST", f"/channels_microsoft365_group/{channel_id}", data)
                elif operation == "configure":
                    result = await _request("POST", f"/channels_microsoft365_verify/{channel_id}", data)
                elif operation == "probe":
                    probe_result = await _request("POST", f"/channels_microsoft365_inbound/{channel_id}", data)
                    count = probe_result.get("content_messages") if isinstance(probe_result, Mapping) else None
                    result = {
                        "success": isinstance(probe_result, Mapping) and probe_result.get("result") == "ok",
                        "content_message_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
                        "mail_content_returned": False,
                    }
                elif operation == "rollback_migration":
                    result = await _request("POST", "/channels_microsoft365_rollback_migration", {"id": channel_id})
                else:
                    raise ValueError("Unsupported Microsoft 365 channel operation")
            else:
                if operation in {"enable", "disable"}:
                    result = await _request("POST", f"/channels/admin/microsoft_graph/{channel_id}/{operation}", {"id": channel_id})
                elif operation == "delete":
                    result = await _request("DELETE", f"/channels/admin/microsoft_graph/{channel_id}", {"id": channel_id})
                elif operation == "reassign":
                    result = await _request("POST", f"/channels/admin/microsoft_graph/group/{channel_id}", data)
                elif operation == "configure":
                    result = await _request("POST", f"/channels/admin/microsoft_graph/verify/{channel_id}", data)
                elif operation == "probe":
                    probe_result = await _request("POST", f"/channels/admin/microsoft_graph/inbound/{channel_id}", data)
                    count = probe_result.get("content_messages") if isinstance(probe_result, Mapping) else None
                    result = {
                        "success": isinstance(probe_result, Mapping) and probe_result.get("result") == "ok",
                        "content_message_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
                        "mail_content_returned": False,
                    }
                else:
                    raise ValueError("Unsupported Microsoft Graph channel operation")
        elif resource in _MESSAGE_CHANNEL_RESOURCES:
            spec = _resource(resource)
            if operation == "create":
                result = await _request("POST", spec.path, data)
            elif operation == "update":
                result = await _request("PUT", f"{spec.path}/{plan['object_id']}", data)
            elif operation == "delete":
                if resource == "telegram_channels":
                    result = await _request("DELETE", spec.path, {"id": plan["object_id"]})
                else:
                    result = await _request("DELETE", f"{spec.path}/{plan['object_id']}")
            elif operation in {"enable", "disable"}:
                active = operation == "enable"
                if resource == "whatsapp_channels":
                    action = "enable" if active else "disable"
                    result = await _request("POST", f"{spec.path}/{plan['object_id']}/{action}")
                else:
                    action_path = f"/{'channels_sms' if resource == 'sms_channels' else 'channels_telegram'}_{operation}"
                    result = await _request("POST", action_path, {"id": plan["object_id"]})
            elif operation == "test" and resource == "sms_channels":
                test_result = await _request("POST", "/channels_sms/test", data)
                result = {
                    "success": isinstance(test_result, Mapping) and test_result.get("success") is True,
                    "diagnostics_returned": False,
                }
            elif operation == "preload" and resource == "whatsapp_channels":
                result = await _request("POST", f"{spec.path}/preload", data)
            else:
                raise ValueError("Unsupported messaging channel operation")
        elif resource == "user_access_tokens" and operation == "create":
            token_response = await _request("POST", "/user_access_token", data)
            token_value = token_response.get("token") if isinstance(token_response, Mapping) else None
            if not isinstance(token_value, str) or not token_value:
                raise RuntimeError("Zammad accepted token creation without returning a retrievable token; inspect token metadata and revoke if needed")
            metadata = {key: data[key] for key in ("name", "permission", "expires_at") if key in data}
            stored_path = _store_generated_token(token_value, metadata)
            result = {
                "name": data["name"],
                "permission": data["permission"],
                "expires_at": data.get("expires_at"),
                "file_path": str(stored_path),
                "file_mode": "0600",
                "token_value_returned": False,
            }
        elif resource == "oauth_applications":
            if operation == "create":
                created = await _request("POST", "/applications", data)
                client_secret = created.get("secret") if isinstance(created, Mapping) else None
                if not isinstance(client_secret, str) or not client_secret:
                    raise RuntimeError("Zammad created the OAuth application without returning a retrievable client secret; delete it before retrying")
                metadata = {
                    "name": f"oauth-app-{created.get('name', 'client')}",
                    "purpose": "zammad-oauth-client-secret",
                    "application_id": created.get("id"),
                    "client_id": created.get("uid"),
                }
                try:
                    secret_file = _store_generated_token(client_secret, metadata)
                except RuntimeError:
                    raise RuntimeError("Zammad created the OAuth application but secure client-secret storage failed; do not retry creation, delete this application and recreate it after fixing the secret store") from None
                result = {
                    **project_oauth_application(created),
                    "file_path": str(secret_file),
                    "client_secret_returned": False,
                }
            elif operation == "update":
                updated = await _request("PUT", f"/applications/{plan['object_id']}", data)
                result = project_oauth_application(updated)
            elif operation == "delete":
                await _request("DELETE", f"/applications/{plan['object_id']}")
                result = {"deleted": True, "application_id": plan["object_id"]}
            else:
                raise ValueError("Unsupported OAuth application operation")
        elif resource == "__oauth_application_token__":
            token_response = await _request("POST", "/applications/token", {"id": _validate_id(plan["object_id"])})
            token_value = token_response.get("token") if isinstance(token_response, Mapping) else None
            if not isinstance(token_value, str) or not token_value:
                raise RuntimeError("Zammad issued no retrievable OAuth application token; inspect application access before retrying")
            secret_file = _store_generated_token(token_value, {
                "name": f"oauth-app-{plan['object_id']}-user-token",
                "purpose": "zammad-oauth-application-access-token",
                "application_id": plan["object_id"],
                "resource_owner": "current Zammad user",
            })
            result = {
                "issued": True,
                "application_id": plan["object_id"],
                "file_path": str(secret_file),
                "token_value_returned": False,
            }
        elif resource == "__knowledge_base_settings__":
            result = await _request("PATCH", f"/knowledge_bases/manage/{plan['object_id']}", data)
        elif resource == "__knowledge_base_lifecycle__":
            await _request(
                "PATCH",
                f"/knowledge_bases/manage/{plan['object_id']}/{operation}",
            )
            result = {"knowledge_base_id": plan["object_id"], "active": data["active"]}
        elif resource == "__knowledge_base_deletion__":
            await _request("DELETE", f"/knowledge_bases/manage/{plan['object_id']}")
            result = {"knowledge_base_id": plan["object_id"], "deleted": True}
        elif resource == "__knowledge_base_menu__":
            await _request(
                "PATCH",
                f"/knowledge_bases/manage/{plan['object_id']}/update_menu_items",
                data,
            )
            result = {
                "knowledge_base_id": plan["object_id"],
                "location": plan["location"],
                "locales_updated": len(data["menu_items_sets"]),
                "updated": True,
            }
        elif resource == "__knowledge_base_attachment_upload__":
            await _request(
                "POST",
                f"/knowledge_bases/{plan['parent_id']}/answers/{plan['object_id']}/attachments",
                files={"file": (data["filename"], data["content"], data["content_type"])},
            )
            result = {
                "knowledge_base_id": plan["parent_id"],
                "answer_id": plan["object_id"],
                "filename": data["filename"],
                "size_bytes": len(data["content"]),
                "uploaded": True,
                "file_contents_returned": False,
            }
        elif resource == "__knowledge_base_attachment_delete__":
            await _request(
                "DELETE",
                f"/knowledge_bases/{plan['parent_id']}/answers/{plan['answer_id']}/attachments/{plan['object_id']}",
            )
            result = {
                "knowledge_base_id": plan["parent_id"],
                "answer_id": plan["answer_id"],
                "attachment_id": plan["object_id"],
                "deleted": True,
            }
        elif resource == "__knowledge_base_order__":
            await _request("PATCH", plan["write_path"], data)
            result = {
                "knowledge_base_id": plan["parent_id"],
                "category_id": plan["object_id"],
                "kind": plan["kind"],
                "ordered_ids": data["ordered_ids"],
                "reordered": True,
            }
        elif resource == "__knowledge_base_publication_transition__":
            await _request(
                "POST",
                f"/knowledge_bases/{plan['parent_id']}/answers/{plan['object_id']}/{operation}",
                {},
            )
            result = {
                "knowledge_base_id": plan["parent_id"],
                "answer_id": plan["object_id"],
                "transition": operation,
                "state": plan["state_after"],
            }
        elif resource == "__knowledge_base_publication_schedule__":
            await _request(
                "POST",
                f"/knowledge_bases/{plan['parent_id']}/answers/{plan['object_id']}/has_publishing_update",
                data,
            )
            result = {
                "knowledge_base_id": plan["parent_id"],
                "answer_id": plan["object_id"],
                "scheduled": True,
                "timestamps_returned": False,
            }
        elif resource in {"__knowledge_base_permissions__", "__knowledge_base_category_permissions__"}:
            result = await _request("PATCH", plan["write_path"], data)
            result = {"updated": isinstance(result, Mapping), "permission_details_returned": False}
        elif resource == "__translation_change__":
            if operation == "upsert":
                await _request("POST", "/translations/upsert", data)
            elif operation == "reset":
                await _request("PUT", f"/translations/reset/{plan['object_id']}")
            elif operation == "delete":
                await _request("DELETE", f"/translations/{plan['object_id']}")
            else:
                raise ValueError("Unsupported translation operation")
            result = {"updated": True, "translation_content_returned": False}
        elif resource == "__ssl_certificates__":
            if operation == "create":
                created = await _request("POST", "/ssl_certificates", data)
                result = {"created": True, "certificate": project_ssl_certificate(created)}
            elif operation == "delete":
                await _request("DELETE", f"/ssl_certificates/{_validate_id(plan['object_id'])}")
                result = {"deleted": True, "certificate_id": plan["object_id"]}
            else:
                raise ValueError("Unsupported SSL certificate operation")
        elif resource == "__monitoring_action__":
            if operation == "rotate_token":
                token_response = await _request("POST", "/monitoring/token")
                token_value = token_response.get("token") if isinstance(token_response, Mapping) else None
                if not isinstance(token_value, str) or not token_value:
                    raise RuntimeError("Zammad rotated the monitoring token without returning a retrievable token")
                try:
                    stored_path = _store_generated_token(
                        token_value,
                        {"name": "zammad-monitoring-token", "purpose": "zammad-monitoring"},
                    )
                except RuntimeError:
                    raise RuntimeError(
                        "Zammad rotated the monitoring token but secure local storage failed; fix the token store, then prepare and approve another rotation"
                    ) from None
                result = {
                    "token_rotated": True,
                    "file_path": str(stored_path),
                    "file_mode": "0600",
                    "token_value_returned": False,
                }
            elif operation == "restart_failed_jobs":
                await _request("POST", "/monitoring/restart_failed_jobs")
                result = {"restarted": True, "failed_job_count": plan["before"]["failed_job_count"]}
            else:
                raise ValueError("Unsupported monitoring operation")
        elif resource == "__package_change__":
            if operation == "install":
                package = data["package_data"]
                package_json = json.dumps(package, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                filename = f"{package['name']}-{package['version']}.zpm"
                await _request(
                    "POST", "/packages",
                    files={"file_upload": (filename, package_json, "application/json")},
                    accept_package_redirect=True,
                )
                result = {
                    "installed": True,
                    "name": package["name"],
                    "version": package["version"],
                    "package_sha256": plan["preview_after"]["package_sha256"],
                    "package_data_returned": False,
                    "required_follow_up": plan["preview_after"]["requires_follow_up"],
                }
            elif operation == "uninstall":
                await _request("DELETE", "/packages", {"id": _validate_id(plan["object_id"])})
                result = {
                    "removed": True,
                    "package_id": plan["object_id"],
                    "required_follow_up": plan["preview_after"]["requires_follow_up"],
                }
            else:
                raise ValueError("Unsupported package operation")
        elif resource == "__object_manager_migrations__":
            await _request("POST", "/object_manager_attributes_execute_migrations", {})
            result = {
                "migrations_executed": True,
                "attribute_count": len(plan["before"]),
                "removed_attribute_count": sum(1 for item in plan["before"] if item.get("to_delete") is True),
            }
        elif resource == "__object_manager_discard_changes__":
            await _request("POST", "/object_manager_attributes_discard_changes", {})
            pending = plan["before"]
            result = {
                "changes_discarded": True,
                "attribute_count": len(pending),
                "queued_additions_removed": sum(1 for item in pending if item.get("to_create") is True),
                "completed_migrations_reversed": False,
            }
        elif resource == "__session_action__":
            await _request("DELETE", f"/sessions/{_validate_id(plan['object_id'])}")
            result = {"session_terminated": True, "session_id": plan["object_id"]}
        elif resource == "__data_privacy_deletion__":
            preferences: dict[str, Any] = {"sure": "DELETE"}
            if data["delete_organization"]:
                preferences["delete_organization"] = "true"
            task = await _request("POST", "/data_privacy_tasks", {
                "deletable_type": plan["object_type"],
                "deletable_id": _validate_id(plan["object_id"]),
                "preferences": preferences,
            })
            result = {
                "task_queued": isinstance(task, Mapping),
                "task_id": task.get("id") if isinstance(task, Mapping) else None,
                "state": task.get("state") if isinstance(task, Mapping) else None,
                "asynchronous_execution": True,
                "deletion_details_returned": False,
            }
        elif resource == "__ticket_notification_reset__":
            queued = await _request("POST", "/settings/ticket_agent_default_notifications/apply_to_all")
            result = {
                "queued": isinstance(queued, Mapping) and queued.get("status") == "ok",
                "asynchronous": True,
                "job": "ResetNotificationsPreferencesJob",
                "job_id_returned": False,
                "agent_preferences_returned": False,
            }
        elif resource == "__user_two_factor_action__":
            user_id = _validate_id(plan["object_id"])
            if operation == "remove_method":
                await _request(
                    "DELETE",
                    f"/users/{user_id}/admin_two_factor/remove_authentication_method",
                    {"method": data["method"]},
                )
            elif operation == "remove_all":
                await _request("DELETE", f"/users/{user_id}/admin_two_factor/remove_all_authentication_methods")
            else:
                raise ValueError("Unsupported user two-factor operation")
            result = {
                "user_id": user_id,
                "methods_removed": "all" if operation == "remove_all" else [data["method"]],
                "credential_details_returned": False,
            }
        elif resource == "__user_unlock__":
            user_id = _validate_id(plan["object_id"])
            await _request("PUT", f"/users/unlock/{user_id}")
            result = {"user_id": user_id, "unlocked": True, "login_failed": 0}
        elif resource == "__proxy_test__":
            try:
                proxy_result = await _request("POST", "/proxy", data)
            except Exception:
                raise RuntimeError("Proxy connectivity check failed; diagnostic details were withheld") from None
            result = {
                "success": isinstance(proxy_result, Mapping) and proxy_result.get("result") == "success",
                "diagnostics_returned": False,
                "settings_saved": False,
            }
        elif resource == "__crypto_material__":
            crypto_resource = plan["crypto_resource"]
            object_id = plan["object_id"]
            if operation == "create" and crypto_resource == "pgp_keys":
                created = await _request("POST", "/integration/pgp/key", data)
                result = {"created": True, "key": project_pgp_key(created), "key_material_returned": False}
            elif operation == "create" and crypto_resource == "smime_certificates":
                created = await _request("POST", "/integration/smime/certificate", data)
                result = {"created": True, "certificates": project_smime_collection(created if isinstance(created, list) else [created])}
            elif operation == "create" and crypto_resource == "smime_private_keys":
                created = await _request("POST", "/integration/smime/private_key", data)
                metadata = project_smime_certificate(created)
                result = {
                    "private_key_configured": True,
                    "certificate_id": metadata.get("id"),
                    "key_material_returned": False,
                    "response_metadata": metadata,
                }
            elif operation == "delete" and crypto_resource == "pgp_keys":
                await _request("DELETE", f"/integration/pgp/key/{_validate_id(object_id)}")
                result = {"deleted": True, "key_id": object_id, "key_material_returned": False}
            elif operation == "delete" and crypto_resource == "smime_certificates":
                await _request("DELETE", "/integration/smime/certificate", {"id": _validate_id(object_id)})
                result = {"deleted": True, "certificate_id": object_id, "paired_private_key_removed": True}
            elif operation == "delete" and crypto_resource == "smime_private_keys":
                await _request("DELETE", "/integration/smime/private_key", {"id": _validate_id(object_id)})
                result = {"private_key_removed": True, "certificate_id": object_id, "certificate_preserved": True}
            else:
                raise ValueError("Unsupported cryptographic material operation")
        elif resource == "__knowledge_base_record__":
            result = await _request(plan["write_method"], plan["write_path"], data)
        else:
            spec = _resource(resource)
            if operation == "create":
                result = await _request("POST", spec.path, data)
            elif operation == "update":
                result = await _request("PUT", f"{spec.path}/{plan['object_id']}", data)
            elif operation == "delete":
                result = await _request("DELETE", f"{spec.path}/{plan['object_id']}")
            else:
                raise ValueError("Unsupported operation")
    if resource == "settings" and _is_sensitive_setting_name(plan.get("data", {}).get("name")):
        result = {"updated": True, "sensitive_value_returned": False}
    response_resource = {
        "__ldap_connection_action__": "ldap_connection_tests",
        "__ldap_import_action__": "ldap_import_actions",
        "__exchange_connection_action__": "exchange_connection_tests",
        "__exchange_import_action__": "exchange_import_actions",
        "__object_manager_migrations__": "object_manager_attributes",
        "__session_action__": "sessions",
        "__data_privacy_deletion__": "data_privacy_tasks",
        "__oauth_application_token__": "oauth_applications",
        "__ticket_notification_reset__": "ticket_agent_notifications",
        "__user_two_factor_action__": "user_two_factor_authentication",
        "__user_unlock__": "user_unlock",
        "__proxy_test__": "proxy_test",
        "__crypto_material__": plan.get("crypto_resource", "cryptographic_material"),
        "__user_import__": "user_imports",
        "__organization_import__": "organization_imports",
        "__knowledge_base_deletion__": "knowledge_base_manager",
        "__knowledge_base_create__": "knowledge_base_manager",
        "__knowledge_base_translation__": "knowledge_base_translations",
        "__knowledge_base_feed_token__": "knowledge_base_feed_tokens",
        "__knowledge_base_lifecycle__": "knowledge_base_lifecycle",
        "__knowledge_base_menu__": "knowledge_base_menu_items",
        "__knowledge_base_order__": "knowledge_base_ordering",
        "__knowledge_base_publication_transition__": "knowledge_base_publication",
        "__knowledge_base_publication_schedule__": "knowledge_base_publication",
    }.get(resource, resource)
    if resource == "external_credentials" and operation == "verify":
        response_note = "Plan consumed. Zammad accepted or rejected the app configuration fields; no credentials were saved and no account was authenticated. OAuth URLs, states, secrets, and raw diagnostics were omitted."
    elif resource == "__ldap_connection_action__":
        response_note = "Plan consumed. No LDAP configuration was saved. If the request timed out, check its status before retrying."
    elif resource == "__exchange_connection_action__":
        response_note = "Plan consumed. No Exchange configuration was saved. The response omits credentials and contact examples."
    elif resource == "__ldap_import_action__" and operation == "dry_run":
        response_note = "Plan consumed. A dry-run ImportJob was submitted; it does not save user or role changes. Read status before starting another dry run."
    elif resource == "__ldap_import_action__":
        response_note = "Plan consumed. A background LDAP sync was queued and may change users and roles. Read status before retrying."
    elif resource == "__exchange_import_action__" and operation == "dry_run":
        response_note = "Plan consumed. A persistent Exchange dry-run job was submitted and may contain contact-derived data. Read its projected status before retrying."
    elif resource == "__exchange_import_action__":
        response_note = "Plan consumed. An Exchange import job was queued and may create or update Zammad users. Read projected status before retrying."
    elif resource == "__data_privacy_deletion__":
        response_note = "The deletion was queued for asynchronous Zammad processing. Its scope can change before execution; inspect the Data Privacy task status before retrying."
    elif resource == "__oauth_application_token__":
        response_note = "The token was issued for the current Zammad user and stored in the local secret store. Do not retry if delivery is uncertain; inspect application access first."
    elif resource == "__ticket_notification_reset__":
        response_note = "A background reset was queued. No job ID is returned. If the outcome is uncertain, inspect agent notification preferences before retrying."
    elif resource == "__knowledge_base_deletion__":
        response_note = "The Knowledge Base and its associated content were permanently deleted. If the outcome is uncertain, inspect the Knowledge Base inventory before retrying."
    elif resource == "__knowledge_base_create__":
        response_note = "The Knowledge Base was created. Verify its title, locale, access and content in the inventory before preparing follow-up changes."
    elif resource == "__knowledge_base_translation__":
        response_note = "The selected Knowledge Base translation was updated. Read it again to confirm the saved text."
    elif resource == "__knowledge_base_feed_token__" and operation == "rotate":
        response_note = "The private-feed token was rotated and saved in the protected local token store; previous feed URLs are invalid. The token value is never returned."
    elif resource == "__knowledge_base_feed_token__":
        response_note = "The private-feed token was ensured and saved in the protected local token store. The token value is never returned."
    elif resource == "__user_two_factor_action__":
        response_note = "The two-factor method removal was applied. Inspect the user's enabled methods before retrying if the outcome is uncertain."
    elif resource == "__user_unlock__":
        response_note = "The user was unlocked. Inspect the failed-login counter before retrying if the outcome is uncertain."
    elif resource == "__proxy_test__":
        response_note = "The one-time outbound connectivity check completed. No proxy settings were saved."
    elif resource == "__crypto_material__":
        response_note = "Plan consumed. Cryptographic changes affect message signing, encryption, or decryption. Key material and passphrases are never returned; inspect the safe metadata before retrying if the result is uncertain."
    elif resource == "__user_import__":
        response_note = "Plan consumed. The response contains only aggregate counts and sanitized row error codes. Do not retry if the result is uncertain; inspect the Zammad user list first."
    elif resource == "__organization_import__":
        response_note = "Plan consumed. The response contains only aggregate counts and sanitized row error codes. Do not retry if the result is uncertain; inspect the Zammad organization list first."
    elif resource == "__object_manager_discard_changes__":
        response_note = "The queued changes were discarded; completed database migrations were not reversed. Inspect the Object Manager queue before retrying if the result is uncertain."
    else:
        response_note = "Plan consumed. If the request timed out or returned an error, inspect Zammad before retrying."
    response = {"resource": response_resource, "operation": operation, "result": result, "note": response_note}
    return _json(_redact_exact_secrets(response, _collect_secret_literals(plan.get("data"))))


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
