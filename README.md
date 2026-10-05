# Zammad Admin MCP

A local Python MCP server for reading and configuring allowlisted Zammad administration resources. Zammad configuration changes are staged through a preview tool and a separate apply tool. This MCP does not perform any configuration change merely by being loaded or by listing a resource.

## Current capabilities

- Read the server version and the allowlisted admin collections/objects.
- Page collection reads with `page` and `per_page` (1–100).
- Preserve the original read-only tool names for groups, roles, calendars, SLAs, triggers, and ticket states.
- Prepare create, update, delete, or special configuration changes and return a redacted before/after preview with a five-minute, one-use plan ID.
- Apply a prepared plan only after an explicit user approval in the conversation; apply re-reads the object and rejects a changed snapshot.
- Restrict resource names, paths, object IDs, and HTTP methods to server-side definitions. There is no arbitrary URL/method/body tool.
- Redact secret-like fields in tool results. Submitted credentials are held only in process memory while a plan is pending and are redacted from the preview.

Writes require a Zammad API token with the corresponding permissions. The token permissions determine actual access; the MCP does not grant additional Zammad rights. The `Codex-Zammad-Anpassung` role's intended equality with Admin is preserved as an existing Zammad decision.

## Important limitations

- API coverage is not yet proven complete for every Zammad admin UI setting. The allowlist is an initial API-backed surface; unsupported controls are not routed through arbitrary endpoints or Rails console commands.
- Zammad's published `latest` and `pre-release` documentation is not a version-pinned guarantee for the installed 7.1.2 instance. Confirm each endpoint and payload against that instance before relying on it.
- The preview/apply check is a read-before-write check. Unless an endpoint supports an atomic conditional update, another client can still change the record in the small interval between the final read and write.
- The server lock coordinates writes only inside this process. It does not serialize other MCP processes or Zammad administrators.
- A plan ID is not human consent. The assistant must show the preview and obtain explicit approval before calling apply. A host with a mandatory per-write approval mechanism is preferable.
- Creating or updating an object-manager attribute does not execute a database migration. Migration and restart operations are deliberately not included in generic writes.
- `email_notification` is a separate high-impact operation: applying it calls Zammad's configure endpoint, which sends a real test email and saves the settings in the same request. It must be separately approved.
- API token issuance/revocation, system-wide settings that are only documented through Rails console, authentication provider setup, and inbound mailbox configuration are not yet implemented. Do not claim full UI parity until each has a dedicated, reviewed workflow.
- Deleting users is intentionally excluded from generic writes because it can affect related ticket data. Deactivate users instead unless a separately reviewed privacy workflow is implemented.

## Setup

Copy `.env.example` to `.env` and set `ZAMMAD_URL` and `ZAMMAD_HTTP_TOKEN`. Remote instances must use HTTPS; plain HTTP is accepted only for localhost or loopback addresses.

Install and run:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e .
zammad-admin-mcp
```

Configure the MCP client with the absolute path to `.venv/bin/zammad-admin-mcp` and this project's working directory. Keep the token in the process environment or the ignored local `.env` file; never copy it into client configuration or Git.

## Main tools

- `zammad_server_version`
- `zammad_list_admin_resources`
- `zammad_list_admin_resource(resource)`
- `zammad_get_admin_object(resource, object_id)`
- `zammad_get_knowledge_base(knowledge_base_id)` and `zammad_get_knowledge_base_permissions(knowledge_base_id)`
- `zammad_get_knowledge_base_record(knowledge_base_id, kind, record_id, translation_id)`
- `zammad_prepare_admin_change(resource, operation, data, object_id, acknowledge_high_impact)`
- `zammad_prepare_knowledge_base_settings_change(knowledge_base_id, data, acknowledge_high_impact)`
- `zammad_prepare_knowledge_base_record_change(knowledge_base_id, kind, operation, data, record_id, acknowledge_high_impact)`
- `zammad_apply_admin_change(plan_id, acknowledge_high_impact)`
- Legacy readers: `zammad_list_groups`, `zammad_list_roles`, `zammad_list_roles_expanded`, `zammad_list_calendars`, `zammad_list_slas`, `zammad_list_triggers`, `zammad_list_ticket_states`

Prepare is read-only. Apply is the only generic write tool. It consumes the plan even when the request fails, so inspect Zammad before retrying an uncertain operation. Destructive and high-impact changes require an additional acknowledgement field, but that field is not a substitute for explicit user approval.

## Security and behavior

The server follows no HTTP redirects, refuses non-HTTPS remote endpoints, validates IDs, emits generic API error messages without response bodies, and only sends requests to registered paths. Secret-like fields are redacted recursively from results and previews. No request payloads are logged.

For a currently unimplemented admin area, add a fixed endpoint/resource definition and its specific side-effect, payload, secret, and rollback rules. Never add a caller-controlled path, method, or raw HTTP proxy.

## References

- [Zammad REST API introduction](https://docs.zammad.org/en/latest/api/intro.html)
- [Object manager API and migration warning](https://docs.zammad.org/en/latest/api/object.html)
- [Outbound email API and live test-email behavior](https://docs.zammad.org/en/pre-release/api/email-notification.html)
- See `ADMIN_COVERAGE.md` for the area-by-area coverage inventory.
