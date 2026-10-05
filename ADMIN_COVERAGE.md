# Zammad Admin MCP coverage

Goal: expose the full Zammad administration surface for reading and configuration writes. This file tracks API-backed coverage; a family is not complete until its endpoints and payloads are checked against the installed Zammad 7.1.2 instance.

## Current source tools

The original live tool registry was read-only: server version, groups, roles, expanded roles, calendars, SLAs, ticket states, and triggers. The local source now also defines a generic but fixed-resource reader and staged create/update/delete tools for the resources below. This source change has not yet been loaded into the running MCP process.

## Coverage inventory

| Admin area | Read | Write | Notes / required safeguards |
|---|---|---|---|
| Groups, roles, permissions, memberships | Read + staged CRUD | Staged CRUD | Preserve the confirmed Admin-equivalent `Codex-Zammad-Anpassung` role. Role changes can alter administrative access. |
| Checklist templates, tag administration, audit log | Checklist templates and tags read; audit log endpoint unavailable (HTTP 404) | Staged CRUD for templates/tags | The two collection reads were verified on 7.1.2 (0 checklist templates, 1 tag); audit log route `/audit_logs` returned 404. Deleting/renaming shared definitions can affect agent workflows and categorization. |
| Users / agents / organizations | Read + staged CRUD | Staged CRUD | Deletions are explicitly high impact because they can affect related records and access. |
| Ticket states and priorities | Read + staged CRUD | Staged CRUD | Other ticket data is intentionally outside this admin resource registry. Check references before deleting values. |
| Calendars and SLAs | Read + staged CRUD | Staged CRUD | Validate cross-resource dependencies and time-zone/business-hour payloads. |
| Triggers, macros, overviews, text modules, templates, core workflows, report profiles | Read + staged CRUD | Staged CRUD | Trigger bodies can send mail or invoke external services in future events; every change requires explicit approval. `/schedulers` returned HTTP 404 on the installed 7.1.2 instance. |
| Object manager | Read + staged create/update | Staged create/update | High risk: schema changes can affect data. Migration endpoint and restart are deliberately not exposed. |
| Outbound sender addresses and notification SMTP | Read + staged CRUD / special configure | Staged writes | Notification configure sends a real test email while saving. Mailbox/inbound channel configuration is not implemented: the public API docs distinguish it from notification mail but do not document a stable endpoint contract. |
| Webhooks | Read + staged CRUD | Staged CRUD | Secret fields are redacted; changes can enable future external calls. |
| Authentication, SSO/LDAP, API tokens | Partial (user records and token metadata) | Staged update of a specific setting; token revocation staged | Zammad's Settings REST controller is used by the Admin UI, but has no current official API contract in the public docs; `/settings` must be verified live against 7.1.2 before relying on it. Updates require matching setting name and ID and replace only `state_current.value`. Token creation returns a generated one-time secret that cannot be retrieved later; no secure one-time delivery channel is implemented. |
| Knowledge base | Read by KB ID, permissions, answer and category records | Staged update/CRUD | Uses dedicated nested routes and requires caller-supplied IDs. The current instance's KB 1 has no answer/category records. Public content writes require explicit confirmation. |
| System settings and other UI-only admin controls | Partial read/write through fixed `/settings` resource | Staged update only | REST route used by Zammad's Admin UI, not a documented/version-pinned API contract; validate every target setting in 7.1.2. Updates are high impact and require explicit confirmation. No Rails-console or arbitrary command bridge is exposed. External SSO proxy/IdP configuration is outside Zammad's REST API. |

## Live 7.1.2 endpoint spot-check

Version returned `7.1.2-bbc6460a.docker`. These GET checks streamed and discarded response bodies; only statuses were retained: version, ticket priorities, macros, overviews, templates, text modules, core workflows, report profiles, webhooks, email addresses, organizations, users, object manager attributes, user access token metadata, roles with expansion, and `/channels_email` returned HTTP 200. `/schedulers`, `/knowledge_bases`, `/knowledge_base_categories`, `/knowledge_base_answers`, and `/knowledge_bases/1/answers` collection returned HTTP 404. `/knowledge_bases/1` and `/knowledge_bases/1/permissions` returned HTTP 200. No API writes were made.

## Remaining scope gaps

The MCP does not yet provide a complete replacement for every Admin UI function. In particular, there is no documented, version-pinned REST contract for LDAP/SSO provider setup or inbound mailbox channels. These cannot be safely completed through guessed endpoints or a general Rails-console bridge. A fixed `/settings` resource has been added based on the Settings REST controller used by the Admin UI, but it is not considered verified until its read/preview/apply behavior is checked against the installed 7.1.2 instance. The generic CRUD registry covers the API-backed resources listed above; each route still needs live verification before it can be described as fully supported.

Access-token creation remains unavailable because Zammad returns the newly generated secret once and cannot retrieve it again. The current secret-handling policy does not provide a secure one-time delivery surface; token metadata can be read and token revocation is staged.

## Write contract

1. Use a fixed server-side registry of resource kinds, methods, and paths. Never accept an arbitrary URL, HTTP method, or endpoint path from a tool caller. Payload schemas remain endpoint-specific follow-up work; validate endpoint behavior against the installed version.
2. Separate preview from apply. Preview reads the current object, validates the requested change, and returns a redacted before/after diff plus a short-lived plan identifier and state fingerprint.
3. Apply requires the plan identifier, re-reads the object, rejects stale fingerprints, and uses only the method/path from the registry. A read-before-write check is not atomic unless the installed endpoint supports conditional writes; report this limitation.
4. Human approval must be enforced by the MCP host/client after preview. A `confirmed` boolean or plan identifier alone does not prove user consent.
5. Separate destructive, credential, email-delivery, authentication, and migration operations into explicit tools with operation-specific warnings and confirmation. Do not retry a write whose outcome is uncertain.
6. Never return stored secret values. For credentials, expose only whether a value is configured and accept replacement input only in the write path. Redact request/response bodies from errors and logs.

## Version verification references

Official documentation describes a broad REST API, but the `latest` and `pre-release` pages are not proof that an endpoint or payload is available in the installed 7.1.2 instance. Verify every route and field against that instance before enabling it.

- API overview: https://docs.zammad.org/en/latest/api/intro.html
- Admin API navigation: https://docs.zammad.org/en/latest/
- Groups: https://docs.zammad.org/en/latest/api/group.html
- Object manager: https://docs.zammad.org/en/latest/api/object.html
- Roles: https://docs.zammad.org/en/pre-release/api/role.html
- Triggers: https://docs.zammad.org/en/pre-release/api/trigger.html
- Outbound email: https://docs.zammad.org/en/pre-release/api/email-notification.html
