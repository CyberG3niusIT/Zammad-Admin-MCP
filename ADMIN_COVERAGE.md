# Zammad Admin MCP coverage

Goal: expose the full Zammad administration surface for reading and configuration writes. This file tracks API-backed coverage; a family is not complete until its endpoints and payloads are checked against the installed Zammad 7.1.2 instance.

## Current source tools

The original live tool registry was read-only: server version, groups, roles, expanded roles, calendars, SLAs, ticket states, and triggers. The running MCP now exposes a fixed-resource reader and staged configuration tools for the resources below.

## Coverage inventory

| Admin area | Read | Write | Notes / required safeguards |
|---|---|---|---|
| Groups, roles, permissions, memberships | Read + staged CRUD | Staged CRUD | Preserve the confirmed Admin-equivalent `Codex-Zammad-Anpassung` role. Role changes can alter administrative access. |
| Checklist templates, tag administration, audit log | Checklist templates and tags read; audit log endpoint unavailable (HTTP 404) | Staged CRUD for templates/tags | The two collection reads were verified on 7.1.2 (0 checklist templates, 1 tag); audit log route `/audit_logs` returned 404. Deleting/renaming shared definitions can affect agent workflows and categorization. |
| Users / agents / organizations | Read + staged CRUD | Staged CRUD | Deletions are explicitly high impact because they can affect related records and access. |
| Ticket states and priorities | Read + staged CRUD | Staged CRUD | Other ticket data is intentionally outside this admin resource registry. Check references before deleting values. |
| Calendars and SLAs | Read + staged CRUD | Staged CRUD | Validate cross-resource dependencies and time-zone/business-hour payloads. |
| Triggers, macros, overviews, text modules, templates, signatures, core workflows, report profiles | Read + staged CRUD | Staged CRUD | Trigger bodies can send mail or invoke external services in future events; every change requires explicit approval. `/schedulers` returned HTTP 404 on the installed 7.1.2 instance. |
| Object manager | Read + staged create/update | Staged create/update | High risk: schema changes can affect data. Migration endpoint and restart are deliberately not exposed. |
| Outbound sender addresses, notification SMTP, inbound mailbox | Read + staged CRUD / special configure | Staged configure, enable, disable, delete, and group reassignment | `email_account` uses `POST /channels_email_verify`: verifies inbound/outbound, sends a test message, saves on success, and begins mail fetching. High impact; no apply was performed. Routes verified against exact Zammad 7.1.2 source. |
| Other messaging channels (web, chat, Google/Microsoft mail, SMS, Facebook, Telegram, WhatsApp) | Web settings by `CustomerWeb::Base` area; sanitized channel inventory; direct SMS, Telegram, WhatsApp, Facebook, Google, Microsoft 365, and Microsoft Graph reads | Staged Web setting updates; staged Facebook page group mappings and lifecycle changes; staged Google and Microsoft mailbox group, folder, archive, sender-address, lifecycle, mailbox-probe, and available migration-rollback actions; staged SMS, Telegram, and WhatsApp CRUD, enable/disable, plus SMS test and WhatsApp preload | Web Admin UI uses the same `/settings` collection and filters `CustomerWeb::Base` settings in the client. The MCP applies this area filter after sensitive-value projection; writes still require setting ID/name matching, preview, approval, and stale checks. Reads omit linked User/Organization assets and diagnostic logs and redact credential fields. SMS tests send real messages; Massenversand test is blocked because its error path can expose provider credentials. Telegram updates set an external webhook; WhatsApp verifies provider data. Google/Microsoft config uses version-pinned verify routes; these reset inbound/outbound status to `ok` and clear prior channel logs. Staged mailbox probes refresh OAuth access and read the mailbox, but return only success and content-message count, never message or diagnostic contents. Google and Microsoft 365 migration rollback restores Zammad's stored legacy IMAP snapshot; the preview exposes only restored area/status, not configuration secrets. Sender-address changes require explicit fields in a configure plan and are checked against the selected channel's addresses. Creating OAuth-linked accounts still requires Zammad's browser session and callback. |
| Webhooks | Read + staged CRUD | Staged CRUD | Secret fields are redacted; changes can enable future external calls. |
| Authentication, SSO/LDAP, API tokens | Partial (user records and token metadata) | Staged update of a specific setting; token creation and revocation staged | Zammad's Settings REST controller is used by the Admin UI, but has no current official API contract in the public docs; `/settings` must be verified live against 7.1.2 before relying on it. Updates require matching setting name and ID and replace only `state_current.value`. Token creation validates active permission names against the live token endpoint and stores the one-time secret in an exclusive owner-only local file (`0600`) beneath a private (`0700`) directory; only the path and metadata are returned. This is not an encrypted keyring. |
| Jobs | Read and staged CRUD | Staged CRUD | The installed 7.1.2 job response was inspected without exposing condition/action values. The schema limits job definition fields and validates timeplan, object-bound conditions, and actions. Every write is high impact because scheduled runs can change records in bulk. No write was applied. |
| LDAP sources and imports | Read + staged CRUD + staged import status | Staged CRUD with a complete wizard-shaped preference object; staged connection discovery and bind checks; staged dry-run and sync-job actions | Fields and preference keys were inspected in the installed 7.1.2 controller, model, and Admin UI wizard. `preferences.bind_pw` is sensitive and must use a process environment reference or be blank for anonymous bind; partial updates preserve the stored secret through Zammad's mask contract. Role mappings are checked against active roles and included in stale-state checks. Dry-run submits only stored active sources and creates an import-job result without applying user or role changes; sync requires the global LDAP integration setting and can create, update, or deactivate users and change roles. No write was applied. |
| External credentials | Read-only metadata and staged create/update/delete | Staged CRUD; Google and Microsoft require both client ID and client secret; Facebook `application_secret` and provider `client_secret` values accept process environment references only | Current 7.1.2 endpoint and provider UI fields were inspected without displaying stored values. The staged payload validates provider-specific required fields; API responses redact `credentials`. Credential replacement/deletion can affect integrations. OAuth account linking and callbacks remain separate workflows. No API write was applied. |
| Postmaster filters | Read-only fixed resource; current app registry needs reload | Staged CRUD | Endpoint schema restricts fields and match operators. Rules change inbound email routing and ticket creation/update; every change is high impact. Zammad remains the final validator for dynamic action keys and regex semantics. |
| Public links | Read-only fixed resource; current app registry needs reload | Staged CRUD | Payload validation follows the 7.1.2 model (`link`, `title`, `screen`, optional `prio`); `screen` is a non-empty list selected from login, signup, and password reset. High-impact preview calls out public redirects, and URLs must be absolute HTTP(S) without embedded credentials. No write has been applied. |
| Chat configuration | Read-only fixed resource; current app registry needs reload | Staged CRUD | Endpoint-specific schema accepts `name`, `note` (max 250), and JSON-object `preferences`. The server validates persisted configuration; preview is high impact. Deleting a chat cascades to its sessions. No write has been applied. |
| Knowledge base | Read by KB ID, permissions, answer and category records | Staged update/CRUD | Uses dedicated nested routes and requires caller-supplied IDs. The current instance's KB 1 has no answer/category records. Public content writes require explicit confirmation. |
| System settings and other UI-only admin controls | Read by settings area; product-logo metadata read | Staged setting updates and reset-to-initial actions, plus staged product-logo upload | `/settings` is used by Zammad Admin UI. Updates and resets require setting ID snapshots, secret-safe previews, approval, and stale checks. Product-logo upload uses the fixed `PUT /settings/image/:id` route, validates image data URL MIME/base64/size and returns no image payload. External SSO proxy/IdP configuration is outside Zammad's REST API. |

## Live 7.1.2 endpoint spot-check

Version returned `7.1.2-bbc6460a.docker`. These GET checks streamed and discarded response bodies; only statuses were retained: version, ticket priorities, macros, overviews, templates, text modules, core workflows, report profiles, webhooks, email addresses, organizations, users, object manager attributes, user access token metadata, roles with expansion, and `/channels_email` returned HTTP 200. `/schedulers`, `/knowledge_bases`, `/knowledge_base_categories`, `/knowledge_base_answers`, and `/knowledge_bases/1/answers` collection returned HTTP 404. `/knowledge_bases/1` and `/knowledge_bases/1/permissions` returned HTTP 200. No API writes were made.

## Remaining scope gaps

The MCP does not yet provide a complete replacement for every Admin UI function. A fixed `/settings` resource supports reads and staged updates; route read and preview were verified against the installed 7.1.2 instance, but apply was not performed. Email mailbox route and controller behavior are verified against exact 7.1.2 source, while applying a configuration remains untested. Facebook page mapping and lifecycle actions plus SMS, Telegram, WhatsApp, public links, chats, postmaster filters, jobs, LDAP sources, imports, and external credentials have endpoint-specific staged schemas and previews; their writes have not been applied against Zammad. LDAP discovery and bind checks, dry-run imports, and sync jobs require their own prepared high-impact plans. The local server registry still needs a reload before newly added tools can be confirmed there. OAuth account linking still requires the browser callback flow. No arbitrary Rails-console bridge is exposed.

Access-token creation is staged and never returns the generated secret in MCP output. The file store defaults to `~/.config/zammad-admin-mcp/tokens`; `ZAMMAD_TOKEN_STORE_DIR` can select another absolute path outside the project. Directories are traversed without following symlinks, the final directory must belong to the MCP user with mode `0700`, and each new token file is created without overwrite using mode `0600`. A local file is not encrypted; protect host backups and storage accordingly. If Zammad creates a token but local storage fails, do not retry creation: inspect token metadata and revoke the possibly active token.

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
- Zammad 7.1.2 email channel routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/channel_email.rb
- Zammad 7.1.2 email channel controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/channels_email_controller.rb
- Zammad 7.1.2 public-link routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/public_link.rb
- Zammad 7.1.2 public-link model: https://github.com/zammad/zammad/blob/7.1.2/app/models/public_link.rb
- Zammad 7.1.2 chat routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/chat.rb
- Zammad 7.1.2 chat model: https://github.com/zammad/zammad/blob/7.1.2/app/models/chat.rb
- Zammad 7.1.2 postmaster-filter routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/postmaster_filter.rb
- Zammad 7.1.2 postmaster-filter model: https://github.com/zammad/zammad/blob/7.1.2/app/models/postmaster_filter.rb
- Zammad 7.1.2 LDAP-source routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/ldap_source.rb
- Zammad 7.1.2 LDAP integration routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/integration_ldap.rb
- Zammad 7.1.2 LDAP-source controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/ldap_sources_controller.rb
- Zammad 7.1.2 LDAP-source model: https://github.com/zammad/zammad/blob/7.1.2/app/models/ldap_source.rb
- Zammad 7.1.2 LDAP configuration wizard: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_integration/ldap.coffee
- Zammad 7.1.2 job routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/job.rb
- Zammad 7.1.2 job model: https://github.com/zammad/zammad/blob/7.1.2/app/models/job.rb
- Zammad 7.1.2 external-credential routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/external_credentials.rb
- Zammad 7.1.2 external-credential controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/external_credentials_controller.rb
- Zammad 7.1.2 Facebook channel routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/channel_facebook.rb
- Zammad 7.1.2 Facebook channel controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/channels_facebook_controller.rb
- Zammad 7.1.2 Facebook channel settings UI: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_channel/facebook.coffee
- Zammad 7.1.2 Google channel routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/google.rb
- Zammad 7.1.2 Google channel controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/channels_google_controller.rb
- Zammad 7.1.2 Google channel form: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_channel/google.coffee
- Zammad 7.1.2 Web channel settings UI: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_channel/web.coffee
- Zammad 7.1.2 settings routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/setting.rb
- Zammad 7.1.2 settings controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/settings_controller.rb
- Zammad 7.1.2 product-logo settings UI: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_settings/area_logo.coffee
- Zammad 7.1.2 product-logo storage service: https://github.com/zammad/zammad/blob/7.1.2/lib/service/system_assets/product_logo.rb
- Zammad 7.1.2 Microsoft 365 channel routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/microsoft365.rb
- Zammad 7.1.2 Microsoft 365 channel controller and form: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_channel/microsoft365.coffee
- Zammad 7.1.2 Microsoft Graph channel routes: https://github.com/zammad/zammad/blob/7.1.2/config/routes/channel_microsoft_graph.rb
- Zammad 7.1.2 Microsoft Graph channel form: https://github.com/zammad/zammad/blob/7.1.2/app/assets/javascripts/app/controllers/_channel/microsoft_graph.coffee
- Zammad 7.1.2 Microsoft channel controller concern: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/concerns/can_xoauth2_email_channel.rb
- Zammad 7.1.2 Microsoft Graph admin controller: https://github.com/zammad/zammad/blob/7.1.2/app/controllers/channels_admin/microsoft_graph_controller.rb
