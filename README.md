<div align="center">

<img width="1672" height="941" alt="Zammad Admin MCP" src="https://github.com/user-attachments/assets/221825e8-708e-4f35-992a-f9e6add9d24d" />

# Zammad Admin MCP

### Controlled administration interface between AI agents and Zammad

A Model Context Protocol server for secure, auditable and permission-aware Zammad administration workflows.

</div>

---

## Overview

Zammad Admin MCP provides a controlled interface for MCP-compatible AI clients to interact with selected Zammad administration resources.

The project is designed around one principle:

> AI systems may assist administration, but administrative control remains explicit, reviewable and bounded.

Instead of exposing unrestricted API access, Zammad Admin MCP introduces validation, preview workflows and controlled execution paths.

```text
AI Client
    |
    v
MCP Protocol
    |
    v
Zammad Admin MCP
    |
    +-- Resource Allowlist
    +-- Validation Layer
    +-- Preview / Approval Workflow
    +-- Secret Redaction
    +-- Audit-oriented Execution
    |
    v
Zammad API
```

---

# Design Goals

## Security by Design

Zammad Admin MCP intentionally avoids becoming a generic API proxy.

Implemented safeguards:

- allowlisted resources and operations
- controlled write workflows
- preview before apply
- explicit approval requirement
- recursive secret redaction
- no arbitrary URL forwarding
- no arbitrary HTTP method execution
- no direct Rails console access

The MCP server does not grant additional Zammad permissions. The configured API token remains the authority.

---

# Architecture

```mermaid
flowchart LR

A[AI Agent / MCP Client]
B[Zammad Admin MCP]
C[Validation & Approval]
D[Zammad REST API]

A --> B
B --> C
C --> D
```

The architecture separates intent, validation and execution.

Administrative operations are not executed merely because the MCP server is connected.

---

# Capabilities

## Read Operations

- server version detection
- allowlisted administration resources
- object inspection
- knowledge base access
- paginated collection reads

## Controlled Changes

Changes follow a prepare/apply workflow:

```text
Prepare Change
       |
       v
Generate Preview
       |
       v
Explicit Approval
       |
       v
Apply Change
```

Supported workflows include:

- create operations
- update operations
- selected delete operations
- selected high-impact configuration changes

---

# MCP Tools

Core:

- `zammad_server_version`
- `zammad_list_admin_resources`
- `zammad_list_admin_resource`
- `zammad_get_admin_object`
- `zammad_prepare_admin_change`
- `zammad_apply_admin_change`

Knowledge base:

- `zammad_get_knowledge_base`
- `zammad_get_knowledge_base_permissions`
- `zammad_get_knowledge_base_record`

Compatibility readers:

- groups
- roles
- calendars
- SLAs
- triggers
- ticket states

---

# Installation

```bash
git clone https://github.com/CyberG3niusIT/Zammad-Admin-MCP.git
cd Zammad-Admin-MCP

python -m venv .venv
. .venv/bin/activate
pip install -e .

zammad-admin-mcp
```

Configure the MCP client with the absolute path to the executable.

Store credentials only through environment variables or ignored local configuration.

---

# Limitations

Zammad Admin MCP does not claim complete Zammad UI coverage.

Currently outside the generic workflow:

- fully verified system settings writes: `/settings` returned 285 settings on the installed 7.1.2 server and a read-only preview succeeded, but no apply was performed
- API token creation: Zammad returns a generated token only once, and this MCP has no secure one-time delivery surface; metadata read and staged revocation are available
- validated LDAP/SSO settings apply behavior: the settings read/preview path covers these entries, but an apply was not performed
- inbound mailbox configuration: no documented, version-pinned REST contract was found
- unrestricted object manager migrations

New capabilities should receive dedicated workflows with defined permissions, validation and side effects.

---

# Development Principles

Every administrative capability should define:

- required permissions
- affected resources
- validation rules
- secret handling
- failure behavior
- rollback considerations

The objective is not maximum automation.

The objective is reliable automation.

---

# References

- [Zammad REST API](https://docs.zammad.org/en/latest/api/intro.html)
- [Object Manager API](https://docs.zammad.org/en/latest/api/object.html)
- [Email Notification API](https://docs.zammad.org/en/pre-release/api/email-notification.html)

See `ADMIN_COVERAGE.md` for detailed coverage information.

---

## License

Open source project by CyberG3niusIT.
