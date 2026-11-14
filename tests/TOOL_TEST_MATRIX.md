# Actual MCP tool test matrix

Registry and object-schema checks below were performed through a real local stdio subprocess. No ContextForge or Zammad API endpoint was contacted. Schema checks establish top-level object shape, not exhaustive input-domain validation. All administrative live writes remain unverified.

| Tool | stdio discovery | Object schema | Functional evidence | Live API / ContextForge |
|---|---|---|---|---|
| `zammad_server_version` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_exchange_integration_status` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_exchange_import_status` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_exchange_connection_action` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_exchange_import_action` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_calendar_timezones` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_report_configuration` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_generate_report_aggregates` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_report_ticket_preview` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_ai_analytics_summary` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_time_accounting_report` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_user_two_factor_methods` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_user_history` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_organization_history` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_user_two_factor_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_user_unlock` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_proxy_test` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_ticket_agent_notification_apply` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_pgp_status` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_pgp_key` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_admin_resources` | PASS | PASS | Real stdio call succeeds (local resource catalog) | NOT VERIFIED |
| `zammad_search_audit_logs` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_user_import` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_organization_import` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_http_logs` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_admin_resource` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_groups` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_roles` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_calendars` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_slas` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_triggers` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_ticket_states` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_roles_expanded` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_admin_object` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_ldap_import_action` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_ldap_import_status` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_ldap_connection_action` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_knowledge_bases` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_menu_items` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_order` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_attachments` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_publication_state` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_server_snippets` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_translation` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_knowledge_base_categories` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_permissions` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_category_permissions` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_list_customized_translations` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_search_translation_suggestions` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_monitoring_health` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_monitoring_action` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_object_manager_migrations` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_object_manager_discard_changes` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_session_action` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_data_privacy_deletion` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_oauth_application_token` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_package_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_ssl_certificate_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_crypto_material_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_translation_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_permissions_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_category_permissions_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_get_knowledge_base_record` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_translation_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_feed_token_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_settings_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_lifecycle_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_creation` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_deletion` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_menu_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_order_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_attachment_upload` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_attachment_delete` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_publication_transition` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_publication_schedule` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_knowledge_base_record_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_prepare_admin_change` | PASS | PASS | Not individually exercised | NOT VERIFIED |
| `zammad_apply_admin_change` | PASS | PASS | Real stdio invalid-plan rejection; synthetic expired/replay/stale/high-impact/queued-expiration and successful PUT tests | NOT VERIFIED |
