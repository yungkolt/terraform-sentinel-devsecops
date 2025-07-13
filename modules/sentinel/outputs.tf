output "workspace_id" {
  description = "Sentinel-enabled workspace ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
}
