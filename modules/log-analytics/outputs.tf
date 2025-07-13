output "workspace_id" {
  description = "The Log Analytics Workspace ID"
  value       = azurerm_log_analytics_workspace.this.id
}

output "workspace_customer_id" {
  description = "The Log Analytics Workspace customer ID"
  value       = azurerm_log_analytics_workspace.this.workspace_id
}

output "primary_shared_key" {
  description = "The primary shared key for the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.this.primary_shared_key
  sensitive   = true
}
