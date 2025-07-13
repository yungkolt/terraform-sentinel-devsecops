output "workspace_id" {
  description = "Log Analytics Workspace ID"
  value       = module.log_analytics.workspace_id
}

output "sentinel_workspace_id" {
  description = "Sentinel Workspace ID"
  value       = module.sentinel.workspace_id
}
