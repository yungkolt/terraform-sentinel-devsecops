variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "workspace_name" {
  description = "Name of the Log Analytics workspace"
  type        = string
}

variable "retention_in_days" {
  description = "Workspace data retention in days"
  type        = number
  default     = 90
}

variable "sku" {
  description = "SKU for Log Analytics workspace"
  type        = string
  default     = "PerGB2018"
}

variable "daily_quota_gb" {
  description = "Daily ingestion quota in GB (-1 for unlimited)"
  type        = number
  default     = -1
}

variable "solutions" {
  description = "List of solutions to enable"
  type        = list(string)
  default     = ["Security", "SecurityInsights"]
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
