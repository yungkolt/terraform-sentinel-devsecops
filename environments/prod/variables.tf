variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "rg-sentinel-prod"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "workspace_name" {
  description = "Log Analytics workspace name"
  type        = string
  default     = "law-sentinel-prod"
}

variable "retention_in_days" {
  description = "Log retention days"
  type        = number
  default     = 90
}

variable "daily_quota_gb" {
  description = "Daily quota in GB"
  type        = number
  default     = 10
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Project     = "Sentinel-DevSecOps"
  }
}
