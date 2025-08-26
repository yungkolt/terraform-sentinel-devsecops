variable "resource_group_name" {
  description = "Resource group name for production environment"
  type        = string
  default     = "rg-sentinel-prod"

  validation {
    condition     = length(var.resource_group_name) <= 90
    error_message = "Resource group name must be 90 characters or less."
  }
}

variable "location" {
  description = "Azure region for production resources"
  type        = string
  default     = "eastus"

  validation {
    condition = contains([
      "eastus", "eastus2", "westus", "westus2", "westus3",
      "centralus", "southcentralus", "westcentralus",
      "northeurope", "westeurope", "uksouth", "ukwest",
      "southeastasia", "eastasia", "australiaeast", "australiasoutheast"
    ], var.location)
    error_message = "Location must be a valid Azure region."
  }
}

variable "workspace_name" {
  description = "Log Analytics workspace name for production"
  type        = string
  default     = "law-sentinel-prod"

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]{2,61}[a-zA-Z0-9]$", var.workspace_name))
    error_message = "Workspace name must be 4-63 characters, start and end with alphanumeric, and contain only alphanumeric and hyphens."
  }
}

variable "retention_in_days" {
  description = "Log retention days for compliance requirements"
  type        = number
  default     = 90

  validation {
    condition     = var.retention_in_days >= 30 && var.retention_in_days <= 730
    error_message = "Retention must be between 30 and 730 days."
  }
}

variable "daily_quota_gb" {
  description = "Daily ingestion quota in GB (production workload)"
  type        = number
  default     = 10

  validation {
    condition     = var.daily_quota_gb >= 1
    error_message = "Daily quota must be at least 1 GB."
  }
}

variable "enable_ueba" {
  description = "Enable User Entity Behavior Analytics for advanced threat detection"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Resource tags for production environment"
  type        = map(string)
  default = {
    Environment  = "Production"
    ManagedBy    = "Terraform"
    Project      = "Sentinel-DevSecOps"
    BusinessUnit = "Security"
    CostCenter   = "Security-001"
    Criticality  = "High"
    DataClass    = "Internal"
    Compliance   = "SOC2"
  }

  validation {
    condition     = contains(keys(var.tags), "Environment")
    error_message = "Tags must include 'Environment' key."
  }
}
