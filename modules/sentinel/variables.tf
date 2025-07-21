variable "workspace_id" {
  description = "Log Analytics Workspace ID"
  type        = string
}

variable "location" {
  description = "Azure region for workbook deployment"
  type        = string
  default     = "eastus"
}

variable "enable_ueba" {
  description = "Enable User Entity Behavior Analytics"
  type        = bool
  default     = true
}

variable "enable_data_connectors" {
  description = "Data connectors to enable"
  type = object({
    azure_activity     = bool
    azure_ad          = bool
    office_365        = bool
    defender_for_cloud = bool
  })
  default = {
    azure_activity     = true
    azure_ad          = true
    office_365        = true
    defender_for_cloud = true
  }
}
