variable "workspace_id" {
  description = "Log Analytics Workspace ID for Sentinel"
  type        = string
}

variable "enable_detection_rules" {
  description = "Enable deployment of detection rules"
  type        = bool
  default     = true
}

variable "rule_severity_threshold" {
  description = "Minimum severity level for deployed rules"
  type        = string
  default     = "Medium"

  validation {
    condition     = contains(["Low", "Medium", "High", "Critical"], var.rule_severity_threshold)
    error_message = "Severity threshold must be one of: Low, Medium, High, Critical."
  }
}
