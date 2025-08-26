terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Data source to reference the Sentinel onboarding
data "azurerm_sentinel_log_analytics_workspace_onboarding" "main" {
  workspace_id = var.workspace_id
}

# All detection rules are now in detection-rules.tf
# This main.tf file serves as the module entry point and can include
# additional Sentinel content resources as they become available
