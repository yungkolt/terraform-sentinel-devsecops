terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Enable Sentinel
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id = var.workspace_id
}

# Configure UEBA
resource "azurerm_sentinel_user_analytics_settings" "this" {
  count = var.enable_ueba ? 1 : 0
  
  workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  enabled      = true
}
