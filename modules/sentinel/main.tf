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
  workspace_id                 = var.workspace_id
  customer_managed_key_enabled = false
}

# Note: azurerm_sentinel_user_analytics_settings is not available in current Azure provider
# UEBA must be configured manually in the Azure portal or via REST API
# For demonstration purposes, we'll use a null_resource to document this requirement

resource "null_resource" "ueba_configuration" {
  count = var.enable_ueba ? 1 : 0
  
  triggers = {
    workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  }

  # This would typically call an Azure REST API or Azure CLI command
  # For now, it serves as documentation that UEBA needs manual configuration
  provisioner "local-exec" {
    command = "echo 'UEBA configuration required - configure manually in Azure portal or via REST API'"
  }
}
