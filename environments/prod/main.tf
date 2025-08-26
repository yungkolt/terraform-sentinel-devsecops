terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  required_version = ">= 1.5.0"
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    log_analytics_workspace {
      permanently_delete_on_destroy = false
    }
  }
}

# =============================================================================
# PRODUCTION ENVIRONMENT RESOURCES
# =============================================================================

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# Deploy Log Analytics Workspace
module "log_analytics" {
  source = "../../modules/log-analytics"

  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  workspace_name      = var.workspace_name
  retention_in_days   = var.retention_in_days
  daily_quota_gb      = var.daily_quota_gb
  tags                = var.tags

  # Production-grade solutions
  solutions = [
    "Security",
    "SecurityInsights",
    "AzureActivity",
    "Updates",
    "VMInsights",
    "ServiceMap"
  ]
}

# Deploy Microsoft Sentinel
module "sentinel" {
  source = "../../modules/sentinel"

  workspace_id = module.log_analytics.workspace_id
  location     = azurerm_resource_group.main.location
  enable_ueba  = var.enable_ueba
}

# Deploy Sentinel Security Content
module "sentinel_content" {
  source = "../../modules/sentinel-content"

  workspace_id = module.sentinel.workspace_id
}
