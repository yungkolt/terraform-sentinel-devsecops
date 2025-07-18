terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  backend "azurerm" {
    # Configure your backend here
    # resource_group_name  = "terraform-state-rg"
    # storage_account_name = "tfstate${var.org_name}"
    # container_name       = "tfstate"
    # key                  = "sentinel-prod.terraform.tfstate"
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# Deploy Log Analytics
module "log_analytics" {
  source = "../../modules/log-analytics"

  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  workspace_name      = var.workspace_name
  retention_in_days   = var.retention_in_days
  daily_quota_gb      = var.daily_quota_gb
  tags                = var.tags

  solutions = [
    "Security",
    "SecurityInsights",
    "AzureActivity",
    "Updates",
    "VMInsights"
  ]
}

# Deploy Sentinel
module "sentinel" {
  source = "../../modules/sentinel"

  workspace_id = module.log_analytics.workspace_id
  enable_ueba  = true
}
