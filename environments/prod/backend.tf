# =============================================================================
# TERRAFORM BACKEND CONFIGURATION - PRODUCTION
# =============================================================================
# This file configures remote state storage in Azure Storage Account
# Ensures state locking, encryption, and team collaboration

terraform {
  backend "azurerm" {
    resource_group_name   = "rg-terraform-state"
    storage_account_name  = "tfstatesentinelprod"
    container_name        = "tfstate"
    key                   = "prod.terraform.tfstate"
    use_azuread_auth     = true  # Use Azure AD for authentication
    encrypt              = true  # Encrypt state file at rest
  }
}

# Note: Backend configuration cannot use variables
# Storage account must be created before first terraform init
# See DEPLOYMENT.md for setup instructions
