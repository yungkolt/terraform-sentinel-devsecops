# =============================================================================
# TERRAFORM BACKEND CONFIGURATION - STAGING
# =============================================================================

terraform {
  backend "azurerm" {
    resource_group_name   = "rg-terraform-state"
    storage_account_name  = "tfstatesentinelstaging"
    container_name        = "tfstate"
    key                   = "staging.terraform.tfstate"
    use_azuread_auth     = true
    encrypt              = true
  }
}
