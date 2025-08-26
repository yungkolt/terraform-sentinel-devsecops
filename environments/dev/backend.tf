# =============================================================================
# TERRAFORM BACKEND CONFIGURATION - DEVELOPMENT
# =============================================================================

terraform {
  backend "azurerm" {
    resource_group_name   = "rg-terraform-state"
    storage_account_name  = "tfstatesentineldev"
    container_name        = "tfstate"
    key                   = "dev.terraform.tfstate"
    use_azuread_auth     = true
    encrypt              = true
  }
}
