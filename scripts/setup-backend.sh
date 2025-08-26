#!/bin/bash

# =============================================================================
# TERRAFORM BACKEND SETUP SCRIPT
# =============================================================================
# This script creates Azure Storage accounts for Terraform remote state
# Run this once before deploying any environments

set -e

# Configuration
RESOURCE_GROUP="rg-terraform-state"
LOCATION="eastus"
ENVIRONMENTS=("dev" "staging" "prod")

echo "🔧 Setting up Terraform backend infrastructure..."

# Check if Azure CLI is installed and logged in
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI is not installed. Please install it first."
    exit 1
fi

if ! az account show &> /dev/null; then
    echo "❌ Not logged into Azure. Please run 'az login' first."
    exit 1
fi

# Get current subscription info
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SUBSCRIPTION_NAME=$(az account show --query name -o tsv)

echo "📋 Using subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"

# Create resource group for Terraform state
echo "📁 Creating resource group: $RESOURCE_GROUP"
az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --tags "Purpose=TerraformState" "ManagedBy=Script" \
    --output table

# Create storage accounts for each environment
for env in "${ENVIRONMENTS[@]}"; do
    STORAGE_ACCOUNT="tfstatesentinel${env}"
    
    echo "💾 Creating storage account: $STORAGE_ACCOUNT"
    
    # Create storage account
    az storage account create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$STORAGE_ACCOUNT" \
        --sku Standard_LRS \
        --encryption-services blob \
        --https-only true \
        --min-tls-version TLS1_2 \
        --allow-blob-public-access false \
        --tags "Environment=$env" "Purpose=TerraformState" \
        --output table
    
    # Create container for Terraform state
    echo "📦 Creating container: tfstate"
    az storage container create \
        --name "tfstate" \
        --account-name "$STORAGE_ACCOUNT" \
        --auth-mode login \
        --output table
    
    # Enable versioning for state file protection
    echo "🔄 Enabling blob versioning..."
    az storage account blob-service-properties update \
        --account-name "$STORAGE_ACCOUNT" \
        --enable-versioning true \
        --output none
        
    echo "✅ Storage account $STORAGE_ACCOUNT configured successfully"
done

echo ""
echo "🎉 Backend setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Ensure you have appropriate RBAC permissions on the storage accounts"
echo "2. Run 'terraform init' in each environment directory"
echo "3. The backend configurations are in environments/*/backend.tf"
echo ""
echo "🔒 Storage accounts created:"
for env in "${ENVIRONMENTS[@]}"; do
    echo "  - tfstatesentinel${env} (${env} environment)"
done

echo ""
echo "⚠️  Important: These storage accounts contain sensitive Terraform state."
echo "   Ensure proper access controls and backup procedures are in place."
