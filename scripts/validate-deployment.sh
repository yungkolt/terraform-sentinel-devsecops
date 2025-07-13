#!/bin/bash

# Validate Terraform deployment

set -e

echo "🔍 Validating Terraform deployment..."

# Check Terraform is installed
if ! command -v terraform &> /dev/null; then
    echo "❌ Terraform is not installed"
    exit 1
fi

# Check Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI is not installed"
    exit 1
fi

# Format check
echo "📝 Checking Terraform formatting..."
terraform fmt -check -recursive

# Validate each module
for module in modules/*/; do
    echo "✅ Validating $module"
    terraform -chdir="$module" init -backend=false
    terraform -chdir="$module" validate
done

echo "✅ All validations passed!"
