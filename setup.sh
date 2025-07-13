#!/bin/bash

# Setup script for terraform-sentinel-devsecops repository
# This script creates the complete project structure

set -e

echo "🚀 Setting up Terraform Sentinel DevSecOps Project"
echo "================================================"

# Check if git is initialized
if [ ! -d .git ]; then
    echo "Initializing git repository..."
    git init
fi

# Create directory structure
echo "📁 Creating directory structure..."

# Root directories
mkdir -p modules/{log-analytics,sentinel,sentinel-content,monitoring}
mkdir -p modules/sentinel-content/{detection-rules,incident-response,threat-intelligence}
mkdir -p environments/{dev,staging,prod}
mkdir -p scripts
mkdir -p tests/{kql-queries,terraform}
mkdir -p .github/workflows

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Local .terraform directories
**/.terraform/*

# .tfstate files
*.tfstate
*.tfstate.*

# Crash log files
crash.log
crash.*.log

# Exclude all .tfvars files, which are likely to contain sensitive data
*.tfvars
*.tfvars.json

# Ignore override files
override.tf
override.tf.json
*_override.tf
*_override.tf.json

# Include override files you do wish to add to version control using negated pattern
# !example_override.tf

# Include tfplan files to ignore the plan output of command: terraform plan -out=tfplan
*tfplan*

# Ignore CLI configuration files
.terraformrc
terraform.rc

# Ignore Mac .DS_Store files
.DS_Store

# Ignore editor files
.vscode/
.idea/
*.swp
*.swo

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/

# Logs
logs/
*.log

# Secrets
*.pem
*.key
secrets/
.env

# Terraform lock files (optional - you may want to commit these)
# .terraform.lock.hcl
EOF

# Create README.md
echo "📝 Creating README.md..."
cat > README.md << 'EOF'
# Terraform Sentinel DevSecOps

This repository contains Infrastructure as Code (IaC) for deploying and managing Azure Sentinel and Log Analytics with a DevSecOps approach.

## 🏗️ Architecture

```
terraform-sentinel-devsecops/
├── modules/                    # Reusable Terraform modules
│   ├── log-analytics/         # Log Analytics workspace configuration
│   ├── sentinel/              # Sentinel enablement and configuration
│   ├── sentinel-content/      # Detection rules and playbooks
│   └── monitoring/            # Monitoring and alerting
├── environments/              # Environment-specific configurations
│   ├── dev/
│   ├── staging/
│   └── prod/
├── scripts/                   # Helper scripts
├── tests/                     # Test files
└── .github/                   # GitHub Actions workflows
```

## 🚀 Getting Started

### Prerequisites

- Terraform >= 1.5.0
- Azure CLI >= 2.50.0
- PowerShell Core >= 7.0
- An Azure subscription with appropriate permissions

### Quick Start

1. Clone this repository
2. Configure Azure credentials:
   ```bash
   az login
   az account set --subscription "YOUR_SUBSCRIPTION_ID"
   ```

3. Initialize Terraform:
   ```bash
   cd environments/dev
   terraform init
   ```

4. Create a `terraform.tfvars` file with your configuration
5. Plan and apply:
   ```bash
   terraform plan
   terraform apply
   ```

## 📋 Modules

### Log Analytics Module
Configures Log Analytics workspace with:
- Retention policies
- Archive settings
- Solutions (Security, Updates, etc.)
- Data sources configuration
- Automation account integration

### Sentinel Module
Enables and configures Microsoft Sentinel with:
- Data connectors (Azure AD, Office 365, etc.)
- Analytics rules
- Hunting queries
- Workbooks
- Automation rules
- UEBA and Entity Analytics

### Detection Rules
Pre-built detection rules organized by MITRE ATT&CK tactics:
- Credential Access
- Persistence
- Privilege Escalation
- Defense Evasion
- Discovery
- Lateral Movement
- Collection
- Exfiltration
- Impact

## 🔒 Security

- All secrets stored in Azure Key Vault
- Terraform state stored in Azure Storage with encryption
- RBAC and least privilege access
- Security scanning in CI/CD pipeline

## 🤝 Contributing

1. Create a feature branch
2. Make your changes
3. Run tests and validation
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License.
EOF

# Create module files
echo "📁 Creating Log Analytics module..."

# Log Analytics module - main.tf
cat > modules/log-analytics/main.tf << 'EOF'
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "this" {
  name                = var.workspace_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.sku
  retention_in_days   = var.retention_in_days
  daily_quota_gb      = var.daily_quota_gb
  tags                = var.tags

  internet_ingestion_enabled = true
  internet_query_enabled     = true
}

# Enable solutions
resource "azurerm_log_analytics_solution" "solutions" {
  for_each = toset(var.solutions)

  solution_name         = each.value
  location              = azurerm_log_analytics_workspace.this.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.this.id
  workspace_name        = azurerm_log_analytics_workspace.this.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/${each.value}"
  }

  tags = var.tags
}
EOF

# Log Analytics module - variables.tf
cat > modules/log-analytics/variables.tf << 'EOF'
variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "workspace_name" {
  description = "Name of the Log Analytics workspace"
  type        = string
}

variable "retention_in_days" {
  description = "Workspace data retention in days"
  type        = number
  default     = 90
}

variable "sku" {
  description = "SKU for Log Analytics workspace"
  type        = string
  default     = "PerGB2018"
}

variable "daily_quota_gb" {
  description = "Daily ingestion quota in GB (-1 for unlimited)"
  type        = number
  default     = -1
}

variable "solutions" {
  description = "List of solutions to enable"
  type        = list(string)
  default     = ["Security", "SecurityInsights"]
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
EOF

# Log Analytics module - outputs.tf
cat > modules/log-analytics/outputs.tf << 'EOF'
output "workspace_id" {
  description = "The Log Analytics Workspace ID"
  value       = azurerm_log_analytics_workspace.this.id
}

output "workspace_customer_id" {
  description = "The Log Analytics Workspace customer ID"
  value       = azurerm_log_analytics_workspace.this.workspace_id
}

output "primary_shared_key" {
  description = "The primary shared key for the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.this.primary_shared_key
  sensitive   = true
}
EOF

# Create Sentinel module files
echo "📁 Creating Sentinel module..."

# Sentinel module - main.tf
cat > modules/sentinel/main.tf << 'EOF'
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
EOF

# Sentinel module - variables.tf
cat > modules/sentinel/variables.tf << 'EOF'
variable "workspace_id" {
  description = "Log Analytics Workspace ID"
  type        = string
}

variable "enable_ueba" {
  description = "Enable User Entity Behavior Analytics"
  type        = bool
  default     = true
}

variable "enable_data_connectors" {
  description = "Data connectors to enable"
  type = object({
    azure_activity     = bool
    azure_ad          = bool
    office_365        = bool
    defender_for_cloud = bool
  })
  default = {
    azure_activity     = true
    azure_ad          = true
    office_365        = true
    defender_for_cloud = true
  }
}
EOF

# Sentinel module - outputs.tf
cat > modules/sentinel/outputs.tf << 'EOF'
output "workspace_id" {
  description = "Sentinel-enabled workspace ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
}
EOF

# Create production environment files
echo "📁 Creating production environment configuration..."

# Production main.tf
cat > environments/prod/main.tf << 'EOF'
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
EOF

# Production variables.tf
cat > environments/prod/variables.tf << 'EOF'
variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "rg-sentinel-prod"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "workspace_name" {
  description = "Log Analytics workspace name"
  type        = string
  default     = "law-sentinel-prod"
}

variable "retention_in_days" {
  description = "Log retention days"
  type        = number
  default     = 90
}

variable "daily_quota_gb" {
  description = "Daily quota in GB"
  type        = number
  default     = 10
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Project     = "Sentinel-DevSecOps"
  }
}
EOF

# Production outputs.tf
cat > environments/prod/outputs.tf << 'EOF'
output "workspace_id" {
  description = "Log Analytics Workspace ID"
  value       = module.log_analytics.workspace_id
}

output "sentinel_workspace_id" {
  description = "Sentinel Workspace ID"
  value       = module.sentinel.workspace_id
}
EOF

# Create example terraform.tfvars
cat > environments/prod/terraform.tfvars.example << 'EOF'
# Rename this file to terraform.tfvars and update with your values

resource_group_name = "rg-sentinel-prod"
location            = "eastus"
workspace_name      = "law-sentinel-prod"
retention_in_days   = 90
daily_quota_gb      = 10

tags = {
  Environment  = "Production"
  ManagedBy    = "Terraform"
  Project      = "Sentinel-DevSecOps"
  Owner        = "security-team@yourcompany.com"
  CostCenter   = "Security-001"
}
EOF

# Create GitHub Actions workflow
echo "📁 Creating GitHub Actions workflow..."

cat > .github/workflows/terraform-deploy.yml << 'EOF'
name: Deploy Sentinel Infrastructure

on:
  push:
    branches: [main]
    paths:
      - 'terraform/**'
      - '.github/workflows/terraform-deploy.yml'
  pull_request:
    branches: [main]
    paths:
      - 'terraform/**'

env:
  TF_VERSION: '1.5.0'
  WORKING_DIR: 'environments/prod'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Format Check
        run: terraform fmt -check -recursive
      
      - name: Terraform Init
        run: terraform init -backend=false
        working-directory: ${{ env.WORKING_DIR }}
      
      - name: Terraform Validate
        run: terraform validate
        working-directory: ${{ env.WORKING_DIR }}

  plan:
    needs: validate
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v3
      
      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: ${{ env.TF_VERSION }}
      
      - name: Terraform Init
        run: terraform init
        working-directory: ${{ env.WORKING_DIR }}
      
      - name: Terraform Plan
        run: terraform plan
        working-directory: ${{ env.WORKING_DIR }}
EOF

# Create validation script
echo "📁 Creating validation script..."

cat > scripts/validate-deployment.sh << 'EOF'
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
EOF

chmod +x scripts/validate-deployment.sh

# Create initial commit
echo "📝 Creating initial git commit..."
git add .
git commit -m "Initial commit: Terraform Sentinel DevSecOps project structure"

echo "✅ Project structure created successfully!"
echo ""
echo "Next steps:"
echo "1. Create a new repository on GitHub:"
echo "   - Go to https://github.com/new"
echo "   - Name it 'terraform-sentinel-devsecops'"
echo "   - Don't initialize with README (we already have one)"
echo ""
echo "2. Add the remote and push:"
echo "   git remote add origin https://github.com/yungkolt/terraform-sentinel-devsecops.git"
echo "   git push -u origin main"
echo ""
echo "3. Configure Azure credentials in GitHub:"
echo "   - Go to Settings > Secrets and variables > Actions"
echo "   - Add a new secret named AZURE_CREDENTIALS"
echo "   - Use: az ad sp create-for-rbac --name 'terraform-sentinel' --role contributor --scopes /subscriptions/{subscription-id}"
echo ""
echo "4. Update backend configuration in environments/prod/main.tf"
echo ""
echo "5. Create terraform.tfvars from the example file"
echo ""
echo "Happy deploying! 🚀"
