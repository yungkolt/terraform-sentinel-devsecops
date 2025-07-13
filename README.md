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
