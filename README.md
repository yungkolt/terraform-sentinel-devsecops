# 🛡️ Terraform Sentinel DevSecOps

This repository implements a comprehensive **Infrastructure as Code (IaC)** solution for deploying and managing **Microsoft Sentinel** and **Azure Log Analytics** with enterprise-grade DevSecOps practices. Built with Terraform, this solution demonstrates advanced cloud security architecture, automated threat detection, and modern CI/CD security practices.

## 🏆 Key Features & Capabilities

### 🔐 **Advanced Security Implementation**
- **Multi-layered Detection Rules**: MITRE ATT&CK framework-aligned detection rules covering Credential Access, Persistence, Defense Evasion
- **Automated Incident Response**: Smart automation rules for incident assignment and classification
- **Proactive Threat Hunting**: Pre-built hunting queries for dormant account reactivation and data staging activities
- **UEBA Integration**: User Entity Behavior Analytics configuration guidance
- **Security Operations Dashboard**: Real-time SOC visibility with custom workbooks

### 🚀 **DevSecOps Excellence**
- **Security-First CI/CD**: Integrated TFSec, Checkov, and TruffleHog scanning in GitHub Actions
- **SARIF Integration**: Security findings uploaded to GitHub Security tab for centralized vulnerability management
- **Automated Validation**: KQL query syntax validation and Terraform format checking
- **Multi-Environment Support**: Separate configurations for dev, staging, and production environments

### 🏗️ **Enterprise Architecture**
- **Modular Design**: Reusable Terraform modules for scalability and maintainability
- **State Management**: Secure Azure backend with encryption for Terraform state
- **Resource Tagging**: Comprehensive tagging strategy for cost management and governance
- **Least Privilege**: RBAC implementation with minimum required permissions

## 🎓 Lessons Learned & Technical Challenges

### **Azure Provider Limitations**
During development, I encountered several challenges with the Azure Terraform provider's Sentinel support:

- **Resource Availability**: Some Sentinel resources like `azurerm_sentinel_hunting_query` and `azurerm_sentinel_user_analytics_settings` are not yet available in the provider
- **Workarounds Implemented**: 
  - Used `azurerm_log_analytics_saved_search` for hunting queries
  - Implemented workbooks via ARM template deployment
  - Documented UEBA configuration requirements for manual setup
- **UUID Requirements**: Automation rules require UUID format for names, not human-readable strings

### **DevSecOps Pipeline Evolution**
- **Initial Challenge**: Multiple overlapping workflows causing complexity and failures
- **Solution**: Consolidated into single comprehensive pipeline with proper job dependencies
- **Result**: Cleaner execution, better error handling, and professional presentation

### **Security Scanning Integration**
- **Learning**: SARIF integration requires specific output formats and error handling
- **Implementation**: Added `soft_fail` options and file existence checks to prevent pipeline failures on security findings
- **Benefit**: Security issues are tracked in GitHub Security tab without breaking builds

### **Cost Optimization Considerations**
- **Discovery**: Sentinel costs can escalate quickly without proper controls
- **Mitigation**: Implemented daily quotas, configurable retention, and resource tagging
- **Best Practice**: Always plan for cost management in cloud security solutions

## 🏗️ Project Architecture

```
terraform-sentinel-devsecops/
├── 📁 modules/                    # Reusable Terraform modules
│   ├── 📊 log-analytics/         # Log Analytics workspace with solutions
│   ├── 🛡️ sentinel/              # Sentinel enablement and UEBA configuration
│   └── 🔍 sentinel-content/      # Detection rules, hunting queries, workbooks
│       └── detection-rules/      # MITRE ATT&CK aligned detection rules
├── 🌍 environments/              # Environment-specific configurations
│   ├── dev/                      # Development environment
│   ├── staging/                  # Staging environment  
│   └── prod/                     # Production environment
├── 🔧 scripts/                   # Deployment validation and KQL testing
├── 🔄 .github/workflows/         # CI/CD security pipelines
└── 📋 tests/                     # Automated testing framework
```

## 🚀 Quick Start Guide

### Prerequisites
- **Terraform** >= 1.5.0
- **Azure CLI** >= 2.50.0  
- **PowerShell Core** >= 7.0
- Azure subscription with **Security Admin** and **Contributor** roles

### Deployment Steps

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd terraform-sentinel-devsecops
   ```

2. **Azure Authentication**
   ```bash
   az login
   az account set --subscription "YOUR_SUBSCRIPTION_ID"
   ```

3. **Environment Configuration**
   ```bash
   cd environments/prod
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your values
   ```

4. **Deploy Infrastructure**
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

5. **Manual Configuration Steps**
   After deployment, configure these items manually in the Azure portal:
   - Enable UEBA in Sentinel settings
   - Configure data connectors (Azure AD, Office 365, Defender for Cloud)
   - Review and tune detection rules based on your environment

## 📋 Module Breakdown

### 🔗 **Log Analytics Module**
Provisions enterprise-grade log analytics workspace with:
- **Configurable Retention**: 30-730 days with cost optimization
- **Data Sources**: Azure Activity, Security Events, Office 365 logs
- **Solutions Integration**: Security, SecurityInsights, VMInsights, Updates
- **Quota Management**: Daily ingestion limits for cost control

### 🛡️ **Sentinel Module**  
Enables Microsoft Sentinel with advanced features:
- **Core Enablement**: Sentinel workspace onboarding
- **Automation Rules**: Intelligent incident routing with UUID-compliant naming
- **Threat Hunting**: Saved searches for proactive threat detection
- **SOC Dashboard**: Custom workbook via ARM template deployment

### 🎯 **Detection Rules (MITRE ATT&CK Aligned)**
Production-ready detection rules organized by tactics:

| Tactic | Technique | Rule Name | Severity |
|--------|-----------|-----------|----------|
| **Credential Access** | T1110 | Brute Force Detection | High |
| **Credential Access** | T1110.003 | Password Spray Detection | High |
| **Defense Evasion** | T1562.001 | Security Tool Tampering | High |
| **Defense Evasion** | T1070.001 | Event Log Clearing | High |
| **Persistence** | T1547.001 | Registry Run Key Persistence | Medium |
| **Persistence** | T1053.005 | Scheduled Task Creation | Medium |

### 🔍 **Threat Hunting Queries**
Proactive hunting capabilities including:
- **Dormant Account Reactivation**: Detects compromised inactive accounts
- **Data Staging Activities**: Identifies potential data exfiltration preparation

## 🔒 Security & Compliance

### **Security Controls**
- ✅ **Secrets Management**: Azure Key Vault integration for sensitive data
- ✅ **State Encryption**: Terraform state secured in Azure Storage with encryption
- ✅ **RBAC Implementation**: Principle of least privilege access
- ✅ **Network Security**: Restricted ingestion and query endpoints
- ✅ **Audit Logging**: Comprehensive activity logging and monitoring

### **CI/CD Security Pipeline**
```yaml
Security Scanning Pipeline:
├── 🔍 TFSec Scan          → Infrastructure security analysis
├── 🛡️ Checkov Scan        → Policy compliance validation  
├── 🔑 TruffleHog Scan     → Secret detection
├── 📝 KQL Validation      → Query syntax verification
└── 📊 SARIF Upload        → GitHub Security integration
```

## 🎯 Why This Technology Stack?

### **Terraform Choice Rationale**
- **Infrastructure as Code**: Version-controlled, repeatable deployments
- **Azure Provider Maturity**: Comprehensive resource coverage with active development
- **Module Reusability**: Scalable architecture across multiple environments
- **State Management**: Remote state with locking prevents configuration drift

### **Microsoft Sentinel Selection**
- **Cloud-Native SIEM**: Scalable, serverless security operations
- **Azure Integration**: Native integration with Azure services and identity
- **AI/ML Capabilities**: Built-in UEBA and advanced analytics
- **Cost Efficiency**: Pay-per-GB ingestion model vs. traditional SIEM licensing

### **DevSecOps Implementation**
- **Shift-Left Security**: Security validation in CI/CD pipeline
- **Automated Compliance**: Policy-as-code with Checkov
- **Continuous Monitoring**: Real-time security posture assessment

## 📊 Operational Metrics

### **Detection Coverage**
- **6 High-Severity Rules**: Critical attack vectors covered
- **MITRE ATT&CK Mapping**: 6 techniques across 4 tactics
- **Custom Hunting Queries**: 2 proactive threat hunting scenarios
- **Automation Rules**: Intelligent incident management with UUID compliance

### **Cost Optimization**
- **Configurable Retention**: Balance between compliance and cost
- **Daily Quota Limits**: Prevent unexpected ingestion costs  
- **Solution Optimization**: Only deploy required Log Analytics solutions
- **Resource Tagging**: Comprehensive cost allocation and chargeback

## 🤝 Contributing

1. **Feature Branch**: Create from `main` branch
2. **Security Validation**: Run `./scripts/validate-deployment.sh`
3. **KQL Testing**: Execute `./scripts/validate-kql.ps1`
4. **Pull Request**: Include security scan results and testing evidence

## 🔗 Additional Resources

- [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/)
- [Terraform Azure Provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ by yungkolt**

*This project demonstrates real-world experience with Azure provider limitations, DevSecOps pipeline design, and enterprise security architecture.*
