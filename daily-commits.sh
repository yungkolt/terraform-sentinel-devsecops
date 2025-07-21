#!/bin/bash

# Daily commits plan for terraform-sentinel-devsecops project
# This script helps create meaningful commits over several days

echo "📅 Daily Commits Plan for Sentinel DevSecOps Project"
echo "===================================================="

# Day 1 (Today) - Add detection rules for credential access
create_day1_commits() {
    echo "📝 Day 1: Adding credential access detection rules..."
    
    # Create detection rules directory
    mkdir -p modules/sentinel-content/detection-rules
    
    # Create credential access detection rules
    cat > modules/sentinel-content/detection-rules/credential-access.tf << 'EOF'
# Detection rules for credential access attacks
# MITRE ATT&CK Tactic: Credential Access (TA0006)

variable "workspace_id" {
  description = "Sentinel workspace ID"
  type        = string
}

# Rule 1: Brute Force Attack Detection
resource "azurerm_sentinel_alert_rule_scheduled" "brute_force_attack" {
  name                       = "BruteForceAttackDetection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Brute Force Attack Detected"
  severity                   = "High"
  description               = "Detects multiple failed login attempts that may indicate a brute force attack"

  query = <<-EOQ
    let threshold = 10;
    let timeframe = 10m;
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType != 0
    | summarize 
        FailedAttempts = count(),
        DistinctIPAddresses = dcount(IPAddress),
        IPAddresses = make_set(IPAddress, 100),
        FirstAttempt = min(TimeGenerated),
        LastAttempt = max(TimeGenerated)
    by UserPrincipalName
    | where FailedAttempts > threshold
    | extend TimeDifference = datetime_diff('minute', LastAttempt, FirstAttempt)
    | project UserPrincipalName, FailedAttempts, DistinctIPAddresses, 
              IPAddresses, FirstAttempt, LastAttempt, TimeDifference
  EOQ

  query_frequency    = "PT5M"
  query_period       = "PT10M"
  trigger_operator   = "GreaterThan"
  trigger_threshold  = 0

  tactics            = ["CredentialAccess"]
  techniques         = ["T1110"]

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration      = "PT30M"
      matching_method        = "AllEntities"
      reopen_closed_incidents = true
    }
  }
}

# Rule 2: Password Spray Attack Detection
resource "azurerm_sentinel_alert_rule_scheduled" "password_spray" {
  name                       = "PasswordSprayDetection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Password Spray Attack Detected"
  severity                   = "High"
  description               = "Detects password spray attacks where same password is tried across multiple accounts"

  query = <<-EOQ
    let timeframe = 30m;
    let threshold = 10;
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType == "50126"
    | summarize 
        AttemptedAccounts = dcount(UserPrincipalName),
        TargetAccounts = make_set(UserPrincipalName, 100),
        StartTime = min(TimeGenerated),
        EndTime = max(TimeGenerated)
    by IPAddress, UserAgent
    | where AttemptedAccounts >= threshold
    | extend AttackDuration = datetime_diff('minute', EndTime, StartTime)
  EOQ

  query_frequency    = "PT15M"
  query_period       = "PT30M"
  trigger_operator   = "GreaterThan"
  trigger_threshold  = 0

  tactics            = ["CredentialAccess"]
  techniques         = ["T1110.003"]
}
EOF
    
    git add modules/sentinel-content/detection-rules/credential-access.tf
    git commit -m "feat: Add credential access detection rules

- Implement brute force attack detection
- Add password spray detection logic
- Configure MITRE ATT&CK mapping (T1110)
- Set up incident grouping for related alerts"
    
    # Create README for detection rules
    cat > modules/sentinel-content/detection-rules/README.md << 'EOF'
# Sentinel Detection Rules

This directory contains custom detection rules organized by MITRE ATT&CK tactics.

## Implemented Rules

### Credential Access (TA0006)
- **Brute Force Attack Detection**: Detects multiple failed login attempts
- **Password Spray Detection**: Identifies distributed password attacks

## Rule Severity Levels
- **Critical**: Immediate response required
- **High**: Investigate within 1 hour
- **Medium**: Investigate within 4 hours
- **Low**: Review during normal operations

## Testing
Each rule includes sample KQL queries that can be tested in the Sentinel workspace.
EOF
    
    git add modules/sentinel-content/detection-rules/README.md
    git commit -m "docs: Add detection rules documentation

- Document implemented detection rules
- Add severity level guidelines
- Include testing instructions"
}

# Day 2 - Add persistence detection rules
create_day2_commits() {
    echo "📝 Day 2: Adding persistence detection rules..."
    
    cat > modules/sentinel-content/detection-rules/persistence.tf << 'EOF'
# Detection rules for persistence techniques
# MITRE ATT&CK Tactic: Persistence (TA0003)

# Rule 1: Registry Run Key Modifications
resource "azurerm_sentinel_alert_rule_scheduled" "registry_persistence" {
  name                       = "RegistryPersistenceDetection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Run Key Persistence Detected"
  severity                   = "Medium"
  description               = "Detects modifications to registry run keys commonly used for persistence"

  query = <<-EOQ
    DeviceRegistryEvents
    | where TimeGenerated > ago(5m)
    | where RegistryKey has @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    | where ActionType == "RegistryValueSet"
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName,
              RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessCommandLine
  EOQ

  query_frequency    = "PT5M"
  query_period       = "PT5M"
  trigger_operator   = "GreaterThan"
  trigger_threshold  = 0

  tactics            = ["Persistence"]
  techniques         = ["T1547.001"]
}

# Rule 2: Scheduled Task Creation
resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation" {
  name                       = "ScheduledTaskPersistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Scheduled Task Created"
  severity                   = "Medium"
  description               = "Detects creation of scheduled tasks that may be used for persistence"

  query = <<-EOQ
    DeviceProcessEvents
    | where TimeGenerated > ago(10m)
    | where FileName =~ "schtasks.exe" or ProcessCommandLine has "Register-ScheduledTask"
    | where ProcessCommandLine has_any ("/create", "-create", "New-ScheduledTask")
    | extend TaskName = extract(@'/tn\s+"?([^"\s]+)"?', 1, ProcessCommandLine)
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName,
              TaskName, ProcessCommandLine, InitiatingProcessFileName
  EOQ

  query_frequency    = "PT10M"
  query_period       = "PT10M"
  trigger_operator   = "GreaterThan"
  trigger_threshold  = 0

  tactics            = ["Persistence", "Execution"]
  techniques         = ["T1053.005"]
}
EOF
    
    git add modules/sentinel-content/detection-rules/persistence.tf
    git commit -m "feat: Add persistence detection rules

- Detect registry run key modifications (T1547.001)
- Monitor scheduled task creation (T1053.005)
- Track persistence mechanisms across endpoints"
    
    # Add automation rules
    cat > modules/sentinel/automation-rules.tf << 'EOF'
# Automation rules for incident management

# Auto-assign high severity incidents to SOC team
resource "azurerm_sentinel_automation_rule" "auto_assign_high_severity" {
  name                       = "AutoAssignHighSeverity"
  log_analytics_workspace_id = var.workspace_id
  display_name              = "Auto-assign High Severity Incidents"
  order                     = 1
  enabled                   = true

  condition {
    property = "IncidentSeverity"
    operator = "Equals"
    values   = ["High", "Critical"]
  }

  action_incident {
    order  = 1
    status = "Active"
    # Note: Update with your SOC team's object ID
    # owner_id = var.soc_team_object_id
  }
}

# Auto-close informational incidents
resource "azurerm_sentinel_automation_rule" "auto_close_info" {
  name                       = "AutoCloseInformational"
  log_analytics_workspace_id = var.workspace_id
  display_name              = "Auto-close Informational Alerts"
  order                     = 2
  enabled                   = true

  condition {
    property = "IncidentSeverity"
    operator = "Equals"
    values   = ["Informational"]
  }

  action_incident {
    order  = 1
    status = "Closed"
    classification = "BenignPositive"
    classification_comment = "Auto-closed informational alert"
  }
}
EOF
    
    git add modules/sentinel/automation-rules.tf
    git commit -m "feat: Implement automation rules for incident response

- Auto-assign high/critical severity incidents
- Auto-close informational alerts
- Improve SOC operational efficiency"
}

# Day 3 - Add defense evasion and KQL validation
create_day3_commits() {
    echo "📝 Day 3: Adding defense evasion detection and KQL validation..."
    
    cat > modules/sentinel-content/detection-rules/defense-evasion.tf << 'EOF'
# Detection rules for defense evasion techniques
# MITRE ATT&CK Tactic: Defense Evasion (TA0005)

# Rule 1: Security Tool Tampering
resource "azurerm_sentinel_alert_rule_scheduled" "security_tool_tampering" {
  name                       = "SecurityToolTampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Tool Tampering Detected"
  severity                   = "High"
  description               = "Detects attempts to disable or modify security tools"

  query = <<-EOQ
    let securityProcesses = dynamic(["MsMpEng.exe", "MsSense.exe", "SentinelAgent.exe"]);
    DeviceProcessEvents
    | where TimeGenerated > ago(5m)
    | where ProcessCommandLine has_any ("Stop-Service", "sc stop", "net stop", "taskkill")
    | where ProcessCommandLine has_any (securityProcesses)
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName,
              ProcessCommandLine, InitiatingProcessFileName
  EOQ

  query_frequency    = "PT5M"
  query_period       = "PT5M"
  trigger_operator   = "GreaterThan"
  trigger_threshold  = 0

  tactics            = ["DefenseEvasion"]
  techniques         = ["T1562.001"]
}

# Rule 2: Event Log Clearing
resource "azurerm_sentinel_alert_rule_scheduled" "log_clearing" {
  name                       = "EventLogClearing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Event Log Cleared"
  severity                   = "High"
  description               = "Detects clearing of Windows event logs"

  query = <<-EOQ
    SecurityEvent
    | where TimeGenerated > ago(5m)
    | where EventID == 1102
    | extend LogCleared = extract(@"cleared the (.+) log", 1, RenderedDescription)
    | project TimeGenerated, Computer, Account, LogCleared
  EOQ

  query_frequency    = "PT5M"
  query_period       = "PT5M"
  trigger_operator   = "GreaterThan"
  trigger_threshold  = 0

  tactics            = ["DefenseEvasion"]
  techniques         = ["T1070.001"]
}
EOF
    
    git add modules/sentinel-content/detection-rules/defense-evasion.tf
    git commit -m "feat: Add defense evasion detection rules

- Detect security tool tampering (T1562.001)
- Monitor event log clearing activities (T1070.001)
- Enhance threat detection coverage"
    
    # Add KQL validation script
    cat > scripts/validate-kql.ps1 << 'EOF'
<#
.SYNOPSIS
    Validates KQL queries in Terraform files
.DESCRIPTION
    Parses Terraform files and validates KQL queries for syntax
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TerraformPath
)

function Test-KQLSyntax {
    param([string]$Query)
    
    # Basic syntax validation
    $errors = @()
    
    if ($Query -notmatch '\w+\s*\|') {
        $errors += "Missing table name at start of query"
    }
    
    if (($Query -split '\|').Count -lt 2) {
        $errors += "Query must have at least one pipe operator"
    }
    
    return $errors
}

# Extract and validate queries
$files = Get-ChildItem -Path $TerraformPath -Filter "*.tf" -Recurse
$totalQueries = 0
$validQueries = 0

foreach ($file in $files) {
    $content = Get-Content -Path $file.FullName -Raw
    $pattern = '(?s)query\s*=\s*<<-EOQ\s*(.*?)\s*EOQ'
    $matches = [regex]::Matches($content, $pattern)
    
    foreach ($match in $matches) {
        $totalQueries++
        $query = $match.Groups[1].Value
        $errors = Test-KQLSyntax -Query $query
        
        if ($errors.Count -eq 0) {
            $validQueries++
            Write-Host "✅ Valid query in $($file.Name)" -ForegroundColor Green
        } else {
            Write-Host "❌ Invalid query in $($file.Name):" -ForegroundColor Red
            $errors | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        }
    }
}

Write-Host "`nValidation Summary:" -ForegroundColor Cyan
Write-Host "Total queries: $totalQueries"
Write-Host "Valid queries: $validQueries"
Write-Host "Invalid queries: $($totalQueries - $validQueries)"
EOF
    
    git add scripts/validate-kql.ps1
    git commit -m "feat: Add KQL query validation script

- Implement syntax validation for KQL queries
- Parse Terraform files for embedded queries
- Provide validation summary report"
}

# Day 4 - Add workbooks and hunting queries
create_day4_commits() {
    echo "📝 Day 4: Adding workbooks and hunting queries..."
    
    cat > modules/sentinel/workbooks.tf << 'EOF'
# Security Operations Center (SOC) Dashboard Workbook

resource "azurerm_sentinel_workbook" "soc_dashboard" {
  log_analytics_workspace_id = var.workspace_id
  location                   = var.location
  display_name              = "SOC Operations Dashboard"
  
  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        content = {
          json = "# Security Operations Center Dashboard\n\nReal-time visibility into security incidents and alerts"
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query = <<-QUERY
            SecurityIncident
            | summarize 
                Critical = countif(Severity == "Critical"),
                High = countif(Severity == "High"),
                Medium = countif(Severity == "Medium"),
                Low = countif(Severity == "Low")
            | project Critical, High, Medium, Low
          QUERY
          size = 4
          visualization = "tiles"
          tileSettings = {
            showBorder = true
            titleContent = {
              columnMatch = "Critical"
              formatter = 12
              formatOptions = {
                palette = "red"
              }
            }
          }
        }
      }
    ]
  })
  
  tags = var.tags
}
EOF
    
    git add modules/sentinel/workbooks.tf
    git commit -m "feat: Add SOC operations dashboard workbook

- Create incident severity overview
- Add real-time security metrics
- Implement tile-based visualization"
    
    # Add hunting queries
    cat > modules/sentinel/hunting-queries.tf << 'EOF'
# Proactive threat hunting queries

resource "azurerm_sentinel_hunting_query" "dormant_accounts" {
  log_analytics_workspace_id = var.workspace_id
  name                      = "DormantAccountReactivation"
  display_name              = "Dormant Account Reactivation"
  description               = "Hunt for accounts that have been dormant and suddenly reactivated"
  
  query = <<-EOQ
    let dormantDays = 90d;
    let lookback = 120d;
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | join kind=leftanti (
        SigninLogs
        | where TimeGenerated between(ago(lookback)..ago(1d))
        | where ResultType == 0
        | distinct UserPrincipalName
    ) on UserPrincipalName
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
  EOQ

  tactics = ["InitialAccess", "Persistence"]
}

resource "azurerm_sentinel_hunting_query" "data_staging" {
  log_analytics_workspace_id = var.workspace_id
  name                      = "DataStagingActivity"
  display_name              = "Potential Data Staging"
  description               = "Hunt for unusual file compression activities that may indicate data staging"
  
  query = <<-EOQ
    DeviceFileEvents
    | where TimeGenerated > ago(24h)
    | where FileName endswith_any (".zip", ".rar", ".7z")
    | summarize FileCount = count(), TotalSize = sum(FileSize) 
    by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 1h)
    | where FileCount > 10 or TotalSize > 1073741824
  EOQ

  tactics = ["Collection", "Exfiltration"]
}
EOF
    
    git add modules/sentinel/hunting-queries.tf
    git commit -m "feat: Add proactive threat hunting queries

- Detect dormant account reactivation
- Identify potential data staging activities
- Enhance threat hunting capabilities"
}

# Day 5 - Add CI/CD improvements and documentation
create_day5_commits() {
    echo "📝 Day 5: Enhancing CI/CD and documentation..."
    
    # Update GitHub Actions workflow
    cat > .github/workflows/security-scan.yml << 'EOF'
name: Security Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  tfsec:
    name: TFSec Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          soft_fail: false
          
  checkov:
    name: Checkov Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform
          output_format: sarif
          
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
EOF
    
    git add .github/workflows/security-scan.yml
    git commit -m "ci: Add security scanning workflow

- Integrate tfsec for Terraform security scanning
- Add Checkov for compliance validation
- Enable SARIF upload for GitHub Security tab"
    
    # Add comprehensive documentation
    cat > docs/DEPLOYMENT_GUIDE.md << 'EOF'
# Deployment Guide

## Prerequisites

- Azure subscription with appropriate permissions
- Terraform >= 1.5.0
- Azure CLI >= 2.50.0
- PowerShell Core >= 7.0

## Step-by-Step Deployment

### 1. Clone Repository
```bash
git clone https://github.com/yungkolt/terraform-sentinel-devsecops.git
cd terraform-sentinel-devsecops
```

### 2. Configure Azure Authentication
```bash
az login
az account set --subscription "YOUR_SUBSCRIPTION_ID"
```

### 3. Create Backend Storage
```bash
./scripts/setup-backend.sh
```

### 4. Configure Variables
```bash
cd environments/prod
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

### 5. Deploy Infrastructure
```bash
terraform init
terraform plan
terraform apply
```

## Post-Deployment

1. Verify Sentinel is enabled in the Azure Portal
2. Check data connectors are active
3. Validate detection rules are firing
4. Test automation rules

## Troubleshooting

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues.
EOF
    
    git add docs/DEPLOYMENT_GUIDE.md
    git commit -m "docs: Add comprehensive deployment guide

- Step-by-step deployment instructions
- Prerequisites and configuration steps
- Post-deployment validation checklist
- Troubleshooting reference"
}

# Function to show progress
show_progress() {
    echo -e "\n📊 Commit Schedule:"
    echo "Day 1 (Today): Detection rules - Credential Access"
    echo "Day 2: Detection rules - Persistence + Automation"
    echo "Day 3: Defense Evasion + KQL Validation"
    echo "Day 4: Workbooks + Hunting Queries"
    echo "Day 5: CI/CD + Documentation"
    echo -e "\nEach day will have 2-3 meaningful commits"
}

# Main execution
case "${1:-today}" in
    "1"|"today")
        create_day1_commits
        echo "✅ Day 1 commits completed!"
        ;;
    "2")
        create_day2_commits
        echo "✅ Day 2 commits completed!"
        ;;
    "3")
        create_day3_commits
        echo "✅ Day 3 commits completed!"
        ;;
    "4")
        create_day4_commits
        echo "✅ Day 4 commits completed!"
        ;;
    "5")
        create_day5_commits
        echo "✅ Day 5 commits completed!"
        ;;
    "all")
        create_day1_commits
        create_day2_commits
        create_day3_commits
        create_day4_commits
        create_day5_commits
        echo "✅ All commits completed!"
        ;;
    "schedule")
        show_progress
        ;;
    *)
        echo "Usage: $0 [1|2|3|4|5|today|all|schedule]"
        echo "  1/today - Create Day 1 commits"
        echo "  2-5     - Create specific day commits"
        echo "  all     - Create all commits at once"
        echo "  schedule - Show commit schedule"
        ;;
esac

echo -e "\n💡 Don't forget to push your changes:"
echo "git push origin main"
