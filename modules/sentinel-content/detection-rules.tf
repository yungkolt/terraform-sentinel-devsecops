# =============================================================================
# SENTINEL DETECTION RULES - MITRE ATT&CK ALIGNED
# =============================================================================
# This file contains all detection rules organized by MITRE ATT&CK tactics.
# Consolidation reduces file sprawl while maintaining clear organization.

# =============================================================================
# CREDENTIAL ACCESS (TA0006)
# =============================================================================

# Rule: Brute Force Attack Detection (T1110)
resource "azurerm_sentinel_alert_rule_scheduled" "brute_force_attack" {
  name                       = "BruteForceAttackDetection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Brute Force Attack Detected"
  severity                   = "High"
  description                = "Detects multiple failed login attempts that may indicate a brute force attack"

  query = <<-EOQ
    let threshold = 10;
    let timeframe = 15m;
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

  query_frequency   = "PT5M"
  query_period      = "PT10M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1110"]

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT30M"
      matching_method         = "AllEntities"
      reopen_closed_incidents = true
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# Rule: Password Spray Attack Detection (T1110.003)
resource "azurerm_sentinel_alert_rule_scheduled" "password_spray" {
  name                       = "PasswordSprayDetection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Password Spray Attack Detected"
  severity                   = "High"
  description                = "Detects password spray attacks where same password is tried across multiple accounts"

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

  query_frequency   = "PT15M"
  query_period      = "PT30M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1110.003"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# =============================================================================
# DEFENSE EVASION (TA0005)
# =============================================================================

# Rule: Security Tool Tampering (T1562.001)
resource "azurerm_sentinel_alert_rule_scheduled" "security_tool_tampering" {
  name                       = "SecurityToolTampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Tool Tampering Detected"
  severity                   = "High"
  description                = "Detects attempts to disable or modify security tools"

  query = <<-EOQ
    let securityProcesses = dynamic(["MsMpEng.exe", "MsSense.exe", "SentinelAgent.exe"]);
    DeviceProcessEvents
    | where TimeGenerated > ago(5m)
    | where ProcessCommandLine has_any ("Stop-Service", "sc stop", "net stop", "taskkill")
    | where ProcessCommandLine has_any (securityProcesses)
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName,
              ProcessCommandLine, InitiatingProcessFileName
  EOQ

  query_frequency   = "PT5M"
  query_period      = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["DefenseEvasion"]
  techniques = ["T1562.001"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# Rule: Event Log Clearing (T1070.001)
resource "azurerm_sentinel_alert_rule_scheduled" "log_clearing" {
  name                       = "EventLogClearing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Event Log Cleared"
  severity                   = "High"
  description                = "Detects clearing of Windows event logs"

  query = <<-EOQ
    SecurityEvent
    | where TimeGenerated > ago(5m)
    | where EventID == 1102
    | extend LogCleared = extract(@"cleared the (.+) log", 1, RenderedDescription)
    | project TimeGenerated, Computer, Account, LogCleared
  EOQ

  query_frequency   = "PT5M"
  query_period      = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["DefenseEvasion"]
  techniques = ["T1070.001"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# =============================================================================
# PERSISTENCE (TA0003)
# =============================================================================

# Rule: Registry Run Key Modifications (T1547.001)
resource "azurerm_sentinel_alert_rule_scheduled" "registry_persistence" {
  name                       = "RegistryPersistenceDetection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Run Key Persistence Detected"
  severity                   = "Medium"
  description                = "Detects modifications to registry run keys commonly used for persistence"

  query = <<-EOQ
    DeviceRegistryEvents
    | where TimeGenerated > ago(5m)
    | where RegistryKey has @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    | where ActionType == "RegistryValueSet"
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName,
              RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessCommandLine
  EOQ

  query_frequency   = "PT5M"
  query_period      = "PT5M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["Persistence"]
  techniques = ["T1547.001"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# Rule: Scheduled Task Creation (T1053.005)
resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation" {
  name                       = "ScheduledTaskPersistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Scheduled Task Created"
  severity                   = "Medium"
  description                = "Detects creation of scheduled tasks that may be used for persistence"

  query = <<-EOQ
    DeviceProcessEvents
    | where TimeGenerated > ago(10m)
    | where FileName =~ "schtasks.exe" or ProcessCommandLine has "Register-ScheduledTask"
    | where ProcessCommandLine has_any ("/create", "-create", "New-ScheduledTask")
    | extend TaskName = extract(@'/tn\s+"?([^"\s]+)"?', 1, ProcessCommandLine)
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName,
              TaskName, ProcessCommandLine, InitiatingProcessFileName
  EOQ

  query_frequency   = "PT10M"
  query_period      = "PT10M"
  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["Persistence", "Execution"]
  techniques = ["T1053.005"]

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.main]
}

# =============================================================================
# LOCALS FOR RULE MANAGEMENT
# =============================================================================

locals {
  # Summary of all deployed rules for outputs
  detection_rules = {
    credential_access = {
      brute_force_attack = azurerm_sentinel_alert_rule_scheduled.brute_force_attack.name
      password_spray     = azurerm_sentinel_alert_rule_scheduled.password_spray.name
    }
    defense_evasion = {
      security_tool_tampering = azurerm_sentinel_alert_rule_scheduled.security_tool_tampering.name
      log_clearing            = azurerm_sentinel_alert_rule_scheduled.log_clearing.name
    }
    persistence = {
      registry_persistence    = azurerm_sentinel_alert_rule_scheduled.registry_persistence.name
      scheduled_task_creation = azurerm_sentinel_alert_rule_scheduled.scheduled_task_creation.name
    }
  }

  # Rule count for monitoring
  total_rule_count = 6
}
