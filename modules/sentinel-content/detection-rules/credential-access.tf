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
