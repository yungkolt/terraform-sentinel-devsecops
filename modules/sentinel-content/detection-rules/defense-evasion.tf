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
