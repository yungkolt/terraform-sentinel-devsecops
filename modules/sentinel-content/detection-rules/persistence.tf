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
