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
