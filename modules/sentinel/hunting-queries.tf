# Hunting Queries - Implemented as Saved Searches
# Note: azurerm_sentinel_hunting_query is not available, using log analytics saved searches instead

resource "azurerm_log_analytics_saved_search" "dormant_accounts" {
  name                       = "DormantAccountReactivation"
  log_analytics_workspace_id = var.workspace_id
  category                   = "Threat Hunting"
  display_name              = "Dormant Account Reactivation"
  
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
    | extend Tactics = "InitialAccess,Persistence"
  EOQ

  tags = {
    Purpose = "Threat Hunting"
    Tactics = "InitialAccess,Persistence"
  }
}

resource "azurerm_log_analytics_saved_search" "data_staging" {
  name                       = "DataStagingActivity"
  log_analytics_workspace_id = var.workspace_id
  category                   = "Threat Hunting"
  display_name              = "Potential Data Staging"
  
  query = <<-EOQ
    DeviceFileEvents
    | where TimeGenerated > ago(24h)
    | where FileName endswith_any (".zip", ".rar", ".7z")
    | summarize FileCount = count(), TotalSize = sum(FileSize) 
    by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 1h)
    | where FileCount > 10 or TotalSize > 1073741824
    | extend Tactics = "Collection,Exfiltration"
  EOQ

  tags = {
    Purpose = "Threat Hunting"  
    Tactics = "Collection,Exfiltration"
  }
}
