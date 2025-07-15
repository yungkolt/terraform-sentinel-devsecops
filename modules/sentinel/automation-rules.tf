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
