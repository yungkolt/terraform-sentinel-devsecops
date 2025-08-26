# Automation rules for incident management
# Note: Azure provider requires UUIDs for automation rule names

resource "azurerm_sentinel_automation_rule" "auto_assign_high_severity" {
  name                       = "12345678-1234-1234-1234-123456789abc" # Must be UUID
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Auto-assign High Severity Incidents"
  order                      = 1
  enabled                    = true

  # Updated to use condition_json (new format)
  condition_json = jsonencode([
    {
      property = "IncidentSeverity"
      operator = "Equals"
      values   = ["High", "Critical"]
    }
  ])

  action_incident {
    order  = 1
    status = "Active"
    # Note: Update with your SOC team's object ID when available
    # owner_id = var.soc_team_object_id
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.this]
}

# Auto-close informational incidents  
resource "azurerm_sentinel_automation_rule" "auto_close_info" {
  name                       = "87654321-4321-4321-4321-fedcba987654" # Must be UUID
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Auto-close Informational Alerts"
  order                      = 2
  enabled                    = true

  condition_json = jsonencode([
    {
      property = "IncidentSeverity"
      operator = "Equals"
      values   = ["Informational"]
    }
  ])

  action_incident {
    order                  = 1
    status                 = "Closed"
    classification         = "BenignPositive_SuspiciousButExpected" # Fixed valid value
    classification_comment = "Auto-closed informational alert"
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.this]
}
