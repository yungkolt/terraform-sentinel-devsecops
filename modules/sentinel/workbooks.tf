# SOC Dashboard - Implemented as Azure Monitor Workbook Template
# Note: azurerm_sentinel_workbook is not available, using template deployment instead

resource "azurerm_resource_group_template_deployment" "soc_dashboard" {
  name                = "soc-dashboard-workbook"
  resource_group_name = data.azurerm_log_analytics_workspace.this.resource_group_name
  deployment_mode     = "Incremental"

  template_content = jsonencode({
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "workbookDisplayName": {
        "type": "string",
        "defaultValue": "SOC Operations Dashboard",
        "metadata": {
          "description": "Display name for the workbook"
        }
      },
      "workspaceResourceId": {
        "type": "string",
        "defaultValue": var.workspace_id,
        "metadata": {
          "description": "Resource ID of the Log Analytics workspace"
        }
      }
    },
    "resources": [
      {
        "type": "microsoft.insights/workbooks",
        "apiVersion": "2021-03-08",
        "name": "[newGuid()]",
        "location": "[resourceGroup().location]",
        "kind": "shared",
        "properties": {
          "displayName": "[parameters('workbookDisplayName')]",
          "serializedData": jsonencode({
            "version": "Notebook/1.0",
            "items": [
              {
                "type": 1,
                "content": {
                  "json": "# Security Operations Center Dashboard\n\nReal-time visibility into security incidents and alerts"
                }
              },
              {
                "type": 3,
                "content": {
                  "version": "KqlItem/1.0",
                  "query": "SecurityIncident\n| summarize \n    Critical = countif(Severity == \"Critical\"),\n    High = countif(Severity == \"High\"),\n    Medium = countif(Severity == \"Medium\"),\n    Low = countif(Severity == \"Low\")\n| project Critical, High, Medium, Low",
                  "size": 4,
                  "visualization": "tiles"
                }
              }
            ]
          }),
          "sourceId": "[parameters('workspaceResourceId')]",
          "category": "sentinel"
        }
      }
    ]
  })

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.this]
}

# Data source for workspace information
data "azurerm_log_analytics_workspace" "this" {
  name                = split("/", var.workspace_id)[8]
  resource_group_name = split("/", var.workspace_id)[4]
}
