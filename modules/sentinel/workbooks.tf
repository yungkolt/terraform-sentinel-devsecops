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
