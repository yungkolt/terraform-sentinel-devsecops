output "detection_rules_deployed" {
  description = "List of deployed detection rules by tactic"
  value       = local.detection_rules
}

output "rule_count" {
  description = "Total number of detection rules deployed"
  value       = local.total_rule_count
}

output "tactics_covered" {
  description = "MITRE ATT&CK tactics covered by deployed rules"
  value = [
    "CredentialAccess",
    "DefenseEvasion", 
    "Persistence"
  ]
}

output "techniques_covered" {
  description = "MITRE ATT&CK techniques covered by deployed rules"
  value = [
    "T1110",
    "T1110.003",
    "T1562.001",
    "T1070.001",
    "T1547.001",
    "T1053.005"
  ]
}
