# Sentinel Detection Rules

This directory contains custom detection rules organized by MITRE ATT&CK tactics.

## Implemented Rules

### Credential Access (TA0006)
- **Brute Force Attack Detection**: Detects multiple failed login attempts
- **Password Spray Detection**: Identifies distributed password attacks

## Rule Severity Levels
- **Critical**: Immediate response required
- **High**: Investigate within 1 hour
- **Medium**: Investigate within 4 hours
- **Low**: Review during normal operations

## Testing
Each rule includes sample KQL queries that can be tested in the Sentinel workspace.
