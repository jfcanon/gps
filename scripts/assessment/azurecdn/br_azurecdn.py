"""Backup and Recovery checks for Azure CDN / AFD (MCSB v3). Configuration is IaC-recoverable."""


def check_br1_azure_backup(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups",
        "status": "UNKNOWN",
        "actual_value": "Azure CDN/AFD has no stateful data to back up. Profile/endpoint configuration is recoverable via ARM templates/IaC. Use geo-redundant origins for content HA.",
        "expected_value": "N/A — use IaC for profile config recovery; configure geo-redundant origins",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/origin-redundancy",
    }
