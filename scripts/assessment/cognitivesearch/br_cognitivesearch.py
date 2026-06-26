"""Backup and Recovery — Azure Cognitive Search (MCSB v3)."""


def check_br1_azure_backup(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all", "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups",
        "status": "UNKNOWN",
        "actual_value": "Azure Cognitive Search has no native backup. Indexes must be rebuilt from source data. Use index snapshots via Search API or reindex from the source data store.",
        "expected_value": "N/A — rebuild indexes from source; document source data backup strategy",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-performance-tips",
    }
