"""BR checks for Azure Database Migration Service (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "DMS is a transient migration tool — backup applies to source and target databases, not the DMS service itself. Use Azure Backup on target databases post-migration.",
            "expected_value": "N/A — enable Azure Backup on target database post-migration",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/security-baseline"}
