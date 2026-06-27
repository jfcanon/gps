"""BR checks for Azure File Sync (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "Azure Backup for Azure Files covers the backing Azure file share, not the StorageSyncService ARM resource. Backup is configured on the storage account/file share, not on the sync service resource.",
            "expected_value": "Azure Backup enabled on the Azure file share (storage account) used as cloud endpoint",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/backup/backup-azure-files"}
