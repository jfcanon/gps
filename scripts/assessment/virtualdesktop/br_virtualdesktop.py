"""BR checks for Azure Virtual Desktop (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "AVD user data resides in FSLogix profile containers on Azure Files or Azure NetApp Files. Back up at the storage level (Azure Backup for Azure Files). The AVD workspace/hostpool ARM resource has no Azure Backup integration.",
            "expected_value": "Azure Backup enabled on Azure Files shares holding FSLogix containers",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#br-1-ensure-regular-automated-backups"}
