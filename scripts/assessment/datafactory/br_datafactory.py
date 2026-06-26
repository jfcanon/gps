"""BR checks for Azure Data Factory (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "ADF pipeline/dataset/linked service definitions should be backed up via Git integration (Azure DevOps or GitHub). Factory has no Azure Backup support for ARM resources.",
            "expected_value": "ADF Git integration enabled (gitHubConfiguration or factoryVSTSConfiguration set)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/source-control"}
