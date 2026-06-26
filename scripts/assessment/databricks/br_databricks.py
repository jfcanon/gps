"""BR checks for Azure Databricks (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "Azure Databricks has no Azure Backup integration. Notebooks, jobs, and cluster configs should be exported to version control (Git) via Databricks Repos. Delta tables reside in ADLS Gen2 — back up via storage redundancy + snapshots.",
            "expected_value": "N/A — use Databricks Repos for notebook backup; configure GRS/ZRS on linked storage",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/repos/"}
