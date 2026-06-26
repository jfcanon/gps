"""BR checks for Azure Cognitive Services (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "Azure Cognitive Services accounts are stateless API endpoints. Models and custom training data reside in linked storage. Backup the linked storage account; the account configuration is recoverable via IaC.",
            "expected_value": "N/A — backup linked storage accounts; use IaC for account config recovery",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/security-baseline"}
