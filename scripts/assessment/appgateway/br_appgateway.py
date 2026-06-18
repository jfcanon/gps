"""
Backup and Recovery checks for Azure Application Gateway (MCSB v3).

BR-1 azure_backup: Azure Backup does not support Application Gateway as a managed backup target → UNKNOWN.
BR-1 native_backup: No soft-delete or purge-protection for AppGW configuration.
                    Export via ARM template provides config backup but is manual → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup (Recovery Services Vault) does not support Application Gateway configuration as a managed backup target. Gateway configuration can be exported as ARM template or Bicep for manual recovery, but no automated backup mechanism exists.",
        "expected_value": "N/A — export ARM template for configuration backup",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/export-template-portal",
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Native Soft-Delete and Purge Protection",
        "status": "UNKNOWN",
        "actual_value": "Application Gateway has no soft-delete or purge-protection equivalent for its configuration. Recovery relies on ARM template exports or infrastructure-as-code (Bicep/Terraform). KV-backed certificates have their own soft-delete via Key Vault.",
        "expected_value": "N/A — use IaC templates for configuration recovery; enable KV soft-delete for certificates",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/export-template-portal",
    }
