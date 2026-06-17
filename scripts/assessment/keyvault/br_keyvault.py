"""
Backup and Recovery checks for Azure Key Vault (MCSB v3).

BR-1 azure_backup: Azure Backup doesn't support Key Vault as a managed backup target
                   (per-object backup CLI exists but is not ARM-checkable) → UNKNOWN.
BR-1 native_backup: enable_soft_delete AND enable_purge_protection → PASS (native protection).

Read-only. Zero ARM writes.
"""
from azure.mgmt.keyvault import KeyVaultManagementClient


def _get_vaults(client: KeyVaultManagementClient, resource_group: str | None, vault_name: str | None) -> list:
    if resource_group and vault_name:
        return [client.vaults.get(resource_group, vault_name)]
    elif resource_group:
        return list(client.vaults.list_by_resource_group(resource_group))
    else:
        return list(client.vaults.list())


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup does not support Key Vault as a managed backup target; per-object backup (az keyvault backup) exists but state is not exposed via ARM",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/backup",
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Native Soft-Delete and Purge Protection",
        "expected_value": "enable_soft_delete=True AND enable_purge_protection=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        props = vault.properties
        soft_delete = getattr(props, "enable_soft_delete", False)
        purge_protection = getattr(props, "enable_purge_protection", False)

        if soft_delete and purge_protection:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"enable_soft_delete={soft_delete}, enable_purge_protection={purge_protection}",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_soft_delete=True, enable_purge_protection=True",
    }
