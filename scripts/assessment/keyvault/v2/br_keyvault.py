"""
Backup and Recovery checks for Azure Key Vault (MCSB v3).

BR-1 azure_backup: Azure Backup does not support standard KV as a managed backup target;
                   per-object CLI backup exists but is not ARM-checkable → UNKNOWN.
BR-1 native_backup: enable_soft_delete=True AND enable_purge_protection=True → PASS.

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
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup (Recovery Services Vault) does not manage standard Key Vault as a backup target. Per-object backup (az keyvault backup) exists for Managed HSM but is not ARM-checkable.",
        "expected_value": "N/A — use native soft-delete + purge-protection as primary recovery mechanism",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/backup",
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Native Soft-Delete and Purge Protection",
        "expected_value": "enable_soft_delete=True AND enable_purge_protection=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            soft_delete = getattr(vault.properties, "enable_soft_delete", False)
            purge_prot = getattr(vault.properties, "enable_purge_protection", False)
            if soft_delete and purge_prot:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": "enable_soft_delete=True, enable_purge_protection=True"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"enable_soft_delete={soft_delete}, enable_purge_protection={purge_prot}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
