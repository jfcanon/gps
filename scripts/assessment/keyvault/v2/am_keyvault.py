"""
Asset Management checks for Azure Key Vault (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.
AM-5: Defender for Cloud AAC — PaaS, targets VMs → UNKNOWN.

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


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/azure-policy",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            tags = getattr(vault, "tags", None) or {}
            if tags:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "AM-5",
        "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Adaptive Application Controls target VMs and Arc-enabled servers only; not applicable to Key Vault",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
