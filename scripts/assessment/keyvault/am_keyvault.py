"""
Asset Management checks for Azure Key Vault (MCSB v3).

AM-2: Azure Policy support — proxy via tags presence check.
AM-5: Defender for Cloud AAC integration — PaaS, not applicable → UNKNOWN.

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
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy",
        "expected_value": "Resource tags present (proxy for policy governance)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/azure-policy",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        tags = getattr(vault, "tags", None) or {}
        if tags:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": "tags={} — no resource tags; policy governance cannot be confirmed",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": f"Resource tags present — policy governance applicable",
    }


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "AM-5",
        "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Adaptive Application Controls target VMs; not applicable to Key Vault",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
