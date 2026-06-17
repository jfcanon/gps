"""
Privileged Access checks for Azure Key Vault (MCSB v3).

PA-1: Local admin (legacy access policies) — enable_rbac_authorization=False → FAIL.
PA-7: RBAC for data plane — enable_rbac_authorization=True → PASS (proxy).
PA-8: Customer Lockbox — KV in Lockbox supported services list since ~2020;
      Lockbox enablement is subscription-level (not ARM-readable per-vault) → UNKNOWN.

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


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "expected_value": "enable_rbac_authorization=True (legacy vault access policies disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        rbac = getattr(vault.properties, "enable_rbac_authorization", False)
        if rbac:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": "enable_rbac_authorization=False — legacy vault access policies active (broad Get/List/Set/Delete permissions without RBAC granularity)",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_rbac_authorization=True — legacy access policies disabled",
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "expected_value": "enable_rbac_authorization=True (data-plane RBAC active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        rbac = getattr(vault.properties, "enable_rbac_authorization", False)
        if rbac:
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": "enable_rbac_authorization=False — data-plane RBAC not active; full assignment check requires azure-mgmt-authorization",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_rbac_authorization=True — data-plane RBAC active; full assignment enumeration requires azure-mgmt-authorization",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Key Vault is in the Customer Lockbox supported services list; Lockbox is enabled/disabled at subscription level via azure-mgmt-support — not readable per-vault via ARM",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }
