"""
Privileged Access checks for Azure Key Vault (MCSB v3).

PA-1: enable_rbac_authorization=False → legacy vault access policies active = broad permissions (FAIL).
PA-7: enable_rbac_authorization=True → data-plane RBAC active (PASS proxy).
PA-8: Customer Lockbox — KV in supported services list; subscription-level only → UNKNOWN.

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
    base = {
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "expected_value": "enable_rbac_authorization=True (legacy access policies disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            rbac = getattr(vault.properties, "enable_rbac_authorization", False)
            if rbac:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": "enable_rbac_authorization=True — legacy access policies disabled; no broad local-admin equivalent"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "enable_rbac_authorization=False — legacy vault access policies active; broad Get/List/Set/Delete grants equivalent to local admin without RBAC granularity"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "expected_value": "enable_rbac_authorization=True (data-plane RBAC active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            rbac = getattr(vault.properties, "enable_rbac_authorization", False)
            if rbac:
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": "enable_rbac_authorization=True — data-plane RBAC active; full role assignment enumeration requires azure-mgmt-authorization"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "enable_rbac_authorization=False — data-plane RBAC not active; vault access policies in use (no JEA enforcement)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Azure Key Vault is in the Customer Lockbox supported services list. Lockbox enablement is at subscription level — not readable per-vault via ARM. Check via azure-mgmt-support or Azure Portal > Customer Lockbox.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }
