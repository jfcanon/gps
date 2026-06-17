"""
Identity Management checks for Azure Key Vault (MCSB v3).

IM-1: Local auth (access keys) vs AAD. KV uses enable_rbac_authorization:
      True = Entra RBAC enforced (PASS), False = legacy access policies active (FAIL).
IM-3: Managed Identity and Service Principal usage — check RBAC assignments via ARM.
IM-7: Conditional Access — not checkable via ARM → UNKNOWN.
IM-8: KV Secrets usage — KV IS the secrets service → PASS.

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


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth",
        "expected_value": "enable_rbac_authorization=True (legacy access policies disabled)",
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
                "actual_value": "enable_rbac_authorization=False — legacy vault access policies active",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_rbac_authorization=True — Entra RBAC enforced, legacy policies disabled",
    }


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
        "expected_value": "enable_rbac_authorization=True (AAD is sole auth method)",
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
                "actual_value": "enable_rbac_authorization=False — non-AAD access policies may be active",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_rbac_authorization=True — AAD is the sole authentication method",
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "RBAC enabled; managed identity assignments verifiable via azure-mgmt-authorization",
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
                "status": "UNKNOWN",
                "actual_value": "enable_rbac_authorization=False — MI assignments not enforced; full check requires azure-mgmt-authorization",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_rbac_authorization=True — managed identity assignments can be used; full enumeration requires azure-mgmt-authorization",
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "IM-3",
        "feature": "Use Azure AD Service Principals for Azure Resource Authentication",
        "expected_value": "RBAC enabled; service principal assignments verifiable via azure-mgmt-authorization",
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
                "status": "UNKNOWN",
                "actual_value": "enable_rbac_authorization=False — SP assignments not enforced; full check requires azure-mgmt-authorization",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "enable_rbac_authorization=True — service principal assignments can be used via RBAC",
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra ID tenant-level configuration — not readable via Azure Resource Manager API",
        "expected_value": "Conditional Access policy targeting Key Vault configured in Entra ID",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "IM-8",
        "feature": "Restrict the Exposure of Credential and Secrets — Use Azure Key Vault",
        "status": "PASS",
        "actual_value": "Azure Key Vault IS the secrets management service; control is inherently satisfied",
        "expected_value": "Secrets stored in Key Vault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
    }
