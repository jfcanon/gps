"""
Identity Management checks for Azure Key Vault (MCSB v3).

IM-1: enable_rbac_authorization=True → Entra enforced (PASS); False → legacy policies (FAIL).
IM-3: RBAC active proxy — MI and SP assignments possible when RBAC enabled.
IM-7: Conditional Access — Entra tenant-level, not ARM-readable → UNKNOWN.
IM-8: KV Secrets → PASS (KV IS the secrets service).

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
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth",
        "expected_value": "enable_rbac_authorization=True (vault access policies disabled)",
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
                     "actual_value": "enable_rbac_authorization=True — legacy vault access policies disabled, Entra enforced"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "enable_rbac_authorization=False — legacy vault access policies active (local auth methods enabled)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
        "expected_value": "enable_rbac_authorization=True (AAD is the sole authentication method)",
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
                     "actual_value": "enable_rbac_authorization=True — AAD/Entra ID is the sole authentication method"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": "enable_rbac_authorization=False — vault access policies allow non-AAD authentication paths"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "enable_rbac_authorization=True (MI RBAC assignments possible)",
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
                     "actual_value": "enable_rbac_authorization=True — managed identity RBAC assignments supported; full enumeration requires azure-mgmt-authorization"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "UNKNOWN",
                        "actual_value": "enable_rbac_authorization=False — RBAC not active; vault policies may grant MI access but without least-privilege enforcement"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Service Principals for Azure Resource Authentication",
        "expected_value": "enable_rbac_authorization=True (SP RBAC assignments possible)",
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
                     "actual_value": "enable_rbac_authorization=True — service principal RBAC assignments supported; full enumeration requires azure-mgmt-authorization"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "UNKNOWN",
                        "actual_value": "enable_rbac_authorization=False — RBAC not active; vault policies may grant SP access without RBAC granularity"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


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
        "actual_value": "Azure Key Vault IS the secrets management service — control inherently satisfied",
        "expected_value": "Secrets stored in Azure Key Vault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
    }
