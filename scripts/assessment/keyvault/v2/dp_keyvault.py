"""
Data Protection checks for Azure Key Vault (MCSB v3).

DP-2: Network ACL restriction as exfil-surface control (now_applicable_native).
DP-3: TLS minimum version check.
DP-4: Platform-managed keys — SKU confirms MS-managed key backing.
DP-5: CMK — KV manages CMKs for others; KV metadata uses MS-managed HSMs → UNKNOWN.
DP-6: Key management → PASS (KV IS the service).
DP-7: Certificate management → PASS (KV IS the service).

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


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "DP-2",
        "feature": "Monitor Anomalies and Threats Targeting Sensitive Data",
        "expected_value": "public_network_access=Disabled OR network_acls.default_action=Deny",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            props = vault.properties
            pub_access = getattr(props, "public_network_access", "Enabled")
            acls = getattr(props, "network_acls", None)
            default_action = getattr(acls, "default_action", "Allow") if acls else "Allow"
            if pub_access == "Disabled" or default_action == "Deny":
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"public_network_access={pub_access}, network_acls.default_action={default_action} — exfil surface restricted"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pub_access}, network_acls.default_action={default_action} — unrestricted public access"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "expected_value": "minimum_tls_version in (TLS1_2, TLS1_3)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/tls",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            tls = getattr(vault.properties, "minimum_tls_version", None)
            if tls in ("1.2", "TLS1_2", "1.3", "TLS1_3"):
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"minimum_tls_version={tls}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "FAIL",
                        "actual_value": f"minimum_tls_version={tls} — TLS 1.2+ not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    base = {
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "expected_value": "sku.name=standard or premium (Microsoft-managed key backing confirmed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features",
    }
    try:
        client = KeyVaultManagementClient(credential, subscription_id)
        vaults = _get_vaults(client, resource_group, vault_name)
        if not vaults:
            return {**base, "resource": vault_name or "none", "status": "PASS",
                    "actual_value": "No Key Vault instances found in scope"}
        first_pass = None
        for vault in vaults:
            sku = getattr(getattr(vault.properties, "sku", None), "name", None)
            sku_str = str(sku).lower() if sku else None
            if sku_str in ("standard", "premium"):
                r = {**base, "resource": vault.name, "status": "PASS",
                     "actual_value": f"sku={sku} — Microsoft-managed platform keys active"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vault.name, "status": "UNKNOWN",
                        "actual_value": f"sku={sku} — unable to confirm platform key backing"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vault_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "status": "UNKNOWN",
        "actual_value": "Key Vault manages CMKs for other Azure services; KV service metadata is encrypted with Microsoft-managed HSMs — customer CMK for KV-at-rest metadata is not supported",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features",
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "status": "PASS",
        "actual_value": "Azure Key Vault IS the key management service — control inherently satisfied",
        "expected_value": "Keys stored in Azure Key Vault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys",
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management using Azure Key Vault",
        "status": "PASS",
        "actual_value": "Azure Key Vault IS the certificate management service — control inherently satisfied",
        "expected_value": "Certificates stored in Azure Key Vault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates",
    }
