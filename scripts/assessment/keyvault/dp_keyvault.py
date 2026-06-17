"""
Data Protection checks for Azure Key Vault (MCSB v3).

DP-2: Data Leakage/Loss Prevention (proxy: public_network_access / network_acls.default_action)
DP-3: TLS minimum version check.
DP-4: Platform-managed keys (HSM backing).
DP-5: Customer-Managed Keys — KV manages keys for other services; KV itself uses
      Microsoft-managed HSMs → UNKNOWN (no customer CMK for KV-at-rest metadata).
DP-6: Key management in Key Vault → automatic PASS (KV IS the service).
DP-7: Certificate management in Key Vault → automatic PASS (KV IS the service).

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
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "expected_value": "public_network_access == Disabled OR network_acls.default_action == Deny",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        properties = getattr(vault, "properties", None)
        pna = getattr(properties, "public_network_access", None)
        network_acls = getattr(properties, "network_acls", None)
        default_action = getattr(network_acls, "default_action", None)
        if pna == "Disabled" or default_action == "Deny":
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"public_network_access={pna}, network_acls.default_action={default_action}",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "Public access restricted by public_network_access or network ACL default deny",
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "expected_value": "minimum_tls_version in (1.2, 1.3)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/tls",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        tls = getattr(vault.properties, "minimum_tls_version", None)
        if tls in ("1.2", "TLS1_2", "1.3", "TLS1_3"):
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "FAIL",
                "actual_value": f"minimum_tls_version={tls}",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": "TLS 1.2+ enforced",
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    client = KeyVaultManagementClient(credential, subscription_id)
    vaults = _get_vaults(client, resource_group, vault_name)
    base = {
        "resource": vault_name or resource_group or subscription_id,
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "expected_value": "Premium SKU (HSM-backed) or Standard SKU with Microsoft-managed keys",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features",
    }
    if not vaults:
        return {**base, "status": "UNKNOWN", "actual_value": "No Key Vault instances found in scope"}

    first_pass = None
    for vault in vaults:
        sku_name = getattr(getattr(vault.properties, "sku", None), "name", None)
        if sku_name and str(sku_name).lower() in ("standard", "premium"):
            if first_pass is None:
                first_pass = vault.name
        else:
            return {
                **base,
                "resource": vault.name,
                "status": "UNKNOWN",
                "actual_value": f"sku={sku_name} — unable to confirm platform key backing",
            }

    return {
        **base,
        "resource": first_pass or vault_name or "all",
        "status": "PASS",
        "actual_value": f"Key Vault uses Microsoft-managed platform keys for at-rest encryption",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "status": "UNKNOWN",
        "actual_value": "Key Vault manages CMKs for other services; KV service metadata encrypted with Microsoft-managed HSMs — customer CMK for KV-at-rest not supported",
        "expected_value": "N/A",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features",
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "status": "PASS",
        "actual_value": "Azure Key Vault IS the key management service; control is inherently satisfied",
        "expected_value": "Service stores keys in Key Vault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys",
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, vault_name: str | None) -> dict:
    return {
        "resource": vault_name or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management using Azure Key Vault",
        "status": "PASS",
        "actual_value": "Azure Key Vault IS the certificate management service; control is inherently satisfied",
        "expected_value": "Service stores certificates in Key Vault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates",
    }
