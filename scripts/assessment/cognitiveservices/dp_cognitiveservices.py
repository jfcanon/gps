"""
Data Protection checks for Azure Cognitive Services (MCSB v3).

DP-2: Purview data classification — UNKNOWN (service-level).
DP-3: Static PASS (HTTPS enforced).
DP-4: Static PASS (platform-managed at rest).
DP-5: account.properties.encryption.key_source == 'Microsoft.KeyVault' → PASS.
DP-6: CMK + identity → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient


def _get_accounts(client, rg, name):
    if rg and name:
        return [client.accounts.get(rg, name)]
    elif rg:
        return list(client.accounts.list_by_resource_group(rg))
    else:
        return list(client.accounts.list())


def check_dp2_data_classification(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention — Data Classification via Microsoft Purview",
        "status": "UNKNOWN",
        "actual_value": "Data classification for Cognitive Services is managed via Microsoft Purview at the tenant level. Not ARM-readable per account.",
        "expected_value": "Sensitive data discovered and classified via Microsoft Purview",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/purview/overview",
    }


def check_dp3_tls_transit(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "status": "PASS",
        "actual_value": "Azure Cognitive Services enforces HTTPS (TLS 1.2+) on all endpoints. HTTP is not supported.",
        "expected_value": "HTTPS with TLS 1.2+ (enforced, not ARM-configurable off)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/security-baseline#dp-3-encrypt-sensitive-data-in-transit",
    }


def check_dp4_platform_keys(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Cognitive Services data at rest is encrypted with Microsoft-managed keys by default.",
        "expected_value": "Microsoft-managed encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/encryption/cognitive-services-encryption-keys-portal",
    }


def check_dp5_cmk(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "DP-5", "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "expected_value": "account.properties.encryption.key_source == 'Microsoft.KeyVault'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/encryption/cognitive-services-encryption-keys-portal",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            enc = getattr(acct, "encryption", None)
            key_source = str(getattr(enc, "key_source", "") or "") if enc else ""
            if key_source.lower() == "microsoft.keyvault":
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": f"encryption.key_source={key_source} — CMK enabled"}
                first_pass = first_pass or r
            elif not key_source or key_source.lower() == "microsoft.cognitiveservices":
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": f"encryption.key_source={key_source or 'not set'} — using platform-managed keys"}
            else:
                return {**base, "resource": acct.name, "status": "UNKNOWN",
                        "actual_value": f"encryption.key_source={key_source} — unexpected value"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_mgmt(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "DP-6", "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "CMK enabled AND managed identity assigned",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/encryption/cognitive-services-encryption-keys-portal",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            enc = getattr(acct, "encryption", None)
            key_source = str(getattr(enc, "key_source", "") or "") if enc else ""
            identity = getattr(acct, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            has_cmk = key_source.lower() == "microsoft.keyvault"
            has_identity = identity and identity_type.lower() not in ("none", "")
            if has_cmk and has_identity:
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": f"CMK enabled; identity.type={identity_type}"}
                first_pass = first_pass or r
            elif not has_cmk:
                return {**base, "resource": acct.name, "status": "UNKNOWN",
                        "actual_value": f"CMK not enabled (key_source={key_source or 'not set'})"}
            else:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": f"CMK enabled but identity.type={identity_type} — KV access may fail"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
