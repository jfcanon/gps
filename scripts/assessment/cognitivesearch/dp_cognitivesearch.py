"""
Data Protection checks for Azure Cognitive Search (MCSB v3).

DP-3: Static PASS (HTTPS enforced, not ARM-configurable off).
DP-4: Static PASS (platform-managed at rest).
DP-5: service.encryption_with_cmk.key_vault_key_url set → PASS.
DP-6: CMK + managed identity → KV-backed key → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.search import SearchManagementClient


def _get_services(client, rg, name):
    if rg and name:
        return [client.services.get(rg, name)]
    elif rg:
        return list(client.services.list_by_resource_group(rg))
    else:
        return list(client.services.list_by_subscription())


def check_dp3_tls_transit(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all",
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "status": "PASS",
        "actual_value": "Azure Cognitive Search enforces HTTPS on all endpoints. HTTP is disabled by default and cannot be re-enabled via ARM.",
        "expected_value": "HTTPS enforced (not ARM-configurable)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-overview#encrypted-transmissions",
    }


def check_dp4_platform_keys(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Cognitive Search indexes are encrypted at rest with Microsoft-managed keys by default.",
        "expected_value": "Microsoft-managed encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-manage-encryption-keys",
    }


def check_dp5_cmk(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "expected_value": "service.encryption_with_cmk.key_vault_key_url set",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-manage-encryption-keys",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No search services found"}
        first_pass = None
        for svc in services:
            enc = getattr(svc, "encryption_with_cmk", None)
            kv_url = getattr(enc, "key_vault_key_url", None) if enc else None
            if kv_url:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"encryption_with_cmk.key_vault_key_url set: {str(kv_url)[:60]}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": "encryption_with_cmk.key_vault_key_url not set — using platform-managed keys only"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_mgmt(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "CMK set AND managed identity or KV access policy in place",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-manage-encryption-keys",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No search services found"}
        first_pass = None
        for svc in services:
            enc = getattr(svc, "encryption_with_cmk", None)
            kv_url = getattr(enc, "key_vault_key_url", None) if enc else None
            identity = getattr(svc, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if kv_url and identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"CMK enabled; identity.type={identity_type}"}
                first_pass = first_pass or r
            elif not kv_url:
                return {**base, "resource": svc.name, "status": "UNKNOWN",
                        "actual_value": "CMK not configured — using platform-managed keys"}
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": f"CMK configured but identity.type={identity_type} — KV access may fail"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
