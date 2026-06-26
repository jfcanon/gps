"""
Data Protection checks for Azure Event Hubs (MCSB v3).

DP-3: namespace.minimum_tls_version == '1.2' → PASS.
DP-4: Platform-managed encryption at rest (static PASS).
DP-5: namespace.encryption.key_source == 'Microsoft.KeyVault' → CMK enabled → PASS.
DP-6: CMK + managed identity → KV-backed key management → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventhub import EventHubManagementClient


def _get_namespaces(client: EventHubManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit — Minimum TLS Version",
        "expected_value": "namespace.minimum_tls_version == '1.2'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/transport-layer-security-configure-minimum-version",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            min_tls = str(getattr(ns, "minimum_tls_version", "") or "1.0")
            if min_tls in ("1.2", "1.3"):
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"minimum_tls_version={min_tls}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"minimum_tls_version={min_tls} — TLS 1.2+ not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Event Hubs data is encrypted at rest with Microsoft-managed keys by default on all tiers.",
        "expected_value": "Microsoft-managed platform key encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/encrypt-data-at-rest-with-cmk",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "expected_value": "namespace.encryption.key_source == 'Microsoft.KeyVault' (CMK enabled — requires Premium tier)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/encrypt-data-at-rest-with-cmk",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            encryption = getattr(ns, "encryption", None)
            key_source = str(getattr(encryption, "key_source", "") or "") if encryption else ""
            if key_source.lower() == "microsoft.keyvault":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"encryption.key_source={key_source} — CMK enabled"}
                first_pass = first_pass or r
            elif not encryption or not key_source:
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": "encryption property not set or not returned — namespace may use platform-managed keys (standard tier)"}
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"encryption.key_source={key_source} — not using Key Vault CMK"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "CMK (key_source=Microsoft.KeyVault) AND managed identity assigned",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/encrypt-data-at-rest-with-cmk",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            identity = getattr(ns, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            has_identity = identity and identity_type.lower() not in ("none", "")
            encryption = getattr(ns, "encryption", None)
            key_source = str(getattr(encryption, "key_source", "") or "") if encryption else ""
            has_cmk = key_source.lower() == "microsoft.keyvault"
            if has_cmk and has_identity:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"CMK enabled (key_source={key_source}); identity.type={identity_type}"}
                first_pass = first_pass or r
            elif not has_cmk:
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": f"CMK not enabled (key_source={key_source or 'not set'}) — using platform-managed keys"}
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"CMK enabled but no managed identity (identity.type={identity_type}) — KV access will fail"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
