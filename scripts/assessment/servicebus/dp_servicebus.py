"""
Data Protection checks for Azure Service Bus (MCSB v3).

DP-2: public_network_access=Disabled → exfil surface restricted → PASS.
DP-3: minimum_tls_version in (1.2 / 1.3) → PASS.
DP-4: All SKUs encrypted with MS-managed keys by default → auto-PASS (static).
DP-5: CMK via KV — Premium SKU only; encryption.key_source=Microsoft.KeyVault → PASS.
DP-6: KV used for CMK key management — scriptable for Premium; UNKNOWN for non-Premium.
DP-7: TLS cert management — Microsoft-managed infrastructure; not ARM-checkable → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.servicebus import ServiceBusManagementClient


def _get_namespaces(client: ServiceBusManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-2",
        "feature": "Monitor Anomalies and Threats Targeting Sensitive Data",
        "expected_value": "public_network_access=Disabled (exfil surface restricted)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/network-security",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            pub_access = str(getattr(ns, "public_network_access", "Enabled"))
            if pub_access.lower() == "disabled":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "public_network_access=Disabled — exfil surface restricted"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pub_access} — network exfil surface not restricted"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "expected_value": "minimum_tls_version in (1.2, 1.3)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/transport-layer-security-configure-minimum-version",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            tls = str(getattr(ns, "minimum_tls_version", "1.0"))
            if tls in ("1.2", "1.3"):
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"minimum_tls_version={tls}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"minimum_tls_version={tls} — TLS 1.2+ not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Service Bus encrypts all data at rest with Microsoft-managed keys by default across all SKUs (Basic, Standard, Premium). No configuration required.",
        "expected_value": "Microsoft-managed platform key encryption enabled by default",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-encryption",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "expected_value": "encryption.key_source=Microsoft.KeyVault (Premium SKU only)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/configure-customer-managed-key",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            sku = str(getattr(getattr(ns, "sku", None), "name", "Standard"))
            if sku.lower() != "premium":
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": f"SKU={sku} — CMK at rest requires Premium tier; not configurable on {sku}"}
            enc = getattr(ns, "encryption", None)
            key_source = getattr(enc, "key_source", None) if enc else None
            if key_source == "Microsoft.KeyVault":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "Premium SKU; encryption.key_source=Microsoft.KeyVault — CMK active"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"Premium SKU but encryption.key_source={key_source} — CMK not configured; using MS-managed keys"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "Premium SKU with encryption.key_source=Microsoft.KeyVault",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/configure-customer-managed-key",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            sku = str(getattr(getattr(ns, "sku", None), "name", "Standard"))
            if sku.lower() != "premium":
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": f"SKU={sku} — KV-managed keys (CMK) require Premium tier; {sku} uses MS-managed keys only"}
            enc = getattr(ns, "encryption", None)
            key_source = getattr(enc, "key_source", None) if enc else None
            if key_source == "Microsoft.KeyVault":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "Premium SKU; cryptographic keys managed via Azure Key Vault (CMK active)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"Premium SKU but key_source={key_source} — KV key management not configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management using Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": "Service Bus TLS certificates are managed by Microsoft infrastructure. Customer-managed TLS certificate configuration via Azure Key Vault is not exposed as an ARM-readable property on namespace resources.",
        "expected_value": "N/A — Microsoft manages Service Bus TLS infrastructure certificates",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/transport-layer-security-configure-minimum-version",
    }
