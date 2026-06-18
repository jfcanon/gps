"""
Data Protection checks for Azure Firewall (MCSB v3).

DP-1: No data stored by firewall → UNKNOWN static.
DP-2: No DLP product for Firewall → UNKNOWN static.
DP-3: Premium — transport_security.certificate_authority set → TLS inspection active → PASS proxy.
DP-4: Platform-managed keys, Microsoft-managed → PASS static.
DP-5: No CMK option on Firewall → UNKNOWN static.
DP-6: Premium — transport_security.certificate_authority.key_vault_secret_id + identity → PASS.
DP-7: Premium — transport_security.certificate_authority.key_vault_secret_id set → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_firewalls(client: NetworkManagementClient, resource_group: str | None, firewall_name: str | None) -> list:
    if resource_group and firewall_name:
        return [client.azure_firewalls.get(resource_group, firewall_name)]
    elif resource_group:
        return list(client.azure_firewalls.list(resource_group))
    else:
        return list(client.azure_firewalls.list_all())


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification",
        "status": "UNKNOWN",
        "actual_value": "Azure Firewall does not store or process customer data at rest; it inspects transiting network traffic. Purview/AIP data classification does not apply to firewall rule sets.",
        "expected_value": "N/A — no customer data stored by Azure Firewall",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/overview",
    }


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": "No DLP product integration for Azure Firewall. Application rule collections with FQDN filtering provide outbound traffic control as a compensating control.",
        "expected_value": "N/A — no dedicated DLP solution for Azure Firewall",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/features",
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption — TLS Inspection",
        "expected_value": "sku.tier='Premium' and transport_security.certificate_authority set (TLS inspection active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/premium-features#tls-inspection",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            sku = getattr(fw, "sku", None)
            tier = getattr(sku, "tier", "Standard") if sku else "Standard"
            if str(tier) != "Premium":
                return {**base, "resource": fw.name, "status": "UNKNOWN",
                        "actual_value": f"sku.tier={tier} — TLS inspection requires Premium SKU; transit encryption enforced by underlying TLS but deep inspection not available"}
            transport_sec = getattr(fw, "transport_security", None)
            ca = getattr(transport_sec, "certificate_authority", None) if transport_sec else None
            if ca:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": "Premium SKU; transport_security.certificate_authority configured — TLS inspection active"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "Premium SKU but transport_security.certificate_authority not configured — TLS inspection disabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "PASS",
        "actual_value": "Azure Firewall derived certificates and backend state are encrypted using Microsoft-managed platform keys. This is the default and non-configurable — DP-4 is microsoft_managed for this service.",
        "expected_value": "Platform-managed encryption enabled by default (microsoft_managed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#dp-4-enable-data-at-rest-encryption-by-default",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": "Azure Firewall does not support customer-managed keys. The service does not store customer data requiring CMK encryption; derived certificates are encrypted with platform keys.",
        "expected_value": "N/A — CMK not supported; no customer data at rest",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required",
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "expected_value": "Premium SKU; transport_security.certificate_authority.key_vault_secret_id set and firewall.identity present",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/premium-certificates#azure-key-vault",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            sku = getattr(fw, "sku", None)
            tier = getattr(sku, "tier", "Standard") if sku else "Standard"
            if str(tier) != "Premium":
                return {**base, "resource": fw.name, "status": "UNKNOWN",
                        "actual_value": f"sku.tier={tier} — Key Vault cert integration only available on Premium SKU"}
            transport_sec = getattr(fw, "transport_security", None)
            ca = getattr(transport_sec, "certificate_authority", None) if transport_sec else None
            kv_secret_id = getattr(ca, "key_vault_secret_id", None) if ca else None
            identity = getattr(fw, "identity", None)
            if kv_secret_id and identity:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"Premium SKU; KV secret ID configured and managed identity present — KV-backed cert in use"}
                first_pass = first_pass or r
            elif kv_secret_id and not identity:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "KV secret ID set but no managed identity — firewall cannot authenticate to Key Vault"}
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "Premium SKU but transport_security.certificate_authority.key_vault_secret_id not configured — KV cert integration not active"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "expected_value": "Premium SKU; transport_security.certificate_authority.key_vault_secret_id set (KV-managed intermediate CA cert)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/premium-certificates",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            sku = getattr(fw, "sku", None)
            tier = getattr(sku, "tier", "Standard") if sku else "Standard"
            if str(tier) != "Premium":
                return {**base, "resource": fw.name, "status": "UNKNOWN",
                        "actual_value": f"sku.tier={tier} — KV certificate management only available on Premium SKU (TLS inspection feature)"}
            transport_sec = getattr(fw, "transport_security", None)
            ca = getattr(transport_sec, "certificate_authority", None) if transport_sec else None
            kv_secret_id = getattr(ca, "key_vault_secret_id", None) if ca else None
            if kv_secret_id:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"Premium SKU; intermediate CA cert stored in Key Vault (key_vault_secret_id configured) — certificate lifecycle managed via KV"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": "Premium SKU but transport_security.certificate_authority.key_vault_secret_id not set — certificate not managed via Key Vault"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
