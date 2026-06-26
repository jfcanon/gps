"""
Data Protection checks for Azure Data Factory (MCSB v3).

DP-1: Purview data classification — UNKNOWN.
DP-3: Static PASS (HTTPS enforced for all ADF communications).
DP-4: Static PASS (platform-managed at rest).
DP-5: factory.properties.encryption.vaultBaseUrl set → CMK → PASS.
DP-6: CMK + managed identity → PASS.
DP-7: Linked services for KV-backed certs → UNKNOWN (linked service level).

Read-only. Zero ARM writes.
"""
from azure.mgmt.datafactory import DataFactoryManagementClient


def _get_factories(client, rg, name):
    if rg and name:
        return [client.factories.get(rg, name)]
    elif rg:
        return list(client.factories.list_by_resource_group(rg))
    else:
        return list(client.factories.list())


def check_dp1_data_classification(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification — Microsoft Purview Integration",
        "status": "UNKNOWN",
        "actual_value": "ADF can connect to Microsoft Purview for data lineage and classification, but this is configured at the Purview account level, not the ADF factory ARM resource.",
        "expected_value": "ADF purviewConfiguration.purviewResourceId set",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/connect-data-factory-to-azure-purview",
    }


def check_dp3_tls_transit(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "DP-3",
        "feature": "Encrypt Data in Transit",
        "status": "PASS",
        "actual_value": "Azure Data Factory enforces HTTPS/TLS for all control plane and orchestration communications. Self-hosted IR connections use TLS. Data plane encryption depends on connected data store.",
        "expected_value": "HTTPS enforced for ADF control plane (default, not ARM-configurable off)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations",
    }


def check_dp4_platform_keys(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "ADF factory metadata (pipeline definitions, linked services, datasets) is encrypted at rest with Microsoft-managed keys by default.",
        "expected_value": "Microsoft-managed encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/enable-customer-managed-key",
    }


def check_dp5_cmk(credential, subscription_id, resource_group, factory_name):
    base = {
        "control_id": "DP-5", "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "expected_value": "factory.properties.encryption.vaultBaseUrl set (CMK via Key Vault)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/enable-customer-managed-key",
    }
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        factories = _get_factories(client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            enc = getattr(factory, "encryption", None)
            vault_url = getattr(enc, "vault_base_url", None) if enc else None
            if vault_url:
                key_name = getattr(enc, "key_name", "") if enc else ""
                r = {**base, "resource": factory.name, "status": "PASS",
                     "actual_value": f"CMK enabled; vault={str(vault_url)[:50]}; key={key_name}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": factory.name, "status": "FAIL",
                        "actual_value": "encryption.vaultBaseUrl not set — using platform-managed keys"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_mgmt(credential, subscription_id, resource_group, factory_name):
    base = {
        "control_id": "DP-6", "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "CMK enabled AND managed identity assigned",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/enable-customer-managed-key",
    }
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        factories = _get_factories(client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            enc = getattr(factory, "encryption", None)
            vault_url = getattr(enc, "vault_base_url", None) if enc else None
            identity = getattr(factory, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if vault_url and identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": factory.name, "status": "PASS",
                     "actual_value": f"CMK enabled; identity.type={identity_type}"}
                first_pass = first_pass or r
            elif not vault_url:
                return {**base, "resource": factory.name, "status": "UNKNOWN",
                        "actual_value": "CMK not configured — platform-managed keys"}
            else:
                return {**base, "resource": factory.name, "status": "FAIL",
                        "actual_value": f"CMK configured but identity.type={identity_type}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp7_cert_kv(credential, subscription_id, resource_group, factory_name):
    return {
        "resource": factory_name or "all", "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": "ADF credential/certificate management via Key Vault is configured in linked service definitions (not the factory ARM resource). Credentials stored in KV are accessed via managed identity at runtime.",
        "expected_value": "Linked services reference Key Vault for credentials (not inline secrets)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/store-credentials-in-key-vault",
    }
