"""
Data Protection checks for Azure Firewall Manager (MCSB v3).

DP-3: True, True → microsoft_managed → PASS static.
      AFM management API uses HTTPS/TLS by default; platform-enforced.
DP-4: microsoft_managed → PASS static.
      Policy configuration encrypted at rest by platform-managed keys.
DP-7: True, False → LIVE check.
      Premium SKU + transport_security.certificate_authority.key_vault_secret_id set → PASS;
      Standard/Basic → UNKNOWN (TLS inspection is Premium-only feature);
      Premium but no KV cert configured → FAIL.
DP-1/2/5/6: N/A — policy stores rule config only; no customer data.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_firewall_policies(client: NetworkManagementClient, resource_group: str | None, policy_name: str | None) -> list:
    if resource_group and policy_name:
        return [client.firewall_policies.get(resource_group, policy_name)]
    elif resource_group:
        return list(client.firewall_policies.list(resource_group))
    else:
        return list(client.firewall_policies.list_all())


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "DP-1", "feature": "Sensitive Data Discovery and Classification", "status": "UNKNOWN", "actual_value": "Firewall Policy stores rule collections and configuration metadata only; no customer PII or business data. Purview/AIP not applicable.", "expected_value": "N/A — policy config only; no customer data", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "DP-2", "feature": "Data Leakage/Loss Prevention", "status": "UNKNOWN", "actual_value": "No DLP product for Firewall Policy resource; policy stores rule config only, no customer data.", "expected_value": "N/A — no customer data storage", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "PASS",
        "actual_value": (
            "Azure Firewall Manager / Firewall Policy management API uses HTTPS/TLS 1.2+ by default — "
            "platform-enforced. Feature supported=True, enabled_by_default=True in MCSB v3 baseline. "
            "All ARM API calls to Firewall Policy are encrypted in transit; no configuration required."
        ),
        "expected_value": "HTTPS/TLS 1.2+ enforced by platform (microsoft_managed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview",
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "PASS",
        "actual_value": (
            "Firewall Policy configuration data (rule collections, threat intelligence settings) is encrypted "
            "at rest with Microsoft-managed keys by default — platform-enforced. "
            "No customer configuration required for baseline encryption."
        ),
        "expected_value": "Platform-managed keys for policy data at rest (microsoft_managed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "DP-5", "feature": "Data at Rest Encryption Using CMK", "status": "UNKNOWN", "actual_value": "CMK not supported for Firewall Policy resource. Policy stores rule configuration only; no CMK concept applicable.", "expected_value": "N/A — CMK not supported on Firewall Policy", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "DP-6", "feature": "Key Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Firewall Policy resource holds no encryption keys. Key Vault integration applies only to TLS certificate (DP-7 / transport_security) for Premium SKU policies.", "expected_value": "N/A — key management not applicable to policy resource itself", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "expected_value": "Premium SKU: transport_security.certificate_authority.key_vault_secret_id set (TLS inspection cert stored in KV)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/deploy-trusted-security-partner",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_firewall_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "none", "status": "PASS",
                    "actual_value": "No Firewall Policy instances found in scope"}
        first_pass = None
        for policy in policies:
            sku_tier = getattr(getattr(policy, "sku", None), "tier", "Standard") or "Standard"
            if sku_tier != "Premium":
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": f"sku.tier={sku_tier} — TLS inspection (IDPS/cert) is Premium SKU feature only; Standard/Basic policies do not support KV cert integration"}
                first_pass = first_pass or r
                continue
            ts = getattr(policy, "transport_security", None)
            ca = getattr(ts, "certificate_authority", None) if ts else None
            kv_ref = getattr(ca, "key_vault_secret_id", None) if ca else None
            if kv_ref:
                r = {**base, "resource": policy.name, "status": "PASS",
                     "actual_value": f"sku.tier=Premium; transport_security.certificate_authority.key_vault_secret_id set — TLS inspection cert managed in Key Vault"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": policy.name, "status": "FAIL",
                        "actual_value": "sku.tier=Premium but transport_security.certificate_authority.key_vault_secret_id not set — TLS inspection cert not configured in Key Vault; IDPS/TLS inspection may be using self-signed or no cert"}
        return first_pass
    except Exception as e:
        return {**base, "resource": policy_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
