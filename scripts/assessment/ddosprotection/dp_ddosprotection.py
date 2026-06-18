"""
Data Protection checks for Azure DDoS Protection (MCSB v3).
DP-1 through DP-7: DDoS plan stores no customer data — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-1", "feature": "Sensitive Data Discovery and Classification", "status": "UNKNOWN", "actual_value": "Azure DDoS Protection Plan is a network protection configuration object; stores no customer data. Purview/AIP not applicable.", "expected_value": "N/A — PaaS; no customer data", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-2", "feature": "Data Leakage/Loss Prevention", "status": "UNKNOWN", "actual_value": "No DLP product for DDoS plan; no data storage.", "expected_value": "N/A — PaaS; no data storage", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-3", "feature": "Data in Transit Encryption", "status": "UNKNOWN", "actual_value": "Control-plane only resource; all management ops via ARM HTTPS. No data-plane traffic passes through the DDoS plan object itself.", "expected_value": "N/A — PaaS; ARM HTTPS enforced by platform", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-4", "feature": "Data at Rest Encryption Using Platform Keys", "status": "UNKNOWN", "actual_value": "DDoS plan stores no customer data at rest; ARM metadata encrypted by platform.", "expected_value": "N/A — PaaS; no customer data at rest", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-5", "feature": "Data at Rest Encryption Using CMK", "status": "UNKNOWN", "actual_value": "CMK not supported; no customer data at rest on DDoS plan.", "expected_value": "N/A — PaaS; CMK not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-6", "feature": "Key Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "No keys/secrets/certificates associated with DDoS plan; KV integration not applicable.", "expected_value": "N/A — PaaS; no key management surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "DP-7", "feature": "Certificate Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "DDoS plan uses no certificates; KV cert management not applicable.", "expected_value": "N/A — PaaS; no certificate concept", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}
