"""
Data Protection checks for Azure Public IP (MCSB v3).

DP-1 through DP-7: PIP is a network addressing object; stores no customer data.
No encryption, CMK, KV, TLS, or DLP concept applies → all UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-1", "feature": "Sensitive Data Discovery and Classification", "status": "UNKNOWN", "actual_value": "Azure Public IP is a network addressing object; it does not store or process customer data. Purview/AIP classification tools do not apply.", "expected_value": "N/A — no customer data stored", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-2", "feature": "Data Leakage/Loss Prevention", "status": "UNKNOWN", "actual_value": "No DLP product integration for Azure Public IP. PIP is an address assignment resource with no data storage.", "expected_value": "N/A — no customer data stored", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-3", "feature": "Data in Transit Encryption", "status": "UNKNOWN", "actual_value": "Azure Public IP is a Layer 3 addressing resource; TLS/encryption is enforced by the application or service using the IP, not by the PIP resource itself.", "expected_value": "N/A — encryption enforced by the resource using the PIP, not the PIP itself", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-4", "feature": "Data at Rest Encryption Using Platform Keys", "status": "UNKNOWN", "actual_value": "Azure Public IP stores only IP address metadata (address, SKU, allocation method). ARM resource metadata is encrypted by Azure platform at rest, but there is no customer data at rest on this resource.", "expected_value": "N/A — no customer data at rest", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-5", "feature": "Data at Rest Encryption Using CMK", "status": "UNKNOWN", "actual_value": "CMK not supported and not applicable. Azure Public IP stores no customer data requiring CMK encryption.", "expected_value": "N/A — CMK not supported; no customer data at rest", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-6", "feature": "Key Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Azure Public IP has no keys, secrets, or certificates to manage in Key Vault. KV integration is not applicable to this resource.", "expected_value": "N/A — no keys/secrets associated with PIP", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "DP-7", "feature": "Certificate Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Azure Public IP does not manage or store certificates. Certificate management applies to the service (e.g. Application Gateway, API Management) using the PIP, not the PIP resource itself.", "expected_value": "N/A — no certificates on PIP resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}
