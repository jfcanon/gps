"""
Data Protection checks for Azure Network Watcher (MCSB v3).

DP-3: True, enabled_by_default=True → microsoft_managed → PASS static.
      NW management API uses HTTPS/TLS by default; platform-enforced.
DP-4: microsoft_managed keys → PASS static.
      Flow log configs and packet capture metadata encrypted by platform-managed keys by default.
DP-1/2/5/6/7: NW stores operational metadata only; no customer PII/secrets — UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "DP-1", "feature": "Sensitive Data Discovery and Classification", "status": "UNKNOWN", "actual_value": "Network Watcher stores operational metadata (flow log configurations, packet capture specs) only; no customer PII or business data. Purview/AIP not applicable.", "expected_value": "N/A — operational metadata only; no customer data", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "DP-2", "feature": "Data Leakage/Loss Prevention", "status": "UNKNOWN", "actual_value": "No DLP product for NW resource; no customer data storage. Flow log output goes to Storage Account (customer-controlled) — apply DLP on that storage.", "expected_value": "N/A — DLP applies to storage account holding flow logs, not NW resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "PASS",
        "actual_value": (
            "Network Watcher management API uses HTTPS/TLS 1.2+ by default — platform-enforced. "
            "Feature supported=True, enabled_by_default=True in MCSB v3 baseline. "
            "All ARM API calls to NW are encrypted in transit; no configuration required. "
            "Flow log data written to Storage Account uses HTTPS (enforced on storage endpoint)."
        ),
        "expected_value": "HTTPS/TLS 1.2+ enforced by platform (microsoft_managed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview",
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "PASS",
        "actual_value": (
            "Any customer content stored by Network Watcher (flow log configuration metadata, packet capture "
            "spec metadata) is encrypted at rest with Microsoft-managed keys by default — platform-enforced. "
            "Actual flow log data resides in customer Storage Account where encryption is separately configurable."
        ),
        "expected_value": "Platform-managed keys for NW resource metadata (microsoft_managed, no customer action required)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "DP-5", "feature": "Data at Rest Encryption Using CMK", "status": "UNKNOWN", "actual_value": "CMK not supported for NW resource metadata. CMK for flow log data applies to the Storage Account where logs are stored — configure CMK on that storage resource.", "expected_value": "N/A — CMK not supported on NW resource; apply to storage account", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "DP-6", "feature": "Key Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "NW resource holds no keys or secrets. Key Vault integration applies to Storage Account encryption (for flow log data) — not to NW resource itself.", "expected_value": "N/A — KV integration not applicable to NW resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "DP-7", "feature": "Certificate Management in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Network Watcher uses no certificates; KV certificate management not applicable.", "expected_value": "N/A — no certificate concept for NW resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}
