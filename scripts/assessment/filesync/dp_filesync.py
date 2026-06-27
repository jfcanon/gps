"""
Data Protection checks for Azure File Sync (MCSB v3).

DP-3: PASS (HTTPS enforced for all File Sync agent traffic).
DP-4: PASS (Microsoft-managed encryption at rest).

Read-only. Zero ARM writes.
"""


def check_dp3_tls_transit(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-3", "feature": "Encrypt Data in Transit",
            "status": "PASS",
            "actual_value": "Azure File Sync enforces HTTPS (TLS 1.2+) for all agent-to-service traffic. Sync data between server endpoints and Azure file shares is always encrypted in transit.",
            "expected_value": "HTTPS enforced (default, non-configurable)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-security-baseline#dp-3-encrypt-sensitive-data-in-transit"}


def check_dp4_platform_keys(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-4", "feature": "Encrypt Data at Rest with Platform-Managed Keys",
            "status": "PASS",
            "actual_value": "Azure File Sync data at rest is encrypted using Azure Storage Service Encryption (SSE) with Microsoft-managed keys. StorageSyncService resource itself uses platform-managed encryption.",
            "expected_value": "Microsoft-managed encryption (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-security-baseline#dp-4-enable-data-at-rest-encryption-by-default"}
