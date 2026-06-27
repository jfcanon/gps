"""
Identity Management checks for Azure File Sync (MCSB v3).

IM-3 SP: StorageSyncService uses service principal for AAD auth from on-prem agents → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.storagesync import MicrosoftStorageSync


def check_im3_service_principals(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-3",
            "feature": "Use Azure AD Managed Identities — Service Principals for Agent Authentication",
            "status": "UNKNOWN",
            "actual_value": "Azure File Sync agents authenticate to the StorageSyncService using an Azure AD app registration (service principal) per-server. The SP configuration is on the server agent side, not on the ARM StorageSyncService resource.",
            "expected_value": "File Sync agents registered with AAD app registration (service principal); managed identity not supported for agent auth",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-server-registration"}
