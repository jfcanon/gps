"""
Privileged Access checks for Azure Event Hubs (MCSB v3).

PA-1 local admin: No local admin concept for Event Hubs — management via ARM RBAC only → UNKNOWN.
PA-7 RBAC: Data plane RBAC via Entra ID (Azure Event Hubs Data Owner/Sender/Receiver roles) → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "status": "UNKNOWN",
        "actual_value": "Event Hubs has no local administrator account concept. SAS key access represents 'local auth' — disable via disable_local_auth=True (see IM-1). ARM management is exclusively via Azure RBAC.",
        "expected_value": "disable_local_auth=True AND ARM RBAC follows least-privilege",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/security-baseline",
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Event Hubs data plane RBAC uses built-in roles: Azure Event Hubs Data Owner, Data Sender, Data Receiver. Role assignments are not readable per-namespace via Event Hubs ARM — use azure-mgmt-authorization for enumeration.",
        "expected_value": "Data plane roles follow least-privilege (Sender/Receiver, not Owner)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-azure-active-directory",
    }
