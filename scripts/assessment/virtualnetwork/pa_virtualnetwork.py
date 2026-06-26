"""
Privileged Access checks for Azure Virtual Network (MCSB v3).
VNet management is ARM RBAC only. All UNKNOWN.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "status": "UNKNOWN",
        "actual_value": "Azure Virtual Network has no local administrator account concept. Management is exclusively via Azure ARM RBAC (Entra ID).",
        "expected_value": "N/A — ARM RBAC only",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles",
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "VNet has no data plane RBAC concept. Access is ARM RBAC at management plane only (Network Contributor, Reader, etc.).",
        "expected_value": "ARM RBAC assignments follow least-privilege (Network Contributor or more specific built-in roles)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#network-contributor",
    }
