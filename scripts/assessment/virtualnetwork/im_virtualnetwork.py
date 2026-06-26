"""
Identity Management checks for Azure Virtual Network (MCSB v3).
VNet is network infrastructure — IM controls not applicable. All UNKNOWN.
"""


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth",
        "status": "UNKNOWN",
        "actual_value": "Azure Virtual Network has no local authentication concept. Management is exclusively via Azure ARM RBAC (Entra ID). No per-VNet auth setting to check.",
        "expected_value": "N/A — ARM RBAC only",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/security-baseline",
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "status": "UNKNOWN",
        "actual_value": "Azure Virtual Network is network infrastructure and does not support Managed Identity assignment. Workloads within the VNet (VMs, App Services) should use managed identities.",
        "expected_value": "N/A — managed identity assigned to workloads within VNet, not VNet itself",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/security-baseline",
    }
