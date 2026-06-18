"""
Privileged Access checks for Azure Application Gateway (MCSB v3).

PA-1: AppGW has no local admin / shared-key concept → UNKNOWN (not applicable).
PA-7: AppGW uses ARM RBAC for management plane only; no separate data-plane RBAC → UNKNOWN.
PA-8: Customer Lockbox — AppGW in supported list; subscription-level only → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "status": "UNKNOWN",
        "actual_value": "Application Gateway has no local administrator account or shared-key equivalent. Management access is exclusively via Azure ARM RBAC (Entra ID). There is no local-admin concept to disable on this PaaS resource.",
        "expected_value": "N/A — no local admin mechanism on Application Gateway",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles",
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Application Gateway has only a management plane (configuration via ARM RBAC). There is no separate data plane RBAC — client HTTP/S traffic is not authenticated by the gateway itself. JEA is enforced at the ARM RBAC level (use built-in roles: Reader, Contributor, Network Contributor). Full role assignment enumeration requires azure-mgmt-authorization.",
        "expected_value": "ARM RBAC role assignments follow least-privilege (Reader/specific built-in roles, not Owner/Contributor)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#network-contributor",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Azure Application Gateway is in the Customer Lockbox supported services list. Lockbox enablement is at subscription level — not readable per-gateway via ARM. Check via Azure Portal > Customer Lockbox or azure-mgmt-support.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }
