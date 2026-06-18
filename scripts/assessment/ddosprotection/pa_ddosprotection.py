"""
Privileged Access checks for Azure DDoS Protection (MCSB v3).
PA-1/7/8: ARM RBAC only; no data plane; no lockbox — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "PA-1", "feature": "Local Admin Accounts", "status": "UNKNOWN", "actual_value": "Managed control-plane resource; no local admin concept; ARM RBAC with Entra ID is the only access model (Network Contributor or DDoS Plan Contributor role).", "expected_value": "N/A — ARM RBAC only; no local admin", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "PA-7", "feature": "Azure RBAC for Data Plane", "status": "UNKNOWN", "actual_value": "No data plane; management via ARM RBAC (Network Contributor or Network DDoS Plan Contributor built-in roles).", "expected_value": "N/A — ARM RBAC only; no separate data-plane RBAC", "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"}


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "PA-8", "feature": "Customer Lockbox", "status": "UNKNOWN", "actual_value": "Azure DDoS Protection Plan not in Customer Lockbox supported services GA list.", "expected_value": "N/A — not in Lockbox supported services", "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"}
