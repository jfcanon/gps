"""
Privileged Access checks for Azure Firewall Manager (MCSB v3).
PA-1/7/8: ARM RBAC only; no data plane; not in Lockbox — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "PA-1", "feature": "Local Admin Accounts", "status": "UNKNOWN", "actual_value": "Managed ARM resource; no local admin concept. Access via ARM RBAC with Entra ID (Network Contributor or custom role with firewall policy permissions).", "expected_value": "N/A — ARM RBAC only; no local admin", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "PA-7", "feature": "Azure RBAC for Data Plane", "status": "UNKNOWN", "actual_value": "Feature=Not Applicable in MCSB v3 — Firewall Policy has no separate data plane. All management via ARM RBAC. Network Contributor or Firewall Policy Contributor role controls access.", "expected_value": "N/A — ARM RBAC only; no separate data-plane RBAC surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"}


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "PA-8", "feature": "Customer Lockbox", "status": "UNKNOWN", "actual_value": "Azure Firewall Manager / Firewall Policy not in Customer Lockbox supported services GA list.", "expected_value": "N/A — not in Lockbox supported services", "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"}
