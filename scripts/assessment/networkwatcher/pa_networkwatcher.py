"""
Privileged Access checks for Azure Network Watcher (MCSB v3).

PA-7: True, enabled_by_default=False → ARM RBAC enforced → PASS static.
      NW Contributor role; ARM guarantees RBAC enforcement.
PA-1/8: UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PA-1", "feature": "Local Admin Accounts", "status": "UNKNOWN", "actual_value": "Managed ARM service; no local admin concept. Access via ARM RBAC with Entra ID (Network Watcher Contributor or Network Contributor role).", "expected_value": "N/A — ARM RBAC only; no local admin", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/required-rbac-permissions"}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "PA-7",
        "feature": "Azure RBAC for Data Plane",
        "status": "PASS",
        "actual_value": (
            "Network Watcher operations are governed by Azure RBAC via ARM. "
            "Feature supported=True in MCSB v3 baseline. "
            "Built-in roles: Network Watcher Contributor (full NW access), "
            "Network Contributor (broader network management). "
            "ARM enforces RBAC at platform level — no per-resource configuration needed. "
            "There is no separate data-plane RBAC surface; all operations go through ARM."
        ),
        "expected_value": "Azure RBAC (ARM) governs all NW operations — Network Watcher Contributor role (microsoft enforced)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/required-rbac-permissions",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PA-8", "feature": "Customer Lockbox", "status": "UNKNOWN", "actual_value": "Azure Network Watcher not in Customer Lockbox supported services GA list.", "expected_value": "N/A — not in Lockbox supported services", "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"}
