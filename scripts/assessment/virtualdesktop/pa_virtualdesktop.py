"""
PA checks for Azure Virtual Desktop (MCSB v3).

PA-1: Local admin accounts on session hosts → UNKNOWN (session host OS level).
PA-7: ARM RBAC for AVD data plane → PASS (AVD uses ARM RBAC exclusively).

Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(c, s, r, n):
    return {"resource": n or "all", "control_id": "PA-1",
            "feature": "Separate and Limit Highly Privileged/Administrative Users — Local Admin Accounts",
            "status": "UNKNOWN",
            "actual_value": "Local admin account restriction on session hosts is enforced via Intune/GPO at session host OS level. Not readable from AVD workspace ARM resource.",
            "expected_value": "Local admin accounts disabled or restricted on session hosts via policy",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#pa-1-separate-and-limit-highly-privileged-administrative-users"}


def check_pa7_rbac_data_plane(c, s, r, n):
    return {"resource": n or "all", "control_id": "PA-7",
            "feature": "Follow Just Enough Administration Principle — Azure RBAC for Data Plane",
            "status": "PASS",
            "actual_value": "Azure Virtual Desktop uses Azure RBAC for all management and data plane access. Built-in roles: Desktop Virtualization User (assign application groups), Contributor, Reader. No separate API key system.",
            "expected_value": "Least-privilege RBAC roles (Desktop Virtualization User for end users)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/rbac"}
