"""
Privileged Access checks for Azure Bastion (MCSB v3).

PA-1/PA-7/PA-8: UNKNOWN static — all feature_supported=False, final_verdict=not_applicable.

PA-1 Local Admin: Bastion has no compute substrate; no local admin account concept.
PA-7 RBAC Data Plane: Bastion explicitly does not support data plane RBAC.
    Baseline note: "Azure Bastion itself does not support Azure RBAC for users access."
    ARM RBAC applies to managing the Bastion resource, not to session initiation.
PA-8 Customer Lockbox: Not in Lockbox supported service list. Not applicable.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PA-1",
        "feature": "Local Admin Accounts",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=False in MCSB v3 baseline. Azure Bastion is a PaaS managed jump host — no compute substrate, no local administrative account concept. All management via ARM with Entra ID. not_applicable.",
        "expected_value": "N/A — feature_supported=False; no local admin concept in Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PA-7",
        "feature": "Azure RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=False in MCSB v3 baseline. Azure Bastion explicitly does not support Azure RBAC for user access to sessions (MCSB v3 baseline note). ARM RBAC (e.g., Network Contributor) controls management-plane operations on the Bastion resource. Data-plane RBAC for session initiation does not exist. not_applicable.",
        "expected_value": "N/A — feature_supported=False; data plane RBAC not supported by Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "PA-8",
        "feature": "Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=False in MCSB v3 baseline. Customer Lockbox is not available for Azure Bastion. Bastion is not in the Lockbox supported service list. Microsoft support access to Bastion infrastructure does not go through the Lockbox approval workflow. not_applicable.",
        "expected_value": "N/A — feature_supported=False; Lockbox not supported for Bastion",
        "evidence_url": _EVIDENCE,
    }
