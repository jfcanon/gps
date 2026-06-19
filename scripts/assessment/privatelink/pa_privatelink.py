"""
Privileged Access checks for Azure Private Link / Private Endpoint (MCSB v3).

PA-1/PA-7/PA-8: UNKNOWN static — PE is a PaaS network resource.
    No compute substrate → no local admin concept.
    No data plane → no data plane RBAC concept (management plane RBAC is standard ARM).
    Customer Lockbox: not_applicable (not in supported service list).

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PA-1",
        "feature": "Local Admin Accounts",
        "status": "UNKNOWN",
        "actual_value": "PaaS network resource (NIC); no compute substrate; no local administrative account concept on Private Endpoint. not_applicable in MCSB v3 baseline.",
        "expected_value": "N/A — PaaS NIC; no compute; local admin N/A",
        "evidence_url": _EVIDENCE,
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PA-7",
        "feature": "Azure RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Private Endpoint has no data plane (it is a NIC routing traffic); data plane RBAC concept does not apply. Management plane access uses standard Azure RBAC via ARM (Network Contributor role). not_applicable in MCSB v3 baseline.",
        "expected_value": "N/A — PE has no data plane; data plane RBAC N/A",
        "evidence_url": _EVIDENCE,
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "PA-8",
        "feature": "Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox is not available for Private Endpoint. feature_supported=Not Applicable in MCSB v3 baseline. Lockbox covers specific Azure services; PE is not in that set.",
        "expected_value": "N/A — Customer Lockbox not available for PE; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }
