"""
Privileged Access checks for Azure WAF Policy (MCSB v3).

PA-7: UNKNOWN static — WAF data plane is unauthenticated HTTP/S inspection;
      no data plane RBAC concept. Management plane RBAC is standard ARM.
PA-1: UNKNOWN static — PaaS; no compute; no local admin concept.
PA-8: UNKNOWN static — Customer Lockbox not available (feature_supported=False).

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PA-1",
        "feature": "Local Admin Accounts",
        "status": "UNKNOWN",
        "actual_value": "PaaS configuration resource; no compute substrate; no local admin account concept on WAF Policy. not_applicable.",
        "expected_value": "N/A — PaaS; no compute; no local admin; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PA-7",
        "feature": "Azure RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "WAF data plane is unauthenticated HTTP/S traffic inspection — no data plane RBAC concept applies. Management plane access control is standard Azure RBAC via ARM. not_applicable to data plane.",
        "expected_value": "N/A — WAF data plane = unauthenticated HTTP/S; no data plane RBAC; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "PA-8",
        "feature": "Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox not available for Azure WAF Policy. feature_supported=False in MCSB v3 baseline. Microsoft support access to WAF infrastructure does not go through Lockbox approval workflow.",
        "expected_value": "N/A — feature_supported=False; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }
