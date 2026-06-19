"""
Privileged Access checks for Azure Front Door (MCSB v3).

PA-1: Not Applicable — PaaS; no compute; no local admin.
PA-7: False, Not Applicable — ARM RBAC enforced; customer assigns roles; UNKNOWN static.
PA-8: Not Applicable — Customer Lockbox not available for AFD.

All UNKNOWN static.
Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview"


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PA-1",
        "feature": "Limit Local Administrator Accounts",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN; no compute substrate; no local administrator concept applicable.",
        "expected_value": "N/A — PaaS; no compute; local admin control not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PA-7",
        "feature": "Limit Access to Azure Resources via RBAC — AFD Management",
        "status": "UNKNOWN",
        "actual_value": (
            "ARM RBAC is enforced for AFD management plane (create/update/delete Front Door, routing rules, endpoints). "
            "Built-in roles: 'Front Door Profile Reader', 'Contributor', 'Owner'. "
            "Customer must assign least-privilege RBAC roles for operators. "
            "RBAC correctness is not checkable via read-only ARM without RBAC enumeration scope. "
            "Feature=False in MCSB v3 baseline — no per-AFD RBAC property checkable on resource."
        ),
        "expected_value": "Customer configures least-privilege RBAC for AFD management plane operators",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/security-controls-policy",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "PA-8",
        "feature": "Microsoft Support Process — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox is not available for Azure Front Door. AFD resource data (routing config, WAF rules) is not customer PII requiring explicit approval flow.",
        "expected_value": "N/A — Customer Lockbox not applicable to AFD",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
