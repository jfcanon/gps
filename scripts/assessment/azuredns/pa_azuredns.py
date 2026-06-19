"""
Privileged Access checks for Azure DNS (MCSB v3).

PA-1: No compute substrate — not applicable.
PA-7: ARM RBAC enforced for DNS zone management; DNS query plane for Public zones is
      unauthenticated (DNS protocol). Customer must assign correct roles. UNKNOWN static.
PA-8: Customer Lockbox not applicable to Azure DNS.

All UNKNOWN static.
Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PA-1",
        "feature": "Limit Local Administrator Accounts",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS Zone; no compute substrate; no local administrator concept applicable.",
        "expected_value": "N/A — PaaS; no compute; local admin control not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PA-7",
        "feature": "Limit Access to Azure Resources via RBAC — DNS Zone Management",
        "status": "UNKNOWN",
        "actual_value": (
            "ARM RBAC is enforced for DNS zone management plane (create/update/delete zone and records). "
            "Built-in roles: 'DNS Zone Contributor' (manage zones not VNets), 'Private DNS Zone Contributor'. "
            "HOWEVER: DNS query plane for Public zones is unauthenticated by protocol (RFC 1035) — "
            "any resolver can query a Public DNS Zone; RBAC does not apply to DNS queries. "
            "Customer must assign least-privilege RBAC roles for operators; RBAC correctness "
            "is not checkable via read-only API without RBAC enumeration scope."
        ),
        "expected_value": "Customer configures DNS Zone Contributor RBAC; no RBAC on DNS query plane (Public)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/dns/dns-protect-zones-recordsets",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "PA-8",
        "feature": "Microsoft Support Process — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox is not available for Azure DNS. DNS Zone data (DNS records) is not customer PII requiring explicit approval flow for Microsoft support access.",
        "expected_value": "N/A — Customer Lockbox not applicable to Azure DNS",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
