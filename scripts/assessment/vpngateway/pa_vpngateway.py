"""
Privileged Access checks for Azure VPN Gateway (MCSB v3).

PA-7: True, True, microsoft_managed → PASS static.
    ARM RBAC enforced by default; Network Contributor or custom role for VPN GW management.

PA-1: Not Applicable → UNKNOWN static.
    PaaS; no compute; no local admin concept on VPN GW.

PA-8: False, Not Applicable → UNKNOWN static (still_not_applicable).
    Customer Lockbox not available for VPN GW.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PA-1",
        "feature": "Local Admin Accounts",
        "status": "UNKNOWN",
        "actual_value": "PaaS network service; no compute substrate; no local administrative account concept on VPN GW resource. Not Applicable in MCSB v3 baseline.",
        "expected_value": "N/A — PaaS; no local admin concept on VPN GW",
        "evidence_url": _EVIDENCE,
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PA-7",
        "feature": "Azure RBAC for Data Plane",
        "status": "PASS",
        "actual_value": (
            "ARM RBAC enforced by default for VPN GW management — "
            "feature_supported=True, enabled_by_default=True, responsibility=microsoft_managed. "
            "Built-in roles: 'Network Contributor' (full management), 'Reader' (read-only). "
            "Custom roles can scope VPN GW create/update/delete/getVpnClientIpsecParameters actions. "
            "No additional customer configuration required."
        ),
        "expected_value": "ARM RBAC enforced by default (microsoft_managed — no customer action required)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "PA-8",
        "feature": "Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox is not available for VPN Gateway. feature_supported=False in MCSB v3 baseline. Microsoft support access to VPN GW infrastructure does not go through Customer Lockbox.",
        "expected_value": "N/A — Customer Lockbox not supported for VPN GW; feature_supported=False",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
