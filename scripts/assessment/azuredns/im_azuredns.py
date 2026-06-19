"""
Identity Management checks for Azure DNS (MCSB v3).

All IM controls: DNS query plane for Public zones is unauthenticated (RFC 1035 DNS protocol).
DNS Zone is a passive hosting service making no outbound service connections.
Management plane access is ARM-enforced with Entra ID (not per-zone configurable).
All UNKNOWN static (not_applicable_paas).

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "IM-1",
        "feature": "Disable Local Authentication Methods",
        "status": "UNKNOWN",
        "actual_value": (
            "DNS query plane for Public zones is unauthenticated by protocol design (RFC 1035). "
            "There is no local authentication mechanism to disable — DNS queries carry no credentials. "
            "Management plane access to zone CRUD operations is enforced by ARM with Entra ID. "
            "No disable_local_auth property exists on the DNS Zone resource. Not Applicable."
        ),
        "expected_value": "N/A — DNS protocol has no authentication; management plane auto-enforces Entra ID via ARM",
        "evidence_url": _EVIDENCE,
    }


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required",
        "status": "UNKNOWN",
        "actual_value": (
            "DNS query and response traffic is unauthenticated (DNS protocol). "
            "ARM management plane for zone CRUD automatically requires Entra ID authentication — this is not "
            "a per-zone configurable property. No aad_auth_only flag exists on DNS Zone resource. "
            "Not Applicable as a checkable control."
        ),
        "expected_value": "N/A — DNS queries unauthenticated by protocol; ARM management plane auto-enforces Entra ID",
        "evidence_url": _EVIDENCE,
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "IM-3",
        "feature": "Managed Identities for Azure Service Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DNS Zone is a passive DNS hosting service. It receives DNS queries and responds per zone records. "
            "It makes no outbound connections to other Azure services. "
            "Managed Identity is for services that call other Azure services on behalf of a workload — "
            "DNS Zone has no such outbound service dependency requiring MI. Not Applicable."
        ),
        "expected_value": "N/A — DNS Zone makes no outbound service connections; MI not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": (
            "DNS Zone makes no outbound connections and has no service principal assignment. "
            "Service principals are used BY OPERATORS/AUTOMATION to manage DNS zone records via ARM API — "
            "that is PA-7 (RBAC) scope, not IM-3 on the zone resource itself. Not Applicable."
        ),
        "expected_value": "N/A — DNS Zone resource has no SP assignment; SP usage by operators is PA-7 scope",
        "evidence_url": _EVIDENCE,
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Conditional Access policies are enforced at the Entra ID level for ARM management plane access. "
            "DNS query plane has no authentication and therefore no Conditional Access concept. "
            "CA on management plane is a subscription/tenant-level Entra ID policy, not a per-zone control. "
            "Not Applicable as a per-zone checkable property."
        ),
        "expected_value": "N/A — CA applies at Entra ID level; DNS query plane has no authentication",
        "evidence_url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "IM-8",
        "feature": "Key/Secret/Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": "Azure DNS Zone stores no secrets, keys, or certificates. KV secret management is not applicable to the zone resource.",
        "expected_value": "N/A — DNS Zone stores no secrets; KV not applicable",
        "evidence_url": _EVIDENCE,
    }
