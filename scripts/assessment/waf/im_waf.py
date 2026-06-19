"""
Identity Management checks for Azure WAF Policy (MCSB v3).

All 6 controls UNKNOWN static — WAF data plane is HTTP/S inspection:
  - No data plane auth concept (traffic is unauthenticated by WAF itself; auth at app layer)
  - WAF policy makes no outbound calls requiring MI or SP
  - Conditional Access not applicable to unauthenticated HTTP/S inspection data plane
  - No credential/secret store in WAF policy resource

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"
_DP_NOTE = "WAF data plane = HTTP/S inspection; unauthenticated; "


def check_im1_aad_auth(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": _DP_NOTE + "WAF data plane inspects HTTP/S traffic without authentication; no Azure AD data plane auth concept applies. Management plane uses Entra ID via ARM.",
        "expected_value": "N/A — WAF data plane is unauthenticated HTTP/S inspection; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_im1_local_auth(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "IM-1",
        "feature": "Local Authentication Methods for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": _DP_NOTE + "No local auth concept on WAF data plane. Management plane enforces Entra ID via ARM. not_applicable.",
        "expected_value": "N/A — no local auth concept; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "IM-3",
        "feature": "Managed Identities",
        "status": "UNKNOWN",
        "actual_value": "WAF policy resource makes no outbound Azure service calls requiring Managed Identity. not_applicable.",
        "expected_value": "N/A — WAF makes no outbound calls requiring MI; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": "WAF policy resource makes no outbound Azure service calls requiring Service Principal identity. not_applicable.",
        "expected_value": "N/A — WAF makes no outbound calls requiring SP; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access for Data Plane",
        "status": "UNKNOWN",
        "actual_value": _DP_NOTE + "Conditional Access targets authenticated Entra ID data planes. WAF data plane processes unauthenticated HTTP/S traffic. CA not applicable to WAF data plane.",
        "expected_value": "N/A — unauthenticated data plane; CA not applicable; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "IM-8",
        "feature": "Service Credential and Secrets Support Integration in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": "WAF policy resource has no credential store. No KV-backed secret integration for WAF policy credentials. not_applicable.",
        "expected_value": "N/A — no credential store; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }
