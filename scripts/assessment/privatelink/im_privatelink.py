"""
Identity Management checks for Azure Private Link / Private Endpoint (MCSB v3).

IM-1×2/IM-3×2/IM-7/IM-8: UNKNOWN static — PE is a network resource.
    It has no data plane authentication concept (it is a NIC).
    All IM controls require an authenticated data plane — which PE does not have.
    Management plane access uses standard ARM RBAC via Entra ID.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
_NIC_NOTE = "Private Endpoint is a NIC resource with no data plane authentication; "


def check_im1_aad_auth(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "PE has no data plane (it is a NIC routing traffic to a PaaS service). Data plane authentication belongs to the connected service, not the PE. not_applicable at PE resource level.",
        "expected_value": "N/A — PE has no data plane authentication concept",
        "evidence_url": _EVIDENCE,
    }


def check_im1_local_auth(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "IM-1",
        "feature": "Local Authentication Methods for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "No local authentication concept on PE. not_applicable at PE resource level.",
        "expected_value": "N/A — no local auth concept on PE",
        "evidence_url": _EVIDENCE,
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "IM-3",
        "feature": "Managed Identities",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "PE makes no outbound Azure service calls requiring Managed Identity. MI applies to the workload consuming the PE, not the PE NIC itself. not_applicable at PE resource level.",
        "expected_value": "N/A — PE has no Managed Identity concept",
        "evidence_url": _EVIDENCE,
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "PE makes no outbound Azure service calls requiring Service Principal. not_applicable at PE resource level.",
        "expected_value": "N/A — PE has no Service Principal concept",
        "evidence_url": _EVIDENCE,
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access for Data Plane",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "PE has no Entra ID-authenticated data plane; Conditional Access targets authenticated data planes. CA applies to the connected service, not the PE NIC. not_applicable at PE resource level.",
        "expected_value": "N/A — PE has no authenticated data plane; CA not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "IM-8",
        "feature": "Service Credential and Secrets Support Integration in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "PE has no credential or secret store; KV integration not applicable at PE resource level.",
        "expected_value": "N/A — PE has no credential store; KV secrets N/A",
        "evidence_url": _EVIDENCE,
    }
