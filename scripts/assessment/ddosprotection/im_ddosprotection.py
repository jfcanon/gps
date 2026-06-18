"""
Identity Management checks for Azure DDoS Protection (MCSB v3).
IM-1/3/7/8: ARM RBAC only; no data plane; all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "IM-1", "feature": "Local Authentication Methods for Data Plane Access", "status": "UNKNOWN", "actual_value": "No data plane or management interface requiring local auth; all ops via ARM with Entra ID.", "expected_value": "N/A — ARM RBAC only; no local auth concept", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "IM-1", "feature": "Azure AD Authentication Required for Data Plane Access", "status": "UNKNOWN", "actual_value": "No data plane; ARM enforces Entra ID auth for all management ops on DDoS plan.", "expected_value": "N/A — ARM RBAC only; no separate data-plane auth surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "IM-3", "feature": "Managed Identities", "status": "UNKNOWN", "actual_value": "DDoS Protection Plan does not support MI assignment; passive control-plane resource with no auth requirements of its own.", "expected_value": "N/A — control-plane resource; no MI concept", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "IM-3", "feature": "Service Principals", "status": "UNKNOWN", "actual_value": "No data-plane SP auth for DDoS plan; SP used only for ARM management at subscription/RG level.", "expected_value": "N/A — ARM RBAC only", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "IM-7", "feature": "Conditional Access for Data Plane", "status": "UNKNOWN", "actual_value": "No data plane; CA applies at Entra ID/ARM level, not per-DDoS-plan resource.", "expected_value": "N/A — ARM RBAC only; no data-plane CA surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "IM-8", "feature": "Service Credential and Secrets Support Integration and Storage in Azure Key Vault", "status": "UNKNOWN", "actual_value": "DDoS plan stores no credentials or secrets; KV integration not applicable.", "expected_value": "N/A — PaaS; no secrets surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}
