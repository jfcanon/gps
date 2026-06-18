"""
Identity Management checks for Azure Firewall Manager (MCSB v3).
IM-1 AAD: False, Not Applicable → no separate data-plane auth → UNKNOWN static.
All IM controls UNKNOWN static — AFM is management-plane policy config resource.
Read-only. Zero ARM writes.
"""


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "IM-1", "feature": "Local Authentication Methods for Data Plane Access", "status": "UNKNOWN", "actual_value": "Firewall Policy is an ARM-only resource; no local authentication concept applies. All management via ARM RBAC with Entra ID.", "expected_value": "N/A — ARM-only; no local auth surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "IM-1", "feature": "Azure AD Authentication Required for Data Plane Access", "status": "UNKNOWN", "actual_value": "Feature=False in MCSB v3 baseline — no separate data-plane auth surface for Firewall Policy; all ops via ARM with Entra ID. Platform-enforced at ARM level.", "expected_value": "N/A — no data plane; ARM enforces Entra ID for all policy management ops", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "IM-3", "feature": "Managed Identities", "status": "UNKNOWN", "actual_value": "Firewall Policy supports Managed Identity assignment (used for pulling TLS certs from Key Vault for Premium SKU) but this is not a customer-configurable MCSB control — it is a prerequisite for DP-7 KV cert integration.", "expected_value": "N/A — MI is a pre-requisite for DP-7, not an independent MCSB control for this resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/deploy-trusted-security-partner"}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "IM-3", "feature": "Service Principals", "status": "UNKNOWN", "actual_value": "No data-plane SP auth for Firewall Policy; SP used at subscription/RG level for ARM management only.", "expected_value": "N/A — ARM RBAC only; no data-plane SP auth surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "IM-7", "feature": "Conditional Access for Data Plane", "status": "UNKNOWN", "actual_value": "No data plane for Firewall Policy; CA applies at Entra ID/ARM level. Feature=Not Applicable in MCSB v3.", "expected_value": "N/A — no data plane; CA not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "IM-8", "feature": "Service Credential and Secrets Support Integration and Storage in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Firewall Policy stores no service credentials. KV integration exists only for TLS cert (captured in DP-7); no standalone secret management surface.", "expected_value": "N/A — no credentials/secrets surface; KV covered in DP-7", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}
