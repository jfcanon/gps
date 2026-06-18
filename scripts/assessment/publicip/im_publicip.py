"""
Identity Management checks for Azure Public IP (MCSB v3).

All IM controls: PIP is a network addressing object with no auth surface or data plane.
ARM RBAC controls management of the resource at the subscription/RG level → all UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "IM-1", "feature": "Local Authentication Methods for Data Plane Access", "status": "UNKNOWN", "actual_value": "Azure Public IP has no data plane or management interface requiring authentication. All operations are via ARM with Entra ID identity enforcement. No local auth concept exists.", "expected_value": "N/A — no local auth; ARM RBAC only", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "IM-1", "feature": "Azure AD Authentication Required for Data Plane Access", "status": "UNKNOWN", "actual_value": "No data plane exists on Azure Public IP. ARM enforces Entra ID authentication for all management operations. No per-resource AAD auth toggle applies.", "expected_value": "N/A — ARM RBAC enforces Entra ID auth for all management ops", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "IM-3", "feature": "Managed Identities", "status": "UNKNOWN", "actual_value": "Azure Public IP does not support managed identity assignment. MI applies to services that need to authenticate to other Azure services — PIP is a passive address resource with no authentication requirements.", "expected_value": "N/A — no MI support on PIP resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "IM-3", "feature": "Service Principals", "status": "UNKNOWN", "actual_value": "No service principal authentication concept for Azure Public IP data plane. Service principals may be used for ARM management operations at subscription/RG level only.", "expected_value": "N/A — no data-plane SP auth for PIP", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "IM-7", "feature": "Conditional Access for Data Plane", "status": "UNKNOWN", "actual_value": "No customer data plane exists on Azure Public IP. Conditional Access applies at Entra ID/ARM level for management operations — not per-PIP resource.", "expected_value": "N/A — no data plane; CA is ARM-level", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "IM-8", "feature": "Service Credential and Secrets Support Integration and Storage in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Azure Public IP stores no credentials or secrets. KV secret integration is not applicable to this resource.", "expected_value": "N/A — no secrets/credentials on PIP", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}
