"""
Identity Management checks for Azure Network Watcher (MCSB v3).

IM-1 AAD: True, enabled_by_default=False → ARM-only; no local auth concept → PASS static.
          NW operations require ARM RBAC with Entra ID; microsoft enforced.
IM-1 local / IM-3 / IM-7 / IM-8: all UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "IM-1", "feature": "Local Authentication Methods for Data Plane Access", "status": "UNKNOWN", "actual_value": "Network Watcher is an ARM-only service; no local authentication method exists for NW operations. All access via ARM RBAC with Entra ID. No local auth surface to disable.", "expected_value": "N/A — ARM-only; no local auth concept", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
        "status": "PASS",
        "actual_value": (
            "Network Watcher operations exclusively use ARM RBAC with Azure Entra ID authentication. "
            "Feature supported=True in MCSB v3 baseline. No local authentication method exists — "
            "Entra ID is the only identity provider for NW. ARM enforces this at platform level; "
            "no per-resource configuration needed."
        ),
        "expected_value": "Entra ID (Azure AD) authentication required for all NW operations (microsoft enforced via ARM)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/required-rbac-permissions",
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "IM-3", "feature": "Managed Identities", "status": "UNKNOWN", "actual_value": "Network Watcher does not support Managed Identity assignment. NW is a passive monitoring service; it does not call other Azure services that would require a managed identity.", "expected_value": "N/A — NW does not support MI", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "IM-3", "feature": "Service Principals", "status": "UNKNOWN", "actual_value": "No data-plane SP auth for NW resource; SP used only for ARM management at subscription/RG level for NW operations.", "expected_value": "N/A — ARM RBAC only; no data-plane SP auth surface", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "IM-7", "feature": "Conditional Access for Data Plane", "status": "UNKNOWN", "actual_value": "NW has no data plane; CA applies at Entra ID/ARM level not per-NW resource. Feature=False in MCSB v3 baseline.", "expected_value": "N/A — no data plane; CA not applicable to NW resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "IM-8", "feature": "Service Credential and Secrets Support Integration and Storage in Azure Key Vault", "status": "UNKNOWN", "actual_value": "Network Watcher stores no credentials or secrets; KV integration not applicable to NW resource.", "expected_value": "N/A — no credentials/secrets surface on NW", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}
