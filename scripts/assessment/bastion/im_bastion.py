"""
Identity Management checks for Azure Bastion (MCSB v3).

IM-1 Azure AD Auth Data Plane: PASS static (microsoft_managed/True/True).
    Bastion access is authenticated via Entra ID through the Azure portal.
    Portal session token validates identity before Bastion connection is initiated.
    Management plane only — no separate data plane auth surface exposed.

IM-8 KV SSH Key Secrets: LIVE→UNKNOWN.
    final_verdict=customer (True/False) — customer can store SSH keys in KV and use
    them for Bastion native client connections. No ARM property on BastionHost
    reflects whether KV-backed SSH keys are in use. Connection-time behavioral
    pattern. Enumerate bastions to confirm scope, then UNKNOWN.

IM-1 Local Auth / IM-3×2 MI+SP / IM-7 CA: UNKNOWN static.
    All feature_supported=False or Not Applicable in MCSB v3 baseline.
    Bastion has no local auth, MI, SP, or Conditional Access data plane.

Read-only. Zero ARM writes.
SDK: azure-mgmt-network (IM-8 scope enumeration only).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_EVIDENCE_KV = "https://learn.microsoft.com/en-us/azure/bastion/bastion-connect-vm-ssh-linux#akv"
_NIC_NOTE = "Azure Bastion is a managed jump host with no customer-accessible data plane auth surface; "


def _get_bastions(client, resource_group, bastion_name):
    if bastion_name and resource_group:
        return [client.bastion_hosts.get(resource_group, bastion_name)]
    elif resource_group:
        return list(client.bastion_hosts.list(resource_group))
    else:
        return list(client.bastion_hosts.list_all())


def check_im1_aad_auth(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
        "status": "PASS",
        "actual_value": "microsoft_managed — Bastion access authenticated via Entra ID through Azure portal or CLI. Portal session validates identity before Bastion connection is initiated. feature_supported=True, enabled_by_default=True.",
        "expected_value": "microsoft_managed — Entra ID auth enforced by platform",
        "evidence_url": _EVIDENCE,
    }


def check_im1_local_auth(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "IM-1",
        "feature": "Local Authentication Methods for Data Plane Access",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "feature_supported=False in MCSB v3 baseline. Bastion has no local authentication methods (no local username/password). All access via Entra ID. not_applicable.",
        "expected_value": "N/A — feature_supported=False; no local auth in Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "IM-3",
        "feature": "Managed Identities",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "feature_supported=False in MCSB v3 baseline. Bastion makes no outbound Azure service calls requiring Managed Identity. MI applies to VMs and workloads accessed via Bastion — not to Bastion itself. not_applicable.",
        "expected_value": "N/A — feature_supported=False; MI not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "feature_supported=Not Applicable in MCSB v3 baseline. Bastion makes no outbound service calls requiring Service Principal identity. not_applicable.",
        "expected_value": "N/A — feature_supported=Not Applicable; SP not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access for Data Plane",
        "status": "UNKNOWN",
        "actual_value": _NIC_NOTE + "feature_supported=Not Applicable in MCSB v3 baseline. Conditional Access targets Entra ID-authenticated data planes with explicit app registration. Bastion connectivity itself is not a CA-evaluable data plane endpoint. CA applies to Azure portal access (the management plane). not_applicable for Bastion data plane.",
        "expected_value": "N/A — feature_supported=Not Applicable; CA data plane not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        bastions = _get_bastions(client, resource_group, bastion_name)
        scope_note = f"Found {len(bastions)} bastion host(s) in scope. "
    except Exception as e:
        scope_note = f"Error enumerating bastions ({e}). "

    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "IM-8",
        "feature": "Service Credential and Secrets Support Integration in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": scope_note + "SSH private keys can be stored in Azure Key Vault and used for Bastion native client SSH sessions (Azure portal > Connect > SSH > Azure Key Vault). This is a connection-time behavioral pattern — no ARM property on BastionHost reflects KV usage. Verify via Azure Policy audit or manual review of connection workflow documentation.",
        "expected_value": "SSH private keys stored in Azure Key Vault for Bastion native client connections",
        "evidence_url": _EVIDENCE_KV,
    }
