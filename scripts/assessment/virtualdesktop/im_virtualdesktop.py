"""
Identity Management checks for Azure Virtual Desktop (MCSB v3).

IM-1 AAD: AVD requires Entra ID by design → static PASS.
IM-3 MI: workspace.identity.type assigned → PASS.
IM-3 SP: UNKNOWN (hostpool/session host level).
IM-7 CA: UNKNOWN (tenant-level Entra ID policy).

Read-only. Zero ARM writes.
"""
from azure.mgmt.desktopvirtualization import DesktopVirtualizationMgmtClient


def _get_workspaces(client, rg, name):
    if rg and name:
        return [client.workspaces.get(rg, name)]
    elif rg:
        return list(client.workspaces.list_by_resource_group(rg))
    else:
        try:
            return list(client.workspaces.list())
        except Exception:
            return []


def check_im1_aad_auth(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-1",
            "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
            "status": "PASS",
            "actual_value": "Azure Virtual Desktop requires Microsoft Entra ID (AAD) authentication for all user connections. Local account desktop access is blocked by design at the AVD service level.",
            "expected_value": "Entra ID authentication required (enforced by AVD service)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#im-1-use-centralized-identity-and-authentication-system"}


def check_im3_managed_identities(credential, subscription_id, resource_group, workspace_name):
    base = {"control_id": "IM-3", "feature": "Use Azure AD Managed Identities — Managed Identity Assigned",
            "expected_value": "workspace.identity.type assigned",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#im-3-use-azure-ad-managed-identities-for-service-authentication"}
    try:
        client = DesktopVirtualizationMgmtClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "UNKNOWN",
                    "actual_value": "No workspaces found — provide --resource-group"}
        first_pass = None
        for ws in workspaces:
            identity = getattr(ws, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity assigned"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-3",
            "feature": "Use Azure AD Managed Identities — Service Principals",
            "status": "UNKNOWN",
            "actual_value": "Service principal usage for AVD connectors (e.g., FSLogix storage auth) is at session host config level, not AVD workspace ARM.",
            "expected_value": "Prefer managed identity over service principal for storage/KV access",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#im-3-use-azure-ad-managed-identities-for-service-authentication"}


def check_im7_conditional_access(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-7",
            "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
            "status": "UNKNOWN",
            "actual_value": "CA policies for AVD are applied in Entra ID at tenant level to the Azure Virtual Desktop application registration. Not readable per workspace via ARM.",
            "expected_value": "CA policies applied to AVD Entra ID application (require MFA, compliant device)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-mfa"}
