"""
Identity Management checks for Azure Front Door (MCSB v3).

IM-8: True, False → LIVE — KV cert source on frontend endpoints (same path as DP-7).
IM-1/3/7: UNKNOWN static — AFD data plane is unauthenticated HTTP/S; no local auth, no MI outbound.

Read-only. Zero ARM writes.
"""
from azure.mgmt.frontdoor import FrontDoorManagementClient

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview"


def _get_front_doors(client: FrontDoorManagementClient, resource_group: str | None, front_door_name: str | None) -> list:
    if resource_group and front_door_name:
        return [client.front_doors.get(resource_group, front_door_name)]
    elif resource_group:
        return list(client.front_doors.list_by_resource_group(resource_group))
    else:
        return list(client.front_doors.list())


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "IM-1",
        "feature": "Disable Local Authentication Methods",
        "status": "UNKNOWN",
        "actual_value": (
            "AFD is a PaaS CDN/WAF proxy. Data plane connections are HTTP/S — "
            "AFD does not authenticate end-user traffic (that is done by backend apps). "
            "There is no local auth mechanism to disable on AFD resource. "
            "Management plane uses ARM with Entra ID. Not Applicable."
        ),
        "expected_value": "N/A — PaaS CDN; no local auth concept; management plane auto-enforces Entra ID",
        "evidence_url": _EVIDENCE,
    }


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required",
        "status": "UNKNOWN",
        "actual_value": (
            "AFD does not authenticate end-user traffic with Entra ID — authentication is handled by backend applications. "
            "AFD-to-origin connections use HTTP/S with optional private link. "
            "No disable_local_auth property on AFD resource. Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — AFD data plane does not authenticate traffic; backends handle auth",
        "evidence_url": _EVIDENCE,
    }


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "IM-3",
        "feature": "Managed Identities for Azure Service Access",
        "status": "UNKNOWN",
        "actual_value": (
            "AFD Classic (azure-mgmt-frontdoor) has no MI support. "
            "AFD Standard/Premium supports System-assigned MI for Key Vault certificate retrieval (GA 2023), "
            "but this is not checkable via the Classic FrontDoor SDK. "
            "Feature=Not Applicable in MCSB v3 baseline for Classic. "
            "Note: for AFD Standard/Premium, check profile.identity via CdnManagementClient if needed."
        ),
        "expected_value": "N/A — AFD Classic has no MI; AFD Premium MI for KV cert not checkable via Classic SDK",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/managed-identity",
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": "AFD resource makes no outbound service calls requiring SP identity. Operators use SP/MI to manage AFD via ARM — that is PA-7 scope, not IM-3 on the AFD resource.",
        "expected_value": "N/A — AFD resource has no SP assignment; SP usage by operators is PA-7 scope",
        "evidence_url": _EVIDENCE,
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "CA is enforced at Entra ID level for ARM management plane. AFD data plane is public HTTP/S with no CA concept. No per-AFD CA property. Feature=False in MCSB v3 baseline.",
        "expected_value": "N/A — CA applies at Entra ID level; AFD data plane has no CA concept",
        "evidence_url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    base = {
        "control_id": "IM-8",
        "feature": "Restrict Credential/Secret Exposure — Azure Key Vault",
        "expected_value": "HTTPS enabled; certificate_source=AzureKeyVault on frontend endpoints (KV manages cert lifecycle)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-custom-domain-https",
    }
    try:
        client = FrontDoorManagementClient(credential, subscription_id)
        front_doors = _get_front_doors(client, resource_group, front_door_name)
        if not front_doors:
            return {**base, "resource": front_door_name or "none", "status": "PASS",
                    "actual_value": "No Front Door instances found in scope"}
        first_pass = None
        for fd in front_doors:
            endpoints = getattr(fd, "frontend_endpoints", None) or []
            kv_endpoints = []
            non_kv_endpoints = []
            for ep in endpoints:
                cfg = getattr(ep, "custom_https_configuration", None)
                src = getattr(cfg, "certificate_source", None) if cfg else None
                if src == "AzureKeyVault":
                    kv_endpoints.append(ep.name)
                else:
                    non_kv_endpoints.append(ep.name)
            if kv_endpoints:
                r = {**base, "resource": fd.name, "status": "PASS",
                     "actual_value": f"KV-backed cert on endpoint(s): {kv_endpoints}; AFD-managed or unconfigured: {non_kv_endpoints}"}
                first_pass = first_pass or r
            elif non_kv_endpoints:
                return {**base, "resource": fd.name, "status": "FAIL",
                        "actual_value": (
                            f"No KV-backed certificates on any endpoint. "
                            f"Endpoints without KV cert: {non_kv_endpoints}. "
                            "Configure certificate_source=AzureKeyVault for KV-managed cert lifecycle."
                        )}
            else:
                r = {**base, "resource": fd.name, "status": "PASS",
                     "actual_value": "No frontend endpoints found on this Front Door instance"}
                first_pass = first_pass or r
        return first_pass
    except Exception as e:
        return {**base, "resource": front_door_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
