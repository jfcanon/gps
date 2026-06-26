"""
Identity Management checks for Azure Cognitive Search (MCSB v3).

IM-1 AAD: service.auth_options.aad_or_api_key or disable_local_auth → PASS.
IM-1 local: API key authentication — check if disableLocalAuth / authOptions enforces AAD only.
IM-3 SP: auth_options check → UNKNOWN.
IM-7 CA: tenant-level → UNKNOWN.
PA-7: RBAC data plane → UNKNOWN.
PA-8: subscription-level → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.search import SearchManagementClient


def _get_services(client, rg, name):
    if rg and name:
        return [client.services.get(rg, name)]
    elif rg:
        return list(client.services.list_by_resource_group(rg))
    else:
        return list(client.services.list_by_subscription())


def check_im1_aad_auth(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
        "expected_value": "service.auth_options enforces AAD (aad_or_api_key or aad_only)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-rbac",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No search services found"}
        first_pass = None
        for svc in services:
            auth_opts = getattr(svc, "auth_options", None)
            aad_or_api = getattr(auth_opts, "aad_or_api_key", None) if auth_opts else None
            api_key_only = getattr(auth_opts, "api_key_only", None) if auth_opts else None
            if aad_or_api is not None:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": "auth_options.aad_or_api_key configured — AAD authentication available alongside API keys"}
                first_pass = first_pass or r
            elif api_key_only is not None:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": "auth_options.api_key_only set — AAD authentication disabled; API key only"}
            else:
                return {**base, "resource": svc.name, "status": "UNKNOWN",
                        "actual_value": "auth_options not returned — default is API key only; configure authOptions for AAD"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_local_auth_methods(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth (API Keys)",
        "expected_value": "service.disable_local_auth=True OR auth_options enforces AAD-only",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-rbac",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No search services found"}
        first_pass = None
        for svc in services:
            disable_local = getattr(svc, "disable_local_auth", None)
            auth_opts = getattr(svc, "auth_options", None)
            if disable_local is True:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — API key authentication disabled"}
                first_pass = first_pass or r
            elif auth_opts and getattr(auth_opts, "api_key_only", None) is None:
                return {**base, "resource": svc.name, "status": "UNKNOWN",
                        "actual_value": "disable_local_auth not set; API keys may be enabled"}
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": f"disable_local_auth={disable_local} — local API key auth available"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication — Service Principals",
        "status": "UNKNOWN",
        "actual_value": "Service principals for data plane access are configured via Entra ID role assignments (Search Index Data Reader/Contributor). Not readable per service via Search ARM.",
        "expected_value": "Prefer managed identity; minimize service principal credentials",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-rbac",
    }


def check_im7_conditional_access(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra ID tenant-level. Not readable per search service via ARM.",
        "expected_value": "CA policies applied to Azure Cognitive Search app registration",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/security-baseline",
    }


def check_pa7_rbac_data_plane(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Cognitive Search data plane RBAC: Search Index Data Reader, Contributor, Search Service Contributor. Role assignments not per-service readable via Search ARM — use azure-mgmt-authorization.",
        "expected_value": "Least-privilege data plane roles (Reader not Contributor where possible)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/search-security-rbac",
    }


def check_pa8_customer_lockbox(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox for Cognitive Search is subscription-level. Not readable per service via ARM.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
