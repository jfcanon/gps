"""
Identity Management checks for Azure App Service (MCSB v3).

IM-1 AAD: auth_settings_v2.global_validation.require_authentication=True → PASS.
IM-1 local auth: site_config.basic_auth_enabled=False → PASS.
IM-3 MI: site.identity.type assigned → PASS.
IM-3 SP: ARM RBAC — not readable per-site → UNKNOWN.
IM-7 CA: Entra tenant-level; not ARM-readable → UNKNOWN.
IM-8: App settings contain @Microsoft.KeyVault() references → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.web import WebSiteManagementClient


def _get_sites(client: WebSiteManagementClient, resource_group: str | None, site_name: str | None) -> list:
    if resource_group and site_name:
        return [client.web_apps.get(resource_group, site_name)]
    elif resource_group:
        return list(client.web_apps.list_by_resource_group(resource_group))
    else:
        return list(client.web_apps.list())


def _rg_of(site, fallback: str | None) -> str | None:
    if fallback:
        return fallback
    site_id = getattr(site, "id", "") or ""
    parts = site_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def check_im1_aad_auth(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required (EasyAuth v2)",
        "expected_value": "auth_settings_v2.global_validation.require_authentication=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            rg = _rg_of(site, resource_group)
            require_auth = False
            unauthenticated_action = "unknown"
            if rg:
                try:
                    auth = client.web_apps.get_auth_settings_v2(rg, site.name)
                    gv = getattr(auth, "global_validation", None)
                    require_auth = getattr(gv, "require_authentication", False) if gv else False
                    unauthenticated_action = str(getattr(gv, "unauthenticated_client_action", "") or "") if gv else ""
                except Exception:
                    pass
            if require_auth:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"EasyAuth v2 require_authentication=True; unauthenticated_action={unauthenticated_action}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": f"EasyAuth v2 require_authentication={require_auth} — anonymous access may be allowed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth (Basic Auth)",
        "expected_value": "site_config.basic_auth_enabled=False (SCM/FTP basic auth disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            cfg = getattr(site, "site_config", None)
            basic_auth = getattr(cfg, "basic_auth_enabled", None) if cfg else None
            if basic_auth is False:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": "basic_auth_enabled=False — local credential login disabled for SCM/FTP"}
                first_pass = first_pass or r
            elif basic_auth is True:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": "basic_auth_enabled=True — local username/password auth enabled for SCM and FTP"}
            else:
                return {**base, "resource": site.name, "status": "UNKNOWN",
                        "actual_value": "basic_auth_enabled not returned in site_config — check via Portal > Configuration > General > SCM Basic Auth"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "site.identity.type in (SystemAssigned, UserAssigned, SystemAssigned,UserAssigned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            identity = getattr(site, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity assigned"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication — Service Principal",
        "status": "UNKNOWN",
        "actual_value": "Service principal role assignments are not readable per-site via App Service ARM API. Use azure-mgmt-authorization to enumerate role assignments for this site's resource ID.",
        "expected_value": "Prefer managed identity over service principal credentials",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity",
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra ID tenant-level, not per App Service resource. Verify via Azure Portal > Entra ID > Conditional Access > Policies.",
        "expected_value": "Conditional Access policies applied to the App Service application registration",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "IM-8",
        "feature": "Restrict the Exposure of Credentials and Secrets — KV References in App Settings",
        "expected_value": "App settings contain @Microsoft.KeyVault() references (no inline secrets)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        sites = _get_sites(client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            rg = _rg_of(site, resource_group)
            props = {}
            if rg:
                try:
                    settings = client.web_apps.list_application_settings(rg, site.name)
                    props = getattr(settings, "properties", None) or {}
                except Exception:
                    pass
            kv_refs = [k for k, v in props.items() if "@Microsoft.KeyVault(" in str(v)]
            if kv_refs:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"{len(kv_refs)} app setting(s) use KV references: {kv_refs[:5]}"}
                first_pass = first_pass or r
            elif not props:
                return {**base, "resource": site.name, "status": "UNKNOWN",
                        "actual_value": "No app settings returned (requires resource group scope or elevated permissions)"}
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": f"{len(props)} app setting(s); none use @Microsoft.KeyVault() references — secrets may be stored inline"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
