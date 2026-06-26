"""
Data Protection checks for Azure Functions (MCSB v3).

DP-3: site_config.min_tls_version in ('1.2', '1.3') → PASS.
DP-4: Platform-managed encryption at rest (static PASS).
DP-5: CMK not supported for standard Function App config at rest → UNKNOWN.
DP-6: Managed identity + @Microsoft.KeyVault() app settings references → PASS.
DP-7: SSL certificates sourced from Key Vault → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.web import WebSiteManagementClient


def _get_function_apps(client: WebSiteManagementClient, resource_group: str | None, site_name: str | None) -> list:
    if resource_group and site_name:
        site = client.web_apps.get(resource_group, site_name)
        return [site] if "functionapp" in (getattr(site, "kind", "") or "").lower() else []
    elif resource_group:
        return [s for s in client.web_apps.list_by_resource_group(resource_group)
                if "functionapp" in (getattr(s, "kind", "") or "").lower()]
    else:
        return [s for s in client.web_apps.list()
                if "functionapp" in (getattr(s, "kind", "") or "").lower()]


def _rg_of(site, fallback: str | None) -> str | None:
    if fallback:
        return fallback
    site_id = getattr(site, "id", "") or ""
    parts = site_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit — Minimum TLS Version",
        "expected_value": "site_config.min_tls_version in ('1.2', '1.3')",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/security-baseline#dp-3-encrypt-sensitive-data-in-transit",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            cfg = getattr(app, "site_config", None)
            min_tls = str(getattr(cfg, "min_tls_version", "") or "1.0") if cfg else "unknown"
            if min_tls in ("1.2", "1.3"):
                r = {**base, "resource": app.name, "status": "PASS",
                     "actual_value": f"min_tls_version={min_tls}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": app.name, "status": "FAIL",
                        "actual_value": f"min_tls_version={min_tls} — TLS 1.2+ not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Functions storage (Blob, Queue, Table for triggers/bindings) uses Microsoft-managed encryption at rest by default.",
        "expected_value": "Microsoft-managed platform key encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "status": "UNKNOWN",
        "actual_value": "Standard Function Apps don't expose CMK for configuration data. The underlying Storage Account supports CMK — check the linked storage account's encryption.key_source. App Service Environments (ASE) support CMK for disk encryption.",
        "expected_value": "Configure CMK on the linked Storage Account; check ASE if applicable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/configure-encrypt-at-rest-using-cmk",
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "Managed identity AND @Microsoft.KeyVault() references in app settings",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            identity = getattr(app, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            has_identity = identity and identity_type.lower() not in ("none", "")
            rg = _rg_of(app, resource_group)
            kv_refs = []
            if rg:
                try:
                    settings = client.web_apps.list_application_settings(rg, app.name)
                    props = getattr(settings, "properties", None) or {}
                    kv_refs = [k for k, v in props.items() if "@Microsoft.KeyVault(" in str(v)]
                except Exception:
                    pass
            if has_identity and kv_refs:
                r = {**base, "resource": app.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}; {len(kv_refs)} KV reference(s): {kv_refs[:3]}"}
                first_pass = first_pass or r
            elif not has_identity:
                return {**base, "resource": app.name, "status": "FAIL",
                        "actual_value": f"No managed identity (identity.type={identity_type})"}
            else:
                return {**base, "resource": app.name, "status": "UNKNOWN",
                        "actual_value": f"identity.type={identity_type} but no @Microsoft.KeyVault() references found"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "DP-7",
        "feature": "Certificate Management using Azure Key Vault",
        "expected_value": "SSL certificates imported from Key Vault (key_vault_id set)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-certificate",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        for app in apps:
            rg = _rg_of(app, resource_group)
            if not rg:
                return {**base, "resource": app.name, "status": "UNKNOWN",
                        "actual_value": "Could not determine resource group — pass --resource-group"}
            try:
                certs = list(client.certificates.list_by_resource_group(rg))
                kv_certs = [c for c in certs if getattr(c, "key_vault_id", None)]
                if kv_certs:
                    return {**base, "resource": app.name, "status": "PASS",
                            "actual_value": f"{len(kv_certs)}/{len(certs)} certificate(s) sourced from Key Vault"}
                elif certs:
                    return {**base, "resource": app.name, "status": "FAIL",
                            "actual_value": f"{len(certs)} certificate(s); none reference Key Vault"}
            except Exception:
                pass
            return {**base, "resource": app.name, "status": "UNKNOWN",
                    "actual_value": "No certificates found or could not enumerate — Function App may use App Service managed certs"}
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
