"""
Backup and Recovery checks for Azure Functions (MCSB v3).

BR-1 azure_backup: Consumption/Flex plan Functions have no Azure Backup support.
                   Dedicated (App Service) plan Functions support backup via App Service Backup.
BR-1 native_backup: Check backup_configuration if on Dedicated plan; UNKNOWN for Consumption.

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


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "expected_value": "Backup configuration with schedule set (Dedicated/Premium plan only)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/functions-recover-storage-account",
    }
    try:
        client = WebSiteManagementClient(credential, subscription_id)
        apps = _get_function_apps(client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            rg = _rg_of(app, resource_group)
            if not rg:
                return {**base, "resource": app.name, "status": "UNKNOWN",
                        "actual_value": "Could not determine resource group — pass --resource-group"}
            try:
                backup_cfg = client.web_apps.get_backup_configuration(rg, app.name)
                schedule = getattr(backup_cfg, "backup_schedule", None)
                storage_url = getattr(backup_cfg, "storage_account_url", None)
                if schedule and storage_url:
                    freq = getattr(schedule, "frequency_interval", None)
                    r = {**base, "resource": app.name, "status": "PASS",
                         "actual_value": f"Backup configured; frequency_interval={freq}; storage_account_url set"}
                    first_pass = first_pass or r
                else:
                    return {**base, "resource": app.name, "status": "FAIL",
                            "actual_value": "Backup config exists but schedule or storage_account_url missing"}
            except Exception as ex:
                err_str = str(ex)
                if "404" in err_str or "Not Found" in err_str or "ResourceNotFound" in err_str:
                    return {**base, "resource": app.name, "status": "UNKNOWN",
                            "actual_value": "No backup configuration — Consumption/Flex plan Functions do not support App Service Backup. Use Durable Functions state in Storage or Flex Consumption with zone-redundant storage."}
                return {**base, "resource": app.name, "status": "UNKNOWN",
                        "actual_value": f"Could not retrieve backup configuration: {ex}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
