"""
Backup and Recovery checks for Azure App Service (MCSB v3).

BR-1 azure_backup: App Service custom backup uses Storage Account (not Azure Backup vault).
                   get_backup_configuration returns schedule + storage_account_url → PASS.
                   404 response → no backup configured → FAIL.

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


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "BR-1",
        "feature": "Ensure Regular Automated Backups — Azure Backup Service",
        "expected_value": "Backup configuration with schedule and storage_account_url set",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/manage-backup",
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
            if not rg:
                return {**base, "resource": site.name, "status": "UNKNOWN",
                        "actual_value": "Could not determine resource group — pass --resource-group"}
            try:
                backup_cfg = client.web_apps.get_backup_configuration(rg, site.name)
                schedule = getattr(backup_cfg, "backup_schedule", None)
                storage_url = getattr(backup_cfg, "storage_account_url", None)
                if schedule and storage_url:
                    freq = getattr(schedule, "frequency_interval", None)
                    r = {**base, "resource": site.name, "status": "PASS",
                         "actual_value": f"Backup configured; frequency_interval={freq}; storage_account_url set"}
                    first_pass = first_pass or r
                else:
                    return {**base, "resource": site.name, "status": "FAIL",
                            "actual_value": "Backup configuration exists but schedule or storage_account_url missing"}
            except Exception as ex:
                err_str = str(ex)
                if "404" in err_str or "Not Found" in err_str or "ResourceNotFound" in err_str:
                    return {**base, "resource": site.name, "status": "FAIL",
                            "actual_value": "No backup configuration found — automated backups not enabled"}
                return {**base, "resource": site.name, "status": "UNKNOWN",
                        "actual_value": f"Could not retrieve backup configuration: {ex}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
