"""
Logging and Threat Detection checks for Azure App Service (MCSB v3).

LT-1: Defender for App Service configured at subscription level → UNKNOWN (not per-site ARM).
LT-4: DiagnosticSettings on site.id — at least one log category enabled → PASS.
      Key categories: AppServiceHTTPLogs, AppServiceConsoleLogs, AppServiceAppLogs.

Read-only. Zero ARM writes.
"""
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_sites(client: WebSiteManagementClient, resource_group: str | None, site_name: str | None) -> list:
    if resource_group and site_name:
        return [client.web_apps.get(resource_group, site_name)]
    elif resource_group:
        return list(client.web_apps.list_by_resource_group(resource_group))
    else:
        return list(client.web_apps.list())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for App Service",
        "status": "UNKNOWN",
        "actual_value": "Defender for App Service is enabled at the subscription level (Security Center pricing tier), not per site. Check via azure-mgmt-security SecurityCenter.pricings API.",
        "expected_value": "Defender for App Service plan enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled (AppServiceHTTPLogs, AppServiceConsoleLogs, etc.)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs",
    }
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        sites = _get_sites(web_client, resource_group, site_name)
        if not sites:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No App Service sites found in scope"}
        first_pass = None
        for site in sites:
            settings = list(monitor.diagnostic_settings.list(site.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": site.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": site.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled — HTTP/application logs not captured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
