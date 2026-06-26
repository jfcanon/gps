"""
Logging and Threat Detection checks for Azure Functions (MCSB v3).

LT-1: Defender for App Service covers Function Apps — subscription-level → UNKNOWN.
LT-4: DiagnosticSettings on function app — any log category enabled → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.monitor import MonitorManagementClient


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


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for App Service (Functions)",
        "status": "UNKNOWN",
        "actual_value": "Defender for App Service covers Azure Functions at the subscription level. Check via azure-mgmt-security SecurityCenter.pricings API.",
        "expected_value": "Defender for App Service plan enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled (FunctionAppLogs)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/functions-monitor-log-analytics",
    }
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        apps = _get_function_apps(web_client, resource_group, site_name)
        if not apps:
            return {**base, "resource": site_name or "none", "status": "PASS",
                    "actual_value": "No Function Apps found in scope"}
        first_pass = None
        for app in apps:
            settings = list(monitor.diagnostic_settings.list(app.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": app.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": app.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": site_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
