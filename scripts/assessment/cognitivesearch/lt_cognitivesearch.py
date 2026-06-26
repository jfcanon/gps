"""
Logging and Threat Detection — Azure Cognitive Search (MCSB v3).
LT-4: DiagnosticSettings on service resource.
"""
from azure.mgmt.search import SearchManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_services(client, rg, name):
    if rg and name:
        return [client.services.get(rg, name)]
    elif rg:
        return list(client.services.list_by_resource_group(rg))
    else:
        return list(client.services.list_by_subscription())


def check_lt1_defender(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all", "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities",
        "status": "UNKNOWN",
        "actual_value": "No standalone Defender for Cognitive Search. Defender for Cloud may surface recommendations.",
        "expected_value": "N/A — monitor via Defender for Cloud",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/monitor-azure-cognitive-search",
    }
    try:
        search_client = SearchManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        services = _get_services(search_client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No search services found"}
        first_pass = None
        for svc in services:
            settings = list(monitor.diagnostic_settings.list(svc.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
