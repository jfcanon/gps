"""
Logging and Threat Detection checks for Azure Event Hubs (MCSB v3).

LT-4: DiagnosticSettings on namespace.id — any log category enabled → PASS.
      Key categories: OperationalLogs, VNetAndIPFilteringLogs.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventhub import EventHubManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_namespaces(client: EventHubManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for Event Hubs",
        "status": "UNKNOWN",
        "actual_value": "No standalone Defender for Event Hubs product. Defender for Cloud may surface namespace recommendations. Check subscription-level Defender plans via azure-mgmt-security.",
        "expected_value": "N/A — use Defender for Cloud recommendations for Event Hubs",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled (OperationalLogs, VNetAndIPFilteringLogs)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/monitor-event-hubs",
    }
    try:
        eh_client = EventHubManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(eh_client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            settings = list(monitor.diagnostic_settings.list(ns.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
