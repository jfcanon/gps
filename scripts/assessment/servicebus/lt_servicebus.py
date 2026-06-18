"""
Logging and Threat Detection checks for Azure Service Bus (MCSB v3).

LT-1: No Defender for Service Bus product in Defender for Cloud → UNKNOWN (static).
LT-4: DiagnosticSettings — any enabled log category → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.servicebus import ServiceBusManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_namespaces(client: ServiceBusManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
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
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for Service Bus",
        "status": "UNKNOWN",
        "actual_value": "Microsoft Defender for Service Bus is not a product in the Defender for Cloud portfolio. Threat detection for Service Bus is not available as a standalone Defender plan. Monitor via Azure Monitor alerts and diagnostic logs instead.",
        "expected_value": "N/A — no Defender for Service Bus product",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/monitor-service-bus",
    }
    try:
        sb_client = ServiceBusManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(sb_client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
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
