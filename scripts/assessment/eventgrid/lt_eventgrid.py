"""
Logging and Threat Detection checks for Azure Event Grid (MCSB v3).

LT-4: DiagnosticSettings on topic.id — any log category enabled → PASS.
      Key categories: DeliveryFailures, PublishFailures.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventgrid import EventGridManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_topics(client: EventGridManagementClient, resource_group: str | None, topic_name: str | None) -> list:
    if resource_group and topic_name:
        return [client.topics.get(resource_group, topic_name)]
    elif resource_group:
        return list(client.topics.list_by_resource_group(resource_group))
    else:
        return list(client.topics.list_by_subscription())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    return {
        "resource": topic_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for Event Grid",
        "status": "UNKNOWN",
        "actual_value": "No standalone Defender for Event Grid product. Defender for Cloud may surface Event Grid recommendations. Check subscription-level Defender plans.",
        "expected_value": "N/A — use Defender for Cloud recommendations",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled (DeliveryFailures, PublishFailures)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/diagnostic-logs",
    }
    try:
        eg_client = EventGridManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        topics = _get_topics(eg_client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            settings = list(monitor.diagnostic_settings.list(topic.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
