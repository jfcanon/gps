"""
Data Protection checks for Azure Event Grid (MCSB v3).

DP-3: topic.minimum_tls_version == '1.2' → PASS.
DP-4: Platform-managed encryption at rest (static PASS).

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventgrid import EventGridManagementClient


def _get_topics(client: EventGridManagementClient, resource_group: str | None, topic_name: str | None) -> list:
    if resource_group and topic_name:
        return [client.topics.get(resource_group, topic_name)]
    elif resource_group:
        return list(client.topics.list_by_resource_group(resource_group))
    else:
        return list(client.topics.list_by_subscription())


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit — Minimum TLS Version",
        "expected_value": "topic.minimum_tls_version == '1.2'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/transport-layer-security",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            min_tls = str(getattr(topic, "minimum_tls_version", "") or "1.0")
            if min_tls in ("1.2", "1.3"):
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": f"minimum_tls_version={min_tls}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": f"minimum_tls_version={min_tls} — TLS 1.2+ not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    return {
        "resource": topic_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Event Grid event data at rest is encrypted with Microsoft-managed keys by default.",
        "expected_value": "Microsoft-managed platform key encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }
