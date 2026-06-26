"""
Asset Management checks for Azure Event Grid (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.

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


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/security-baseline#am-2-use-only-approved-azure-services",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            tags = getattr(topic, "tags", None) or {}
            if tags:
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
