"""
Asset Management checks for Azure Event Hubs (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventhub import EventHubManagementClient


def _get_namespaces(client: EventHubManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/security-baseline#am-2-use-only-approved-azure-services",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            tags = getattr(ns, "tags", None) or {}
            if tags:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
