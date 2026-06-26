"""Asset Management — Azure Cognitive Search (MCSB v3). AM-2: tags proxy."""
from azure.mgmt.search import SearchManagementClient


def check_am2_policy(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/security-baseline#am-2-use-only-approved-azure-services",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        if resource_group and service_name:
            svcs = [client.services.get(resource_group, service_name)]
        elif resource_group:
            svcs = list(client.services.list_by_resource_group(resource_group))
        else:
            svcs = list(client.services.list_by_subscription())
        if not svcs:
            return {**base, "resource": service_name or "none", "status": "PASS", "actual_value": "No services found"}
        first_pass = None
        for svc in svcs:
            tags = getattr(svc, "tags", None) or {}
            if tags:
                r = {**base, "resource": svc.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
