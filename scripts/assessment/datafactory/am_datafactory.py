"""AM-2 tags check for Azure Data Factory (MCSB v3)."""
from azure.mgmt.datafactory import DataFactoryManagementClient


def check_am2_policy(credential, subscription_id, resource_group, factory_name):
    base = {"control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
            "expected_value": "Resource tags present",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/security-baseline#am-2-use-only-approved-azure-services"}
    try:
        client = DataFactoryManagementClient(credential, subscription_id)
        if resource_group and factory_name:
            factories = [client.factories.get(resource_group, factory_name)]
        elif resource_group:
            factories = list(client.factories.list_by_resource_group(resource_group))
        else:
            factories = list(client.factories.list())
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            tags = getattr(factory, "tags", None) or {}
            if tags:
                r = {**base, "resource": factory.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": factory.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
