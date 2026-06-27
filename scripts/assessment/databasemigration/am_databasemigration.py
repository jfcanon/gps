"""AM-2 tags check for Azure Database Migration Service (MCSB v3)."""
from azure.mgmt.datamigration import DataMigrationManagementClient


def check_am2_policy(credential, subscription_id, resource_group, service_name):
    base = {"control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
            "expected_value": "Resource tags present",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/security-baseline"}
    try:
        client = DataMigrationManagementClient(credential, subscription_id)
        if resource_group and service_name:
            services = [client.services.get(resource_group, service_name)]
        elif resource_group:
            services = list(client.services.list_by_resource_group(resource_group))
        else:
            services = list(client.services.list())
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS", "actual_value": "No DMS services found"}
        first_pass = None
        for svc in services:
            tags = getattr(svc, "tags", None) or {}
            if tags:
                r = {**base, "resource": svc.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
