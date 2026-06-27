"""AM-2 tags check for Azure Virtual WAN (MCSB v3)."""
from azure.mgmt.network import NetworkManagementClient


def check_am2_policy(credential, subscription_id, resource_group, wan_name):
    base = {"control_id": "AM-2", "feature": "Use Only Approved Azure Services — Azure Policy Support",
            "expected_value": "Resource tags present",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/security-baseline"}
    try:
        client = NetworkManagementClient(credential, subscription_id)
        if resource_group and wan_name:
            wans = [client.virtual_wans.get(resource_group, wan_name)]
        elif resource_group:
            wans = list(client.virtual_wans.list_by_resource_group(resource_group))
        else:
            wans = list(client.virtual_wans.list())
        if not wans:
            return {**base, "resource": wan_name or "none", "status": "PASS", "actual_value": "No Virtual WANs found"}
        first_pass = None
        for wan in wans:
            tags = getattr(wan, "tags", None) or {}
            if tags:
                r = {**base, "resource": wan.name, "status": "PASS", "actual_value": f"tags: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wan.name, "status": "FAIL", "actual_value": "tags={} — no tags"}
        return first_pass
    except Exception as e:
        return {**base, "resource": wan_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
