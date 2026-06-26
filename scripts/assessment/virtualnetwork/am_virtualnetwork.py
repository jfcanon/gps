"""
Asset Management checks for Azure Virtual Network (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_vnets(client: NetworkManagementClient, resource_group: str | None, vnet_name: str | None) -> list:
    if resource_group and vnet_name:
        return [client.virtual_networks.get(resource_group, vnet_name)]
    elif resource_group:
        return list(client.virtual_networks.list(resource_group))
    else:
        return list(client.virtual_networks.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/security-baseline#am-2-use-only-approved-azure-services",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        vnets = _get_vnets(client, resource_group, vnet_name)
        if not vnets:
            return {**base, "resource": vnet_name or "none", "status": "PASS",
                    "actual_value": "No Virtual Networks found in scope"}
        first_pass = None
        for vnet in vnets:
            tags = getattr(vnet, "tags", None) or {}
            if tags:
                r = {**base, "resource": vnet.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vnet.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vnet_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
