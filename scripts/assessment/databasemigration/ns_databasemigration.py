"""
Network Security checks for Azure Database Migration Service (MCSB v3).

NS-1 NSG: NSG is on the VNet subnet used by DMS — not on service ARM resource → UNKNOWN.
NS-1 VNet: service.properties.virtual_subnet_id set → VNet-integrated → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.datamigration import DataMigrationManagementClient


def _get_services(client: DataMigrationManagementClient, resource_group: str | None, service_name: str | None) -> list:
    if resource_group and service_name:
        return [client.services.get(resource_group, service_name)]
    elif resource_group:
        return list(client.services.list_by_resource_group(resource_group))
    else:
        return list(client.services.list())


def check_ns1_nsg(credential, subscription_id, resource_group, service_name):
    return {
        "resource": service_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on DMS VNet Subnet",
        "status": "UNKNOWN",
        "actual_value": "DMS deploys into a customer VNet subnet for connectivity to source/target databases. NSG is on the VNet subnet (NetworkManagementClient), not on the DMS service ARM resource.",
        "expected_value": "NSG attached to DMS VNet subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/resource-scenario-status",
    }


def check_ns1_vnet_integration(credential, subscription_id, resource_group, service_name):
    base = {
        "control_id": "NS-1", "feature": "Establish Network Segmentation Boundaries — VNet Integration",
        "expected_value": "service.properties.virtualSubnetId set (DMS deployed in customer VNet)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/resource-scenario-status",
    }
    try:
        client = DataMigrationManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS", "actual_value": "No DMS services found"}
        first_pass = None
        for svc in services:
            subnet_id = getattr(svc, "virtual_subnet_id", None)
            if subnet_id:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"virtualSubnetId={str(subnet_id)[:60]} — DMS in customer VNet"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": "virtualSubnetId not set — DMS not deployed in customer VNet"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
