"""
Network Security checks for Azure Virtual Desktop (MCSB v3).

NS-1 NSG: session host subnets have NSGs — not on workspace/hostpool ARM → UNKNOWN.
NS-1 VNet: session hosts are VMs in customer VNet — VNet integration at VM level → UNKNOWN.
NS-2 PE: workspace.properties.private_endpoint_connections non-empty → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.desktopvirtualization import DesktopVirtualizationMgmtClient


def _get_workspaces(client: DesktopVirtualizationMgmtClient, resource_group: str | None, workspace_name: str | None) -> list:
    if resource_group and workspace_name:
        return [client.workspaces.get(resource_group, workspace_name)]
    elif resource_group:
        return list(client.workspaces.list_by_resource_group(resource_group))
    else:
        try:
            return list(client.workspaces.list())
        except Exception:
            return []


def check_ns1_nsg(credential, subscription_id, resource_group, workspace_name):
    return {
        "resource": workspace_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on Session Host Subnets",
        "status": "UNKNOWN",
        "actual_value": "NSG is configured on the VNet subnet where AVD session hosts are deployed — not on the workspace/hostpool ARM resource. Verify via NetworkManagementClient on session host subnets.",
        "expected_value": "NSG attached to session host VNet subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns1_vnet_integration(credential, subscription_id, resource_group, workspace_name):
    return {
        "resource": workspace_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — VNet Integration (Session Hosts)",
        "status": "UNKNOWN",
        "actual_value": "AVD session hosts are Azure VMs deployed by the customer into their VNet. VNet association is on session host VMs via the host pool registration, not on the workspace/hostpool ARM resource.",
        "expected_value": "Session host VMs deployed in customer-owned VNet subnet",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/network-connectivity",
    }


def check_ns2_private_link(credential, subscription_id, resource_group, workspace_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "workspace.properties.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-overview",
    }
    try:
        client = DesktopVirtualizationMgmtClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "UNKNOWN",
                    "actual_value": "No workspaces found — provide --resource-group to scope"}
        first_pass = None
        for ws in workspaces:
            pe_conns = getattr(ws, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
