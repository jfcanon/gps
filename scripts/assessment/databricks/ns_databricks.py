"""
Network Security checks for Azure Databricks (MCSB v3).

NS-1 NSG: Databricks VNet injection deploys NSGs on host/container subnets → UNKNOWN (on VNet subnets).
NS-1 VNet: workspace.parameters.customVirtualNetworkId set → VNet injection → PASS.
NS-2 PE: workspace.private_endpoint_connections non-empty → PASS.
NS-2 disable public: workspace.parameters.enableNoPublicIp.value=True → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.databricks import AzureDatabricksManagementClient


def _get_workspaces(client: AzureDatabricksManagementClient, resource_group: str | None, workspace_name: str | None) -> list:
    if resource_group and workspace_name:
        return [client.workspaces.get(resource_group, workspace_name)]
    elif resource_group:
        return list(client.workspaces.list_by_resource_group(resource_group))
    else:
        return list(client.workspaces.list_by_subscription())


def check_ns1_nsg(credential, subscription_id, resource_group, workspace_name):
    return {
        "resource": workspace_name or "all", "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on VNet-Injected Subnets",
        "status": "UNKNOWN",
        "actual_value": "Databricks VNet injection deploys NSGs automatically on the host and container subnets. NSG exists on the VNet subnets (customer-controlled in no-public-IP mode), not on the workspace ARM resource.",
        "expected_value": "VNet-injected workspace (customVirtualNetworkId set) with NSG on subnets",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/vnet-inject",
    }


def check_ns1_vnet_integration(credential, subscription_id, resource_group, workspace_name):
    base = {
        "control_id": "NS-1", "feature": "Establish Network Segmentation Boundaries — VNet Injection",
        "expected_value": "workspace.parameters.customVirtualNetworkId set (VNet-injected workspace)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/vnet-inject",
    }
    try:
        client = AzureDatabricksManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
        first_pass = None
        for ws in workspaces:
            params = getattr(ws, "parameters", None)
            vnet_id_param = getattr(params, "custom_virtual_network_id", None) if params else None
            vnet_id = getattr(vnet_id_param, "value", None) if vnet_id_param else None
            if vnet_id:
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"VNet-injected; customVirtualNetworkId={str(vnet_id)[:60]}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": "customVirtualNetworkId not set — workspace uses default managed VNet (not VNet-injected)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id, resource_group, workspace_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "workspace.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/cloud-configurations/azure/private-link",
    }
    try:
        client = AzureDatabricksManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
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


def check_ns2_disable_public_access(credential, subscription_id, resource_group, workspace_name):
    base = {
        "control_id": "NS-2", "feature": "Secure Cloud Services with Network Controls — Disable Public IP (No Public IP mode)",
        "expected_value": "workspace.parameters.enableNoPublicIp.value=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/network/secure-cluster-connectivity",
    }
    try:
        client = AzureDatabricksManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "PASS", "actual_value": "No workspaces found"}
        first_pass = None
        for ws in workspaces:
            params = getattr(ws, "parameters", None)
            no_public_ip_param = getattr(params, "enable_no_public_ip", None) if params else None
            no_public_ip = getattr(no_public_ip_param, "value", None) if no_public_ip_param else None
            if no_public_ip is True:
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": "enableNoPublicIp=True — Secure Cluster Connectivity (no public IP on cluster nodes)"}
                first_pass = first_pass or r
            elif no_public_ip is False:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": "enableNoPublicIp=False — cluster nodes have public IPs assigned"}
            else:
                return {**base, "resource": ws.name, "status": "UNKNOWN",
                        "actual_value": "enableNoPublicIp parameter not returned — may not be VNet-injected workspace"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
