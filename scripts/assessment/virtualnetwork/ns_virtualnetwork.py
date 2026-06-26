"""
Network Security checks for Azure Virtual Network (MCSB v3).

NS-1 NSG: Check subnets for NSG attachment (subnet.network_security_group).
NS-2-SUPPLEMENT: enable_default_outbound_access=False → new subnets have no
                 implicit internet access (March 2026 guidance).

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


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on Subnets",
        "expected_value": "All non-gateway subnets have network_security_group attached",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        vnets = _get_vnets(client, resource_group, vnet_name)
        if not vnets:
            return {**base, "resource": vnet_name or "none", "status": "PASS",
                    "actual_value": "No Virtual Networks found in scope"}
        first_pass = None
        for vnet in vnets:
            subnets = getattr(vnet, "subnets", None) or []
            if not subnets:
                r = {**base, "resource": vnet.name, "status": "UNKNOWN",
                     "actual_value": "No subnets found in VNet"}
                first_pass = first_pass or r
                continue
            unprotected = []
            for subnet in subnets:
                name = getattr(subnet, "name", "") or ""
                if name.lower() in ("gatewaysubnet", "azurebastionsubnet", "azurefirewallsubnet"):
                    continue
                if not getattr(subnet, "network_security_group", None):
                    unprotected.append(name)
            if unprotected:
                return {**base, "resource": vnet.name, "status": "FAIL",
                        "actual_value": f"{len(unprotected)} subnet(s) without NSG: {unprotected[:5]}"}
            total = len([s for s in subnets if (getattr(s, "name", "") or "").lower()
                         not in ("gatewaysubnet", "azurebastionsubnet", "azurefirewallsubnet")])
            r = {**base, "resource": vnet.name, "status": "PASS",
                 "actual_value": f"All {total} non-gateway subnet(s) have NSG attached"}
            first_pass = first_pass or r
        return first_pass
    except Exception as e:
        return {**base, "resource": vnet_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_supplement_default_outbound_access(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    base = {
        "control_id": "NS-2-SUPPLEMENT",
        "feature": "Secure Cloud Services with Network Controls — Default Outbound Access Disabled",
        "expected_value": "VNet enable_default_outbound_access=False (subnets have no implicit internet access)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        vnets = _get_vnets(client, resource_group, vnet_name)
        if not vnets:
            return {**base, "resource": vnet_name or "none", "status": "PASS",
                    "actual_value": "No Virtual Networks found in scope"}
        first_pass = None
        for vnet in vnets:
            doa = getattr(vnet, "enable_default_outbound_access", None)
            if doa is False:
                r = {**base, "resource": vnet.name, "status": "PASS",
                     "actual_value": "enable_default_outbound_access=False — default outbound internet access disabled"}
                first_pass = first_pass or r
            elif doa is True:
                return {**base, "resource": vnet.name, "status": "FAIL",
                        "actual_value": "enable_default_outbound_access=True — new subnets have implicit outbound internet access"}
            else:
                return {**base, "resource": vnet.name, "status": "UNKNOWN",
                        "actual_value": "enable_default_outbound_access property not returned by ARM — check ARM API version or SDK version (requires 2023-09-01+)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vnet_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
