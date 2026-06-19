"""
Network Security checks for Azure Private Link / Private Endpoint (MCSB v3).

NS-1 NSG Support: LIVE-DIRECT (with subnet cross-ref).
    Private endpoint subnets bypass NSG rules by default.
    Must check subnet.private_endpoint_network_policies explicitly.
    PASS: 'Enabled' or 'NetworkSecurityGroupEnabled'
    FAIL: 'Disabled' (default — most deployments)

NS-1 VNet Integration: PASS static (microsoft_managed).
    PE always deployed in customer VNet by definition.

NS-2 Azure Private Link: PASS static (microsoft_managed).
    The service IS Private Link — meta-tautology.

NS-2 Disable Public Network Access: PASS static (microsoft_managed).
    PE has no public endpoint concept.

Read-only. Zero ARM writes.
SDK: azure-mgmt-network (NetworkManagementClient).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
_EVIDENCE_NSG = "https://learn.microsoft.com/en-us/azure/private-link/disable-private-endpoint-network-policy"


def _get_endpoints(client, resource_group, endpoint_name):
    if endpoint_name and resource_group:
        return [client.private_endpoints.get(resource_group, endpoint_name)]
    elif resource_group:
        return list(client.private_endpoints.list(resource_group))
    else:
        return list(client.private_endpoints.list_by_subscription())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        endpoints = _get_endpoints(client, resource_group, endpoint_name)
    except Exception as e:
        return {
            "resource": endpoint_name or resource_group or "all",
            "control_id": "NS-1",
            "feature": "Network Security Group Support",
            "status": "UNKNOWN",
            "actual_value": f"Error listing endpoints: {e}",
            "expected_value": "subnet.private_endpoint_network_policies in ('Enabled','NetworkSecurityGroupEnabled')",
            "evidence_url": _EVIDENCE_NSG,
        }

    if not endpoints:
        return {
            "resource": endpoint_name or resource_group or "all",
            "control_id": "NS-1",
            "feature": "Network Security Group Support",
            "status": "UNKNOWN",
            "actual_value": "No private endpoints found in scope",
            "expected_value": "subnet.private_endpoint_network_policies in ('Enabled','NetworkSecurityGroupEnabled')",
            "evidence_url": _EVIDENCE_NSG,
        }

    results = []
    for ep in endpoints:
        if not ep.subnet or not ep.subnet.id:
            results.append(("UNKNOWN", ep.name, "No subnet attached to endpoint"))
            continue
        parts = ep.subnet.id.split('/')
        try:
            subnet_rg = parts[4]
            vnet_name = parts[8]
            subnet_name = parts[10]
        except IndexError:
            results.append(("UNKNOWN", ep.name, f"Cannot parse subnet ID: {ep.subnet.id}"))
            continue
        try:
            subnet = client.subnets.get(subnet_rg, vnet_name, subnet_name)
            policy = getattr(subnet, 'private_endpoint_network_policies', 'Disabled') or 'Disabled'
            if policy in ('Enabled', 'NetworkSecurityGroupEnabled'):
                results.append(("PASS", ep.name, policy))
            else:
                results.append(("FAIL", ep.name, policy))
        except Exception as e:
            results.append(("UNKNOWN", ep.name, str(e)))

    statuses = [r[0] for r in results]
    if "FAIL" in statuses:
        agg_status = "FAIL"
    elif all(s == "PASS" for s in statuses):
        agg_status = "PASS"
    else:
        agg_status = "UNKNOWN"

    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": agg_status,
        "actual_value": str(results),
        "expected_value": "subnet.private_endpoint_network_policies in ('Enabled','NetworkSecurityGroupEnabled')",
        "evidence_url": _EVIDENCE_NSG,
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "PASS",
        "actual_value": "microsoft_managed — Private Endpoint always deployed in customer VNet by definition; VNet integration is inherent to PE architecture",
        "expected_value": "microsoft_managed",
        "evidence_url": _EVIDENCE,
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "PASS",
        "actual_value": "microsoft_managed — The assessed service IS Azure Private Link; Private Link support is meta-tautological for this resource type",
        "expected_value": "microsoft_managed",
        "evidence_url": _EVIDENCE,
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "PASS",
        "actual_value": "microsoft_managed — Private Endpoint has no public endpoint concept; traffic only via private IP in customer VNet",
        "expected_value": "microsoft_managed",
        "evidence_url": _EVIDENCE,
    }
