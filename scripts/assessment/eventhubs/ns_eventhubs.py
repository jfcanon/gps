"""
Network Security checks for Azure Event Hubs (MCSB v3).

NS-1 NSG: NSG on VNet integration subnet — not readable from namespace resource → UNKNOWN.
NS-1 VNet: network_rule_set.virtual_network_rules non-empty → VNet filtering active.
NS-2 PE: namespace.private_endpoint_connections non-empty → PASS.
NS-2 disable public: namespace.public_network_access == 'Disabled' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventhub import EventHubManagementClient


def _get_namespaces(client: EventHubManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def _rg_of(ns, fallback: str | None) -> str | None:
    if fallback:
        return fallback
    ns_id = getattr(ns, "id", "") or ""
    parts = ns_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    return {
        "resource": namespace_name or "all",
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG on VNet Integration Subnet",
        "status": "UNKNOWN",
        "actual_value": "NSG is on the VNet subnet referenced in network_rule_set.virtual_network_rules, not on the Event Hubs namespace itself. Verify subnet NSG via NetworkManagementClient.",
        "expected_value": "NSG attached to the VNet subnet used in virtual_network_rules",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns1_vnet_rules(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — VNet Service Endpoint Rules",
        "expected_value": "network_rule_set.virtual_network_rules non-empty (VNet service endpoint filtering active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/network-security",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            rg = _rg_of(ns, resource_group)
            vnet_rules = []
            if rg:
                try:
                    ruleset = client.namespaces.get_network_rule_set(rg, ns.name)
                    vnet_rules = getattr(ruleset, "virtual_network_rules", None) or []
                except Exception:
                    pass
            if vnet_rules:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"{len(vnet_rules)} VNet service endpoint rule(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "virtual_network_rules=[] — no VNet service endpoint filtering; inbound not network-restricted via VNet"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "namespace.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/private-link-service",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            pe_conns = getattr(ns, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "namespace.public_network_access == 'Disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-hubs/network-security",
    }
    try:
        client = EventHubManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Event Hubs namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            pna = str(getattr(ns, "public_network_access", "") or "Enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public inbound access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
