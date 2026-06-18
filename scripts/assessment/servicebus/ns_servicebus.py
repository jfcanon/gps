"""
Network Security checks for Azure Service Bus (MCSB v3).

NS-1 NSG: network rule set default_action=Deny → network-level control → PASS.
NS-1 VNet: VNet rules in network rule set (Premium only) or private endpoints.
NS-2 Private Link: private_endpoint_connections with Approved status.
NS-2 Disable Public Access: public_network_access=Disabled OR rule set default_action=Deny.

Read-only. Zero ARM writes.
"""
from azure.mgmt.servicebus import ServiceBusManagementClient


def _get_namespaces(client: ServiceBusManagementClient, resource_group: str | None, namespace_name: str | None) -> list:
    if resource_group and namespace_name:
        return [client.namespaces.get(resource_group, namespace_name)]
    elif resource_group:
        return list(client.namespaces.list_by_resource_group(resource_group))
    else:
        return list(client.namespaces.list())


def _rg_from_id(resource_id: str) -> str:
    return resource_id.split('/')[4]


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "expected_value": "network rule set default_action=Deny (network-level control active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/network-security",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            rg = resource_group or _rg_from_id(ns.id)
            nrs = client.namespaces.get_network_rule_set(rg, ns.name)
            default_action = str(getattr(nrs, "default_action", "Allow"))
            if default_action.lower() == "deny":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "network rule set default_action=Deny — network-level control active"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"network rule set default_action={default_action} — all traffic allowed; no network restriction"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "expected_value": "Premium SKU with VNet rules or private endpoints configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-service-endpoints",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            sku = str(getattr(getattr(ns, "sku", None), "name", "Standard"))
            if sku.lower() != "premium":
                return {**base, "resource": ns.name, "status": "UNKNOWN",
                        "actual_value": f"SKU={sku} — VNet integration requires Premium tier; not available on {sku}"}
            rg = resource_group or _rg_from_id(ns.id)
            nrs = client.namespaces.get_network_rule_set(rg, ns.name)
            vnet_rules = getattr(nrs, "virtual_network_rules", None) or []
            pec = getattr(ns, "private_endpoint_connections", None) or []
            if vnet_rules or pec:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"Premium SKU; {len(vnet_rules)} VNet rule(s), {len(pec)} private endpoint(s)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": "Premium SKU but no VNet rules or private endpoints configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "expected_value": "At least one Approved private endpoint connection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/private-link-service",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            pec = getattr(ns, "private_endpoint_connections", None) or []
            approved = [
                c for c in pec
                if getattr(
                    getattr(getattr(c, "properties", None), "private_link_service_connection_state", None),
                    "status", ""
                ) == "Approved"
            ]
            if approved:
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"{len(pec)} endpoint(s), {len(approved)} Approved"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"{len(pec)} endpoint(s), none Approved — no private link active"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, namespace_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "expected_value": "public_network_access=Disabled OR network rule set default_action=Deny",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/network-security",
    }
    try:
        client = ServiceBusManagementClient(credential, subscription_id)
        namespaces = _get_namespaces(client, resource_group, namespace_name)
        if not namespaces:
            return {**base, "resource": namespace_name or "none", "status": "PASS",
                    "actual_value": "No Service Bus namespaces found in scope"}
        first_pass = None
        for ns in namespaces:
            pub_access = str(getattr(ns, "public_network_access", "Enabled"))
            if pub_access.lower() == "disabled":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": "public_network_access=Disabled"}
                first_pass = first_pass or r
                continue
            rg = resource_group or _rg_from_id(ns.id)
            nrs = client.namespaces.get_network_rule_set(rg, ns.name)
            default_action = str(getattr(nrs, "default_action", "Allow"))
            if default_action.lower() == "deny":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"public_network_access={pub_access} but network rule set default_action=Deny"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pub_access}, network rule set default_action={default_action}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": namespace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
