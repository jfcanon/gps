"""
Network Security checks for Azure Cognitive Search (MCSB v3).

NS-2 PE: service.private_endpoint_connections non-empty → PASS.
NS-2 disable public: service.public_network_access == 'disabled' → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.search import SearchManagementClient


def _get_services(client: SearchManagementClient, resource_group: str | None, service_name: str | None) -> list:
    if resource_group and service_name:
        return [client.services.get(resource_group, service_name)]
    elif resource_group:
        return list(client.services.list_by_resource_group(resource_group))
    else:
        return list(client.services.list_by_subscription())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, service_name: str | None) -> dict:
    return {
        "resource": service_name or "all",
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG",
        "status": "UNKNOWN",
        "actual_value": "Azure Cognitive Search is a PaaS search service — not deployed in a customer VNet. Network restriction via private endpoints (NS-2) and IP rules. No NSG ARM property on search service.",
        "expected_value": "N/A — use private endpoints for network restriction",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, service_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Azure Private Link",
        "expected_value": "service.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/service-create-private-endpoint",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No Cognitive Search services found in scope"}
        first_pass = None
        for svc in services:
            pe_conns = getattr(svc, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, service_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "service.public_network_access == 'disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/search/service-configure-firewall",
    }
    try:
        client = SearchManagementClient(credential, subscription_id)
        services = _get_services(client, resource_group, service_name)
        if not services:
            return {**base, "resource": service_name or "none", "status": "PASS",
                    "actual_value": "No Cognitive Search services found in scope"}
        first_pass = None
        for svc in services:
            pna = str(getattr(svc, "public_network_access", "") or "enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": svc.name, "status": "PASS",
                     "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": svc.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public inbound access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": service_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
