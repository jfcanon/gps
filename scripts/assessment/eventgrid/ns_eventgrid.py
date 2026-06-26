"""
Network Security checks for Azure Event Grid (MCSB v3).

NS-1 NSG: Event Grid topics don't sit in a VNet — NSG not applicable → UNKNOWN.
NS-2 PE: topic.private_endpoint_connections non-empty → PASS.
NS-2 disable public: topic.public_network_access == 'Disabled' → PASS.
NS-2-SUPPLEMENT-EVENTGRID: EventGrid Namespaces (MQTT) — check private endpoints on namespace resources.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventgrid import EventGridManagementClient


def _get_topics(client: EventGridManagementClient, resource_group: str | None, topic_name: str | None) -> list:
    if resource_group and topic_name:
        return [client.topics.get(resource_group, topic_name)]
    elif resource_group:
        return list(client.topics.list_by_resource_group(resource_group))
    else:
        return list(client.topics.list_by_subscription())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    return {
        "resource": topic_name or "all",
        "control_id": "NS-1",
        "feature": "Establish Network Segmentation Boundaries — NSG",
        "status": "UNKNOWN",
        "actual_value": "Azure Event Grid topics are not deployed into a customer VNet. NSG segmentation is controlled via private endpoints (NS-2) and IP firewall rules. No per-topic NSG ARM property exists.",
        "expected_value": "N/A — use private endpoints (NS-2) and inboundIpRules for network restriction",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/security-baseline#ns-1-establish-network-segmentation-boundaries",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Private Endpoint",
        "expected_value": "topic.private_endpoint_connections non-empty",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/configure-private-endpoints",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            pe_conns = getattr(topic, "private_endpoint_connections", None) or []
            if pe_conns:
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": f"{len(pe_conns)} private endpoint connection(s) configured"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": "private_endpoint_connections=[] — no private endpoint configured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_disable_public_access(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Secure Cloud Services with Network Controls — Disable Public Network Access",
        "expected_value": "topic.public_network_access == 'Disabled'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/network-security",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            pna = str(getattr(topic, "public_network_access", "") or "Enabled")
            if pna.lower() == "disabled":
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": f"public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": f"public_network_access={pna} — public inbound access enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_supplement_eventgrid_namespaces(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "NS-2-SUPPLEMENT-EVENTGRID",
        "feature": "Secure Cloud Services with Network Controls — EventGrid MQTT Namespaces Private Endpoint",
        "expected_value": "EventGrid Namespace resources have private_endpoint_connections or public_network_access=Disabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/mqtt-overview",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        try:
            if resource_group:
                namespaces = list(client.namespaces.list_by_resource_group(resource_group))
            else:
                namespaces = list(client.namespaces.list_by_subscription())
        except AttributeError:
            return {**base, "resource": topic_name or "all", "status": "UNKNOWN",
                    "actual_value": "EventGrid Namespaces API not available in installed SDK version — upgrade azure-mgmt-eventgrid to 10.0.0+"}
        if not namespaces:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No EventGrid Namespace resources found in scope (MQTT namespaces not deployed)"}
        first_pass = None
        for ns in namespaces:
            pe_conns = getattr(ns, "private_endpoint_connections", None) or []
            pna = str(getattr(ns, "public_network_access", "") or "Enabled")
            if pe_conns or pna.lower() == "disabled":
                r = {**base, "resource": ns.name, "status": "PASS",
                     "actual_value": f"private_endpoints={len(pe_conns)}; public_network_access={pna}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ns.name, "status": "FAIL",
                        "actual_value": f"No private endpoints and public_network_access={pna} — MQTT namespace publicly accessible"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
