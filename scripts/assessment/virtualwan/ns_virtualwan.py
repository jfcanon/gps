"""
Network Security checks for Azure Virtual WAN (MCSB v3).

NS-7 SUPPLEMENT: Forced tunneling for Virtual WAN Secure Hubs via NVA/SASE
→ UNKNOWN (routing table config not inspectable without hub routing tables).

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_virtual_wans(client: NetworkManagementClient, resource_group: str | None, wan_name: str | None) -> list:
    if resource_group and wan_name:
        return [client.virtual_wans.get(resource_group, wan_name)]
    elif resource_group:
        return list(client.virtual_wans.list_by_resource_group(resource_group))
    else:
        return list(client.virtual_wans.list())


def check_ns7_forced_tunneling(credential, subscription_id, resource_group, wan_name):
    return {
        "resource": wan_name or "all", "control_id": "NS-7",
        "feature": "Simplify Network Security Configuration — Forced Tunneling via NVA/SASE (NS-7-SUPPLEMENT-VIRTUALWAN)",
        "status": "UNKNOWN",
        "actual_value": "Forced tunneling in Virtual WAN Secure Hubs is configured via routing tables (default route 0.0.0.0/0 via NVA or SASE partner). Routing table configuration is at hub level — readable via virtual_hubs but requires cross-resource correlation beyond single-WAN ARM property.",
        "expected_value": "Virtual WAN Secure Hub with default route (0.0.0.0/0) via trusted NVA or SASE partner",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/scenario-route-through-nva",
    }
