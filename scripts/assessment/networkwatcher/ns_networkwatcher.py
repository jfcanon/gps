"""
Network Security checks for Azure Network Watcher (MCSB v3).

All NS controls: NW auto-provisions per region (NetworkWatcherRG); it IS the monitoring
infrastructure — no NSG, no VNet integration, no Private Link, no public toggle.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Network Watcher auto-provisions per region in the NetworkWatcherRG resource group. "
            "It is the monitoring infrastructure, not a workload — no NSG is attached to the NW resource itself. "
            "NSGs apply to the VNet resources that NW monitors."
        ),
        "expected_value": "N/A — NW is monitoring infra; NSG applies to monitored VNet resources",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview",
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "UNKNOWN",
        "actual_value": (
            "Network Watcher monitors Virtual Networks but does not integrate into one — it is a regional "
            "ARM resource that exists outside the VNet data plane. VNet Integration as a security control "
            "is not applicable to NW itself."
        ),
        "expected_value": "N/A — NW monitors VNets; it does not join them",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "Network Watcher is an ARM control-plane service accessed via ARM management API. "
            "It has no data-plane endpoint that could be exposed via Private Link. "
            "Private Link is not applicable to the NW resource."
        ),
        "expected_value": "N/A — ARM control-plane service; no Private Link concept",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview",
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Network Watcher is a regional ARM resource with no public network access toggle. "
            "All management access is via ARM with Entra ID authentication. "
            "There is no public/private network mode switch for NW."
        ),
        "expected_value": "N/A — ARM control-plane only; no public network access toggle",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview",
    }
