"""
Asset Management checks for Azure Network Watcher (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage — live check.
AM-5: Defender AAC — targets VMs only → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_network_watchers(client: NetworkManagementClient, resource_group: str | None, watcher_name: str | None) -> list:
    if resource_group and watcher_name:
        return [client.network_watchers.get(resource_group, watcher_name)]
    elif resource_group:
        return list(client.network_watchers.list(resource_group))
    else:
        return list(client.network_watchers.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        watchers = _get_network_watchers(client, resource_group, watcher_name)
        if not watchers:
            return {**base, "resource": watcher_name or "none", "status": "PASS",
                    "actual_value": "No Network Watcher instances found in scope"}
        first_pass = None
        for nw in watchers:
            tags = getattr(nw, "tags", None) or {}
            if tags:
                r = {**base, "resource": nw.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": nw.name, "status": "FAIL",
                        "actual_value": "tags={} — no resource tags; policy governance tagging not confirmed. Note: NW auto-provisions as 'NetworkWatcher_<region>' in NetworkWatcherRG — consider tagging via Azure Policy."}
        return first_pass
    except Exception as e:
        return {**base, "resource": watcher_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "AM-5", "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — Adaptive Application Controls target VMs and Arc-enabled servers; not applicable to Network Watcher.", "expected_value": "N/A — PaaS; AAC not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls"}
