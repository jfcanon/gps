"""
Endpoint Security checks for Azure Network Watcher (MCSB v3).
ES-1/2/3: PaaS monitoring service — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "ES-1", "feature": "Use Endpoint Detection and Response (EDR) Solution", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — no customer-accessible compute substrate. EDR agents deploy on VMs that NW monitors, not on NW itself.", "expected_value": "N/A — PaaS; no compute substrate", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "ES-2", "feature": "Use Modern Anti-Malware Software", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — antimalware does not apply to Network Watcher. Deploy antimalware on the VMs and resources NW monitors.", "expected_value": "N/A — PaaS; antimalware not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "ES-3", "feature": "Ensure Anti-Malware Software and Signatures are Updated", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — no antimalware health monitoring concept for Network Watcher.", "expected_value": "N/A — PaaS; not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}
