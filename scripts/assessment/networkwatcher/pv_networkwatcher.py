"""
Posture and Vulnerability Management checks for Azure Network Watcher (MCSB v3).
PV-3/5/6: PaaS monitoring service — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_pv3_automation_state_config(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PV-3", "feature": "Azure Automation State Configuration", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — Automation State Configuration targets VMs/Arc servers with an OS. Network Watcher has no OS substrate.", "expected_value": "N/A — PaaS; no OS substrate", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_pv3_guest_config_agent(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PV-3", "feature": "Azure Policy Guest Configuration Agent", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — guest config agent requires VM or Arc substrate. Not deployable on Network Watcher.", "expected_value": "N/A — PaaS; guest config not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_pv3_custom_container_images(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PV-3", "feature": "Custom Container Images", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — no container image concept applies to Network Watcher.", "expected_value": "N/A — PaaS; no container support", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_pv3_custom_vm_images(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PV-3", "feature": "Custom VM Images", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — no VM image concept applies to Network Watcher.", "expected_value": "N/A — PaaS; no VM image support", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}


def check_pv5_defender_va(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PV-5", "feature": "Vulnerability Assessment using Microsoft Defender", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — Defender VA targets VMs, containers, App Service, SQL. Network Watcher not in supported services list.", "expected_value": "N/A — PaaS; Defender VA not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_pv6_update_management(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {"resource": watcher_name or "all", "control_id": "PV-6", "feature": "Azure Automation Update Management", "status": "UNKNOWN", "actual_value": "PaaS monitoring service — Azure Automation Update Management targets VMs. Network Watcher has no OS or patch surface.", "expected_value": "N/A — PaaS; update management not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"}
