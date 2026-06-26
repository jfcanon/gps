"""
Logging and Threat Detection checks for Azure Virtual Network (MCSB v3).

LT-4: DiagnosticSettings on VNet resource — any log category enabled → PASS.
      Key log category: VMProtectionAlerts.
      Note: NSG flow logs are a separate resource — check via network_watchers flow_logs.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_vnets(client: NetworkManagementClient, resource_group: str | None, vnet_name: str | None) -> list:
    if resource_group and vnet_name:
        return [client.virtual_networks.get(resource_group, vnet_name)]
    elif resource_group:
        return list(client.virtual_networks.list(resource_group))
    else:
        return list(client.virtual_networks.list_all())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    return {
        "resource": vnet_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for VNet",
        "status": "UNKNOWN",
        "actual_value": "No dedicated Defender for Cloud plan for Azure Virtual Network as a resource type. Network threat detection is via Defender for Cloud's network security features and NSG flow logs.",
        "expected_value": "N/A — use NSG flow logs and Defender for Cloud network recommendations",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, vnet_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled on VNet (e.g. VMProtectionAlerts)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/monitor-virtual-network",
    }
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        vnets = _get_vnets(net_client, resource_group, vnet_name)
        if not vnets:
            return {**base, "resource": vnet_name or "none", "status": "PASS",
                    "actual_value": "No Virtual Networks found in scope"}
        first_pass = None
        for vnet in vnets:
            settings = list(monitor.diagnostic_settings.list(vnet.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": vnet.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vnet.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": vnet_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
