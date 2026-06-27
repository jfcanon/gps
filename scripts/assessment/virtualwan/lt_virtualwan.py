"""LT checks for Azure Virtual WAN (MCSB v3). LT-4: DiagnosticSettings on virtual WAN."""
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_virtual_wans(client, rg, name):
    if rg and name:
        return [client.virtual_wans.get(rg, name)]
    elif rg:
        return list(client.virtual_wans.list_by_resource_group(rg))
    else:
        return list(client.virtual_wans.list())


def check_lt1_defender(c, s, r, n):
    return {"resource": n or "all", "control_id": "LT-1", "feature": "Enable Threat Detection Capabilities",
            "status": "UNKNOWN",
            "actual_value": "No standalone Defender for Virtual WAN. Use Defender for Cloud for recommendations.",
            "expected_value": "N/A",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_lt4_resource_logs(credential, subscription_id, resource_group, wan_name):
    base = {"control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
            "expected_value": "At least one diagnostic log category enabled on Virtual WAN resource",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/monitor-virtual-wan"}
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        wans = _get_virtual_wans(net_client, resource_group, wan_name)
        if not wans:
            return {**base, "resource": wan_name or "none", "status": "PASS", "actual_value": "No Virtual WANs found"}
        first_pass = None
        for wan in wans:
            settings = list(monitor.diagnostic_settings.list(wan.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": wan.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); logs enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wan.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": wan_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
