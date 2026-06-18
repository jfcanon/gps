"""
Logging and Threat Detection checks for Azure Public IP (MCSB v3).

LT-1: No dedicated Defender for Public IP product → UNKNOWN static.
LT-4: DiagnosticSettings — any enabled log or metric category → PASS.
      Key categories: DDoSProtectionNotifications, DDoSMitigationFlowLogs, AllMetrics.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_public_ips(client: NetworkManagementClient, resource_group: str | None, public_ip_name: str | None) -> list:
    if resource_group and public_ip_name:
        return [client.public_ip_addresses.get(resource_group, public_ip_name)]
    elif resource_group:
        return list(client.public_ip_addresses.list(resource_group))
    else:
        return list(client.public_ip_addresses.list_all())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {
        "resource": public_ip_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service — Azure Public IP",
        "status": "UNKNOWN",
        "actual_value": (
            "No dedicated Microsoft Defender for Azure Public IP product in the Defender for Cloud portfolio. "
            "DDoS Protection Standard provides threat detection for PIP-level volumetric attacks. "
            "Defender for Cloud may surface recommendations about PIP exposure but has no per-PIP pricing tier."
        ),
        "expected_value": "N/A — no Defender for Public IP product; use DDoS Protection Standard for attack detection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "expected_value": "Diagnostic settings enabled with at least one log or metric category (DDoSProtectionNotifications, DDoSMitigationFlowLogs, or AllMetrics)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/monitor-public-ip",
    }
    ddos_categories = {"DDoSProtectionNotifications", "DDoSMitigationFlowLogs", "DDoSMitigationReports"}
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        pips = _get_public_ips(net_client, resource_group, public_ip_name)
        if not pips:
            return {**base, "resource": public_ip_name or "none", "status": "PASS",
                    "actual_value": "No Public IP instances found in scope"}
        first_pass = None
        for pip in pips:
            settings = list(monitor.diagnostic_settings.list(pip.id))
            enabled_logs = set()
            has_metrics = False
            for s in settings:
                for log in (getattr(s, "logs", None) or []):
                    if getattr(log, "enabled", False):
                        cat = getattr(log, "category", None) or getattr(log, "category_group", None)
                        if cat:
                            enabled_logs.add(str(cat))
                for metric in (getattr(s, "metrics", None) or []):
                    if getattr(metric, "enabled", False):
                        has_metrics = True
            if enabled_logs or has_metrics:
                ddos_enabled = enabled_logs & ddos_categories
                detail = f"DDoS log categories: {sorted(ddos_enabled)}" if ddos_enabled else "metrics-only logging enabled"
                r = {**base, "resource": pip.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); {detail}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": pip.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no logs or metrics enabled — DDoS events and IP metrics not captured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": public_ip_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
