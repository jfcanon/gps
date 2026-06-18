"""
Logging and Threat Detection checks for Azure Firewall (MCSB v3).

LT-1: No dedicated Microsoft Defender for Firewall product → UNKNOWN static.
LT-4: DiagnosticSettings — AzureFirewallApplicationRule or AzureFirewallNetworkRule log enabled → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_firewalls(client: NetworkManagementClient, resource_group: str | None, firewall_name: str | None) -> list:
    if resource_group and firewall_name:
        return [client.azure_firewalls.get(resource_group, firewall_name)]
    elif resource_group:
        return list(client.azure_firewalls.list(resource_group))
    else:
        return list(client.azure_firewalls.list_all())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service — Azure Firewall",
        "status": "UNKNOWN",
        "actual_value": (
            "No dedicated Microsoft Defender for Azure Firewall product exists in the Defender for Cloud portfolio. "
            "Azure Firewall Premium provides built-in IDPS (check NS-1) and TLS inspection for threat detection. "
            "Defender for Cloud surfaces network recommendations but has no per-firewall security product tier."
        ),
        "expected_value": "N/A — no Defender for Firewall product; use IDPS (NS-1) for network threat detection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "expected_value": "Diagnostic settings enabled with AzureFirewallApplicationRule or AzureFirewallNetworkRule log category",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/firewall-diagnostics",
    }
    fw_log_categories = {"AzureFirewallApplicationRule", "AzureFirewallNetworkRule", "AzureFirewallDnsProxy"}
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        firewalls = _get_firewalls(net_client, resource_group, firewall_name)
        if not firewalls:
            return {**base, "resource": firewall_name or "none", "status": "PASS",
                    "actual_value": "No Azure Firewall instances found in scope"}
        first_pass = None
        for fw in firewalls:
            settings = list(monitor.diagnostic_settings.list(fw.id))
            enabled_categories = set()
            for s in settings:
                for log in (getattr(s, "logs", None) or []):
                    if getattr(log, "enabled", False):
                        cat = getattr(log, "category", None) or getattr(log, "category_group", None)
                        if cat:
                            enabled_categories.add(str(cat))
            fw_logs_enabled = enabled_categories & fw_log_categories
            if fw_logs_enabled:
                r = {**base, "resource": fw.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); firewall log categories enabled: {sorted(fw_logs_enabled)}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fw.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no AzureFirewall* log categories enabled — application and network rule logs not captured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": firewall_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
