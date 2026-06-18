"""
Logging and Threat Detection checks for Azure Application Gateway (MCSB v3).

LT-1: No Defender for Application Gateway product → UNKNOWN (static).
LT-4: DiagnosticSettings — any enabled log category → PASS.
      Key logs: ApplicationGatewayAccessLog, ApplicationGatewayFirewallLog.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        return [client.application_gateways.get(resource_group, gateway_name)]
    elif resource_group:
        return list(client.application_gateways.list(resource_group))
    else:
        return list(client.application_gateways.list_all())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for Application Gateway",
        "status": "UNKNOWN",
        "actual_value": "Microsoft Defender for Application Gateway is not a standalone product in the Defender for Cloud portfolio. WAF (check NS-1) provides threat detection at the application layer. Defender for Cloud may surface AppGW recommendations but has no dedicated pricing tier for this service.",
        "expected_value": "N/A — no Defender for Application Gateway product; use WAF (NS-1) for threat detection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled (ideally ApplicationGatewayAccessLog or ApplicationGatewayFirewallLog)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-diagnostics",
    }
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        gateways = _get_gateways(net_client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            settings = list(monitor.diagnostic_settings.list(gw.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled — access and firewall logs not captured"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
