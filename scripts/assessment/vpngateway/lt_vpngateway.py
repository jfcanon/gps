"""
Logging and Threat Detection checks for Azure VPN Gateway (MCSB v3).

LT-1: Not Applicable → UNKNOWN static (still_not_applicable).
    No dedicated Microsoft Defender for VPN Gateway product.

LT-4: False, Not Applicable (original) → now_applicable_native LIVE.
    VPN GW DiagSettings now available — feature was missing from original v3 baseline.
    Key log categories: TunnelDiagnosticLog, IKEDiagnosticLog, P2SDiagnosticLog,
    RouteDiagnosticLog, GatewayDiagnosticLog.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_vpn_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        gw = client.virtual_network_gateways.get(resource_group, gateway_name)
        return [gw] if getattr(gw, "gateway_type", "") == "Vpn" else []
    elif resource_group:
        return [g for g in client.virtual_network_gateways.list(resource_group)
                if getattr(g, "gateway_type", "") == "Vpn"]
    else:
        raise ValueError("--resource-group required: VirtualNetworkGateways have no subscription-wide list()")


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service",
        "status": "UNKNOWN",
        "actual_value": (
            "No dedicated Microsoft Defender for VPN Gateway product in the Defender for Cloud portfolio. "
            "VPN GW has no Defender pricing tier. "
            "Network security monitoring is done via Azure Monitor, NSG flow logs on connected VNets, "
            "and Azure Firewall logs on traffic traversing VPN-connected networks. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no Defender for VPN GW product; use Azure Monitor + NSG flow logs for tunnel telemetry",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "expected_value": "At least one diagnostic log category enabled (TunnelDiagnosticLog / IKEDiagnosticLog / P2SDiagnosticLog / RouteDiagnosticLog)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/vpn-gateway/troubleshoot-vpn-with-azure-diagnostics",
    }
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        gateways = _get_vpn_gateways(net_client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No VPN Gateway instances found in scope"}
        first_pass = None
        for vng in gateways:
            settings = list(monitor.diagnostic_settings.list(vng.id))
            logs_enabled = any(
                getattr(log_setting, "enabled", False)
                for s in settings
                for log_setting in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": vng.name, "status": "PASS",
                     "actual_value": (
                         f"{len(settings)} diagnostic setting(s); at least one log category enabled. "
                         "feature_supported=False in original v3 baseline; "
                         "VPN GW DiagSettings now available (now_applicable_native)."
                     )}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vng.name, "status": "FAIL",
                        "actual_value": (
                            f"{len(settings)} diagnostic setting(s); no log categories enabled. "
                            "TunnelDiagnosticLog and IKEDiagnosticLog not captured — "
                            "VPN tunnel connectivity issues and IKE negotiation failures will not be logged. "
                            "Enable DiagSettings to send logs to Log Analytics or Storage Account."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
