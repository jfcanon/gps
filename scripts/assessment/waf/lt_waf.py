"""
Logging and Threat Detection checks for Azure WAF Policy (MCSB v3).

LT-1: LIVE-SUB — SecurityCenter subscription pricings (AppServices plan).
      WAF alerts appear in Defender for Cloud when Defender for App Service is Standard tier.
LT-4: LIVE-INDIRECT — DiagSettings on App Gateway resource (NOT on WAF policy.id).
      Category: ApplicationGatewayFirewallLog.
      WAF policy itself emits no diagnostic logs; App GW emits WAF events.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient

_EVIDENCE_LT1 = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/other-threat-protections#display-azure-waf-alerts-in-defender-for-cloud"
_EVIDENCE_LT4 = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-metrics"


def _get_waf_policies(client, resource_group, policy_name):
    if resource_group and policy_name:
        return [client.web_application_firewall_policies.get(resource_group, policy_name)]
    elif resource_group:
        return list(client.web_application_firewall_policies.list(resource_group))
    else:
        return list(client.web_application_firewall_policies.list_all())


def _get_app_gateways_for_policy(client, policy_id):
    result = []
    for ag in client.application_gateways.list_all():
        fp = getattr(ag, 'firewall_policy', None)
        if fp and getattr(fp, 'id', '').lower() == policy_id.lower():
            result.append(ag)
    return result


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "resource": policy_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service (WAF alerts in Defender for Cloud)",
        "expected_value": "Defender for AppServices pricing_tier == 'Standard'",
        "evidence_url": _EVIDENCE_LT1,
    }
    try:
        from azure.mgmt.security import SecurityCenter
        sec = SecurityCenter(credential, subscription_id)
        pricing = sec.pricings.get(
            scope=f"/subscriptions/{subscription_id}",
            pricing_name="AppServices"
        )
        tier = getattr(pricing, 'pricing_tier', None)
        if tier == 'Standard':
            return {**base, "status": "PASS",
                    "actual_value": f"Defender for App Services pricing_tier=Standard; WAF alerts surface in Defender for Cloud"}
        else:
            return {**base, "status": "FAIL",
                    "actual_value": f"Defender for App Services pricing_tier={tier!r}; upgrade to Standard to receive WAF alerts in Defender for Cloud"}
    except Exception as e:
        return {**base, "status": "UNKNOWN", "actual_value": str(e)}


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs (ApplicationGatewayFirewallLog)",
        "expected_value": "ApplicationGatewayFirewallLog enabled on App Gateway DiagSettings",
        "evidence_url": _EVIDENCE_LT4,
    }
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            ags = _get_app_gateways_for_policy(client, policy.id)
            if not ags:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "Policy not attached to any Application Gateway; check DiagSettings on AG directly"}
                first_pass = first_pass or r
                continue
            for ag in ags:
                settings = list(monitor.diagnostic_settings.list(ag.id))
                waf_log_enabled = any(
                    getattr(log_setting, 'enabled', False)
                    for s in settings
                    for log_setting in (getattr(s, 'logs', None) or [])
                    if getattr(log_setting, 'category', '') == 'ApplicationGatewayFirewallLog'
                )
                if waf_log_enabled:
                    r = {**base, "resource": policy.name, "status": "PASS",
                         "actual_value": f"ApplicationGatewayFirewallLog enabled on AG {ag.name} DiagSettings"}
                else:
                    return {**base, "resource": policy.name, "status": "FAIL",
                            "actual_value": f"ApplicationGatewayFirewallLog NOT enabled on AG {ag.name}; enable in Diagnostic Settings to capture WAF block/detect events"}
                first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No App Gateway associations found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}
