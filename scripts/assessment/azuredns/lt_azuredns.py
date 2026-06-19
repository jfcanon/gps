"""
Logging and Threat Detection checks for Azure DNS (MCSB v3).

LT-1: Defender for DNS — LIVE check via SecurityCenter.pricings API.
      Subscription-level (not per-zone). pricing_name='Dns'; Standard→PASS; Free→FAIL.
      Handle ResourceNotFoundError: plan may be deprecated/merged in newer tenants.

LT-4: Azure Resource Logs — LIVE check via MonitorManagementClient.diagnostic_settings.
      DiagnosticSettings on zone.id; any enabled log category→PASS.
      Key categories: QueryVolume, VirtualNetworkLinkWithRegistration, VirtualNetworkLink.

Read-only. Zero ARM writes.
"""
from azure.mgmt.dns import DnsManagementClient


def _get_dns_zones(client: DnsManagementClient, resource_group: str | None, zone_name: str | None) -> list:
    if resource_group and zone_name:
        return [client.zones.get(resource_group, zone_name)]
    elif resource_group:
        return list(client.zones.list_by_resource_group(resource_group))
    else:
        return list(client.zones.list())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    base = {
        "resource": zone_name or "subscription",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for DNS",
        "expected_value": "pricing_tier == 'Standard' (Defender for DNS enabled at subscription level)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-introduction",
    }
    try:
        from azure.mgmt.security import SecurityCenter
        sec_client = SecurityCenter(credential, subscription_id)
        pricing = sec_client.pricings.get(
            scope=f"/subscriptions/{subscription_id}",
            pricing_name="Dns",
        )
        tier = getattr(pricing, "pricing_tier", None)
        if tier == "Standard":
            return {**base, "status": "PASS",
                    "actual_value": "Defender for DNS pricing_tier=Standard — enabled at subscription level; protects all DNS queries in subscription"}
        else:
            return {**base, "status": "FAIL",
                    "actual_value": f"Defender for DNS pricing_tier={tier!r} — not enabled; DNS-based exfiltration and C2 detection inactive"}
    except Exception as e:
        err = str(e)
        if "ResourceNotFound" in err or "NotFound" in err or "404" in err:
            return {**base, "status": "UNKNOWN",
                    "actual_value": (
                        "Defender for DNS plan not found in this subscription. "
                        "This plan may have been deprecated or merged into 'Dns' subplan under Defender CSPM "
                        "in newer tenants. Verify via Defender for Cloud → Environment Settings. "
                        f"API error: {err}"
                    )}
        return {**base, "status": "UNKNOWN", "actual_value": err}


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "expected_value": "At least one diagnostic log category enabled (QueryVolume, VirtualNetworkLinkWithRegistration, or VirtualNetworkLink)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/dns/dns-alerts-metrics",
    }
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        dns_client = DnsManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        zones = _get_dns_zones(dns_client, resource_group, zone_name)
        if not zones:
            return {**base, "resource": zone_name or "none", "status": "PASS",
                    "actual_value": "No DNS Zones found in scope"}
        first_pass = None
        for zone in zones:
            settings = list(monitor.diagnostic_settings.list(zone.id))
            logs_enabled = any(
                getattr(log_setting, "enabled", False)
                for s in settings
                for log_setting in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": zone.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": zone.name, "status": "FAIL",
                        "actual_value": (
                            f"{len(settings)} diagnostic setting(s); no log categories enabled. "
                            "DNS query volume and VNet link logs not captured. "
                            "Enable QueryVolume category to track resolution patterns."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": zone_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
