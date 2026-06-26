"""
Logging and Threat Detection checks for Azure CDN / Azure Front Door (MCSB v3).

LT-4: DiagnosticSettings on profile resource — any log category enabled → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_profiles(client: CdnManagementClient, resource_group: str | None, profile_name: str | None) -> list:
    if resource_group and profile_name:
        return [client.profiles.get(resource_group, profile_name)]
    elif resource_group:
        return list(client.profiles.list_by_resource_group(resource_group))
    else:
        return list(client.profiles.list())


def check_lt1_defender(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "LT-1",
        "feature": "Enable Threat Detection Capabilities — Microsoft Defender for CDN",
        "status": "UNKNOWN",
        "actual_value": "No standalone Defender for CDN/AFD product. WAF policy on AFD Premium provides threat detection at edge. Check WAF policy association.",
        "expected_value": "WAF policy with DRS rule set attached to AFD endpoint",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview",
    }


def check_lt4_resource_logs(credential, subscription_id, resource_group, profile_name):
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cdn/monitoring-and-access-log",
    }
    try:
        cdn_client = CdnManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        profiles = _get_profiles(cdn_client, resource_group, profile_name)
        if not profiles:
            return {**base, "resource": profile_name or "none", "status": "PASS",
                    "actual_value": "No CDN/AFD profiles found in scope"}
        first_pass = None
        for profile in profiles:
            settings = list(monitor.diagnostic_settings.list(profile.id))
            logs_enabled = any(
                getattr(log, "enabled", False)
                for s in settings
                for log in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": profile.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": profile.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": profile_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
