"""
Logging and Threat Detection checks for Azure Front Door (MCSB v3).

LT-1: False, Not Applicable — no Defender for Front Door product → UNKNOWN static.
LT-4: True, False → DiagnosticSettings on fd.id → LIVE via MonitorManagementClient.
      Key categories: FrontdoorAccessLog, FrontdoorWebApplicationFirewallLog.

Read-only. Zero ARM writes.
"""
from azure.mgmt.frontdoor import FrontDoorManagementClient


def _get_front_doors(client: FrontDoorManagementClient, resource_group: str | None, front_door_name: str | None) -> list:
    if resource_group and front_door_name:
        return [client.front_doors.get(resource_group, front_door_name)]
    elif resource_group:
        return list(client.front_doors.list_by_resource_group(resource_group))
    else:
        return list(client.front_doors.list())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Azure Front Door",
        "status": "UNKNOWN",
        "actual_value": (
            "No dedicated Microsoft Defender for Front Door product in Defender for Cloud portfolio. "
            "WAF policy linked to AFD (NS-2 check) provides application-layer threat detection "
            "(OWASP ruleset, bot protection, IP filtering). "
            "Defender for Cloud may surface AFD WAF recommendations but has no dedicated pricing tier. "
            "Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no Defender for AFD product; use WAF policy (NS-2) for threat detection",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Enable Logging for Azure Resources",
        "expected_value": "At least one diagnostic log category enabled (FrontdoorAccessLog or FrontdoorWebApplicationFirewallLog)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-diagnostics",
    }
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        fd_client = FrontDoorManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        front_doors = _get_front_doors(fd_client, resource_group, front_door_name)
        if not front_doors:
            return {**base, "resource": front_door_name or "none", "status": "PASS",
                    "actual_value": "No Front Door instances found in scope"}
        first_pass = None
        for fd in front_doors:
            settings = list(monitor.diagnostic_settings.list(fd.id))
            logs_enabled = any(
                getattr(log_setting, "enabled", False)
                for s in settings
                for log_setting in (getattr(s, "logs", None) or [])
            )
            if logs_enabled:
                r = {**base, "resource": fd.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); at least one log category enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fd.name, "status": "FAIL",
                        "actual_value": (
                            f"{len(settings)} diagnostic setting(s); no log categories enabled. "
                            "FrontdoorAccessLog and FrontdoorWebApplicationFirewallLog not captured."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": front_door_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
