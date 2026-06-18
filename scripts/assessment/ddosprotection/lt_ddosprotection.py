"""
Logging and Threat Detection checks for Azure DDoS Protection (MCSB v3).

LT-1: No dedicated Defender for DDoS Protection product → UNKNOWN static.
LT-4: DiagnosticSettings on plan — any enabled log/metric → PASS.
      Note: primary DDoS telemetry (mitigation flow logs, notifications) lives on Public IP resources;
      plan-level DiagnosticSettings checked as proxy.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_ddos_plans(client: NetworkManagementClient, resource_group: str | None, plan_name: str | None) -> list:
    if resource_group and plan_name:
        return [client.ddos_protection_plans.get(resource_group, plan_name)]
    elif resource_group:
        return list(client.ddos_protection_plans.list_by_resource_group(resource_group))
    else:
        return list(client.ddos_protection_plans.list())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {
        "resource": plan_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service — Azure DDoS Protection",
        "status": "UNKNOWN",
        "actual_value": (
            "No dedicated Microsoft Defender for Azure DDoS Protection product in the Defender for Cloud portfolio. "
            "DDoS Protection Standard IS the threat detection and mitigation mechanism for volumetric attacks. "
            "Defender for Cloud may surface DDoS-related recommendations but has no per-plan pricing tier."
        ),
        "expected_value": "N/A — DDoS Protection Standard itself is the network threat mitigation service",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    base = {
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "expected_value": "Diagnostic settings enabled with at least one log or metric (plan-level proxy; primary DDoS telemetry is on Public IP resources)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/diagnostic-logging",
    }
    try:
        net_client = NetworkManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        plans = _get_ddos_plans(net_client, resource_group, plan_name)
        if not plans:
            return {**base, "resource": plan_name or "none", "status": "PASS",
                    "actual_value": "No DDoS Protection Plan instances found in scope"}
        first_pass = None
        for plan in plans:
            settings = list(monitor.diagnostic_settings.list(plan.id))
            enabled_logs = []
            has_metrics = False
            for s in settings:
                for log in (getattr(s, "logs", None) or []):
                    if getattr(log, "enabled", False):
                        cat = getattr(log, "category", None) or getattr(log, "category_group", None)
                        if cat:
                            enabled_logs.append(str(cat))
                for metric in (getattr(s, "metrics", None) or []):
                    if getattr(metric, "enabled", False):
                        has_metrics = True
            if enabled_logs or has_metrics:
                detail = f"log categories: {enabled_logs}" if enabled_logs else "metrics-only"
                r = {**base, "resource": plan.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s) on plan; {detail}. Note: DDoSProtectionNotifications and flow logs are on protected Public IP resources — verify those separately."}
                first_pass = first_pass or r
            else:
                return {**base, "resource": plan.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no logs or metrics enabled on DDoS plan. Also verify DiagnosticSettings on associated Public IP resources for mitigation flow logs."}
        return first_pass
    except Exception as e:
        return {**base, "resource": plan_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
