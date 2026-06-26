"""LT checks for Azure Virtual Desktop (MCSB v3). LT-4: DiagnosticSettings on workspace."""
from azure.mgmt.desktopvirtualization import DesktopVirtualizationMgmtClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_workspaces(client, rg, name):
    if rg and name:
        return [client.workspaces.get(rg, name)]
    elif rg:
        return list(client.workspaces.list_by_resource_group(rg))
    else:
        try:
            return list(client.workspaces.list())
        except Exception:
            return []


def check_lt1_defender(c, s, r, n):
    return {"resource": n or "all", "control_id": "LT-1", "feature": "Enable Threat Detection Capabilities",
            "status": "UNKNOWN",
            "actual_value": "Defender for Endpoint covers AVD session hosts (Windows VMs). Defender for Cloud provides AVD-level recommendations. Not ARM-readable per workspace.",
            "expected_value": "MDE deployed on all session hosts; Defender for Cloud enabled",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#lt-1-enable-threat-detection-capabilities"}


def check_lt4_resource_logs(credential, subscription_id, resource_group, workspace_name):
    base = {"control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
            "expected_value": "At least one diagnostic log category enabled (Checkpoint, Error, Management, Feed)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/diagnostics-log-analytics"}
    try:
        avd_client = DesktopVirtualizationMgmtClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        workspaces = _get_workspaces(avd_client, resource_group, workspace_name)
        if not workspaces:
            return {**base, "resource": workspace_name or "none", "status": "UNKNOWN",
                    "actual_value": "No workspaces found — provide --resource-group"}
        first_pass = None
        for ws in workspaces:
            settings = list(monitor.diagnostic_settings.list(ws.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": ws.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); logs enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": ws.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workspace_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
