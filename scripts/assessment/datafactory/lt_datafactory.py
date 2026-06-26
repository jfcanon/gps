"""LT checks for Azure Data Factory (MCSB v3). LT-4: DiagnosticSettings on factory."""
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.monitor import MonitorManagementClient


def _get_factories(client, rg, name):
    if rg and name:
        return [client.factories.get(rg, name)]
    elif rg:
        return list(client.factories.list_by_resource_group(rg))
    else:
        return list(client.factories.list())


def check_lt1_defender(c, s, r, n):
    return {"resource": n or "all", "control_id": "LT-1", "feature": "Enable Threat Detection Capabilities",
            "status": "UNKNOWN", "actual_value": "No standalone Defender for ADF. Monitor via Defender for Cloud recommendations.",
            "expected_value": "N/A", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_lt4_resource_logs(credential, subscription_id, resource_group, factory_name):
    base = {"control_id": "LT-4", "feature": "Enable Logging for Azure Resources",
            "expected_value": "At least one diagnostic log category enabled (ActivityRuns, PipelineRuns, TriggerRuns)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/data-factory/monitor-using-azure-monitor"}
    try:
        adf_client = DataFactoryManagementClient(credential, subscription_id)
        monitor = MonitorManagementClient(credential, subscription_id)
        factories = _get_factories(adf_client, resource_group, factory_name)
        if not factories:
            return {**base, "resource": factory_name or "none", "status": "PASS", "actual_value": "No factories found"}
        first_pass = None
        for factory in factories:
            settings = list(monitor.diagnostic_settings.list(factory.id))
            logs_enabled = any(getattr(lg, "enabled", False) for s in settings for lg in (getattr(s, "logs", None) or []))
            if logs_enabled:
                r = {**base, "resource": factory.name, "status": "PASS",
                     "actual_value": f"{len(settings)} diagnostic setting(s); logs enabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": factory.name, "status": "FAIL",
                        "actual_value": f"{len(settings)} diagnostic setting(s); no log categories enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": factory_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
