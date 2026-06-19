"""
Logging and Threat Detection checks for Azure Bastion (MCSB v3).

LT-4 Azure Resource Logs: LIVE-DIRECT.
    final_verdict=customer (True/False). Bastion emits 'BastionAuditLogs' which record
    remote session details: user identity, source IP, target VM, session duration.
    Check: DiagnosticSettings on bastion.id with 'BastionAuditLogs' enabled.
    SDK: azure-mgmt-monitor (MonitorManagementClient).
    Category name: 'BastionAuditLogs' (check both with and without trailing 's'
    for API version safety).

LT-1 Microsoft Defender for Service: UNKNOWN static.
    feature_supported=Not Applicable, final_verdict=not_applicable.
    No Microsoft Defender plan exists for Azure Bastion as a service.
    Defender for Cloud monitors the VMs accessed via Bastion, not Bastion itself.

Read-only. Zero ARM writes.
SDK: azure-mgmt-network + azure-mgmt-monitor (LT-4 only).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_EVIDENCE_LOGS = "https://learn.microsoft.com/en-us/azure/bastion/diagnostic-logs"


def _get_bastions(client, resource_group, bastion_name):
    if bastion_name and resource_group:
        return [client.bastion_hosts.get(resource_group, bastion_name)]
    elif resource_group:
        return list(client.bastion_hosts.list(resource_group))
    else:
        return list(client.bastion_hosts.list_all())


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=Not Applicable in MCSB v3 baseline. No Microsoft Defender plan exists for Azure Bastion. Defender for Cloud monitors the VMs and other resources accessed via Bastion, not Bastion itself. not_applicable.",
        "expected_value": "N/A — no Defender plan for Azure Bastion; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.monitor import MonitorManagementClient

    net_client = NetworkManagementClient(credential, subscription_id)
    monitor = MonitorManagementClient(credential, subscription_id)

    try:
        bastions = _get_bastions(net_client, resource_group, bastion_name)
    except Exception as e:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "LT-4",
            "feature": "Azure Resource Logs",
            "status": "UNKNOWN",
            "actual_value": f"Error listing bastion hosts: {e}",
            "expected_value": "DiagnosticSettings with BastionAuditLogs enabled",
            "evidence_url": _EVIDENCE_LOGS,
        }

    if not bastions:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "LT-4",
            "feature": "Azure Resource Logs",
            "status": "UNKNOWN",
            "actual_value": "No Azure Bastion hosts found in scope",
            "expected_value": "DiagnosticSettings with BastionAuditLogs enabled",
            "evidence_url": _EVIDENCE_LOGS,
        }

    results = []
    for bastion in bastions:
        try:
            settings = list(monitor.diagnostic_settings.list(bastion.id))
            audit_enabled = any(
                getattr(log, 'enabled', False)
                for s in settings
                for log in (getattr(s, 'logs', None) or [])
                if getattr(log, 'category', '') in ('BastionAuditLogs', 'BastionAuditLog')
            )
            if audit_enabled:
                results.append(("PASS", bastion.name, "BastionAuditLogs enabled"))
            else:
                cat_found = [
                    getattr(log, 'category', '')
                    for s in settings
                    for log in (getattr(s, 'logs', None) or [])
                ]
                detail = f"BastionAuditLogs not enabled; found categories: {cat_found}" if settings else "No DiagnosticSettings configured"
                results.append(("FAIL", bastion.name, detail))
        except Exception as e:
            results.append(("UNKNOWN", bastion.name, str(e)))

    statuses = [r[0] for r in results]
    if "FAIL" in statuses:
        agg_status = "FAIL"
    elif all(s == "PASS" for s in statuses):
        agg_status = "PASS"
    else:
        agg_status = "UNKNOWN"

    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "status": agg_status,
        "actual_value": str(results),
        "expected_value": "DiagnosticSettings with BastionAuditLogs enabled",
        "evidence_url": _EVIDENCE_LOGS,
    }
