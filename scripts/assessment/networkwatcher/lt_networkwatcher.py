"""
Logging and Threat Detection checks for Azure Network Watcher (MCSB v3).

LT-1: No dedicated Defender for Network Watcher product → UNKNOWN static.
LT-4: False, Not Applicable in MCSB v3 — NW IS the logging/monitoring infrastructure;
      it does not emit its own resource logs to Azure Monitor in the traditional sense.
      UNKNOWN static with note to verify flow log coverage via NSG assessments.

Read-only. Zero ARM writes.
"""


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "LT-1",
        "feature": "Microsoft Defender for Service — Azure Network Watcher",
        "status": "UNKNOWN",
        "actual_value": (
            "No dedicated Microsoft Defender for Network Watcher product in Defender for Cloud portfolio. "
            "Network Watcher is itself a monitoring and diagnostics service — it is part of the security "
            "monitoring stack, not a target for Defender coverage. Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no Defender for NW product; NW IS part of security monitoring infrastructure",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction",
    }


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, watcher_name: str | None) -> dict:
    return {
        "resource": watcher_name or "all",
        "control_id": "LT-4",
        "feature": "Azure Resource Logs",
        "status": "UNKNOWN",
        "actual_value": (
            "Network Watcher resource logs: Feature=False, enabled_by_default=Not Applicable in MCSB v3. "
            "NW IS the logging and traffic analysis infrastructure — it manages NSG Flow Logs, Connection Monitor, "
            "Packet Capture, and Traffic Analytics for other resources. "
            "NW does not emit its own resource logs to Azure Monitor in the traditional service pattern. "
            "RECOMMENDATION: Verify that NSG Flow Logs are configured and enabled on critical NSGs via "
            "client.flow_logs.list(rg, watcher_name) — this is the primary telemetry surface NW provides."
        ),
        "expected_value": "N/A — NW is monitoring infrastructure; verify NSG Flow Log coverage separately",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview",
    }
