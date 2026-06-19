"""
Backup and Recovery checks for Azure WAF Policy (MCSB v3).

BR-1×2: UNKNOWN static — WAF policy is an ARM resource with no backup targets.
    Azure Backup does not support WAF policy as backup target.
    WAF policy config is IaC-recoverable (ARM template / Bicep / Terraform).

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": "Azure Backup does not support WAF Policy as a backup target. WAF policy configuration is IaC-recoverable via ARM template export (managed rule sets, custom rules, policy settings). not_applicable.",
        "expected_value": "N/A — Azure Backup not supported for WAF Policy; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": "WAF Policy has no native backup capability. Configuration (managed rule sets, exclusions, custom rules) is IaC-recoverable via ARM template export. not_applicable.",
        "expected_value": "N/A — no native backup; IaC-recoverable; not_applicable in baseline",
        "evidence_url": _EVIDENCE,
    }
