"""
Logging and Threat Detection checks for Azure Firewall Manager (MCSB v3).
LT-1/4: AFM is management-plane; no Defender product, no resource logs — UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_lt1_defender(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "LT-1", "feature": "Microsoft Defender for Service — Azure Firewall Manager", "status": "UNKNOWN", "actual_value": "No dedicated Microsoft Defender for Azure Firewall Manager product. Defender for Azure Firewall (the resource) may surface recommendations, but Firewall Policy ARM resource has no Defender coverage. Feature=Not Applicable in MCSB v3.", "expected_value": "N/A — no Defender for AFM/Firewall Policy", "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction"}


def check_lt4_resource_logs(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "LT-4", "feature": "Azure Resource Logs", "status": "UNKNOWN", "actual_value": "Firewall Policy ARM resource does not emit standard diagnostic resource logs. Feature=False, Not Applicable in MCSB v3. Firewall activity logs (application/network/threat intel rules) are emitted by the Azure Firewall instances that consume the policy — configure diagnostic settings on those firewall resources.", "expected_value": "N/A — resource logs on Azure Firewall instances, not on policy resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/firewall-diagnostics"}
