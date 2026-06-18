"""
Endpoint Security checks for Azure Firewall Manager (MCSB v3).
ES-1/2/3: PaaS management-plane service — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "ES-1", "feature": "Use Endpoint Detection and Response (EDR) Solution", "status": "UNKNOWN", "actual_value": "PaaS management-plane service — no customer-accessible compute substrate. EDR agents deploy on VMs protected by the firewalls using this policy, not on the policy resource itself.", "expected_value": "N/A — PaaS; no compute substrate", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "ES-2", "feature": "Use Modern Anti-Malware Software", "status": "UNKNOWN", "actual_value": "PaaS management-plane service — antimalware does not apply to a Firewall Policy configuration object. Note: Azure Firewall Premium with IDPS provides network-level threat detection for traffic governed by this policy.", "expected_value": "N/A — PaaS; antimalware not applicable to policy resource", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {"resource": policy_name or "all", "control_id": "ES-3", "feature": "Ensure Anti-Malware Software and Signatures are Updated", "status": "UNKNOWN", "actual_value": "PaaS management-plane service — no antimalware health monitoring concept for Firewall Policy resource.", "expected_value": "N/A — PaaS; not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview"}
