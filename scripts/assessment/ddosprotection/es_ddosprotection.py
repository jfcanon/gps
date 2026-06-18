"""
Endpoint Security checks for Azure DDoS Protection (MCSB v3).
ES-1/2/3: PaaS control-plane resource — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "ES-1", "feature": "Use Endpoint Detection and Response (EDR) Solution", "status": "UNKNOWN", "actual_value": "PaaS control-plane resource — no customer-accessible compute substrate. EDR agents deploy on VMs in the protected VNets, not on the DDoS plan itself.", "expected_value": "N/A — PaaS; no compute substrate", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "ES-2", "feature": "Use Modern Anti-Malware Software", "status": "UNKNOWN", "actual_value": "PaaS control-plane resource — antimalware does not apply to a DDoS configuration object. Deploy antimalware on the VMs within the protected VNets.", "expected_value": "N/A — PaaS; antimalware not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {"resource": plan_name or "all", "control_id": "ES-3", "feature": "Ensure Anti-Malware Software and Signatures are Updated", "status": "UNKNOWN", "actual_value": "PaaS control-plane resource — no antimalware health monitoring concept for DDoS plan.", "expected_value": "N/A — PaaS; not applicable", "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview"}
