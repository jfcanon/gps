"""
Endpoint Security checks for Azure Public IP (MCSB v3).
ES-1/2/3: PaaS network resource — all UNKNOWN static.
Read-only. Zero ARM writes.
"""


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "ES-1", "feature": "Use Endpoint Detection and Response (EDR) Solution", "status": "UNKNOWN", "actual_value": "PaaS network resource — no customer-accessible compute substrate. EDR agents are deployed on VMs/containers using the Public IP, not on the PIP resource itself.", "expected_value": "N/A — PaaS; no compute substrate", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "ES-2", "feature": "Use Modern Anti-Malware Software", "status": "UNKNOWN", "actual_value": "PaaS network resource — antimalware does not apply to an IP address object. Deploy antimalware on the VMs or services associated with this Public IP.", "expected_value": "N/A — PaaS; antimalware not applicable to PIP", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "ES-3", "feature": "Ensure Anti-Malware Software and Signatures are Updated", "status": "UNKNOWN", "actual_value": "PaaS network resource — no antimalware health monitoring concept for an IP address object.", "expected_value": "N/A — PaaS; not applicable to PIP", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}
