"""
Endpoint Security checks for Azure Firewall (MCSB v3).

ES-1/2/3: PaaS — no VM or container substrate accessible to customer → all UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "ES-1",
        "feature": "Use Endpoint Detection and Response (EDR) Solution",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Azure Firewall runs on Microsoft-managed infrastructure. No customer-accessible VM or container substrate exists to deploy EDR agents. Microsoft manages platform-level endpoint security.",
        "expected_value": "N/A — PaaS; no customer-managed compute substrate",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#es-1-use-endpoint-detection-and-response-edr",
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "ES-2",
        "feature": "Use Modern Anti-Malware Software",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — Microsoft-managed infrastructure. Customers cannot deploy or configure antimalware solutions on Azure Firewall compute nodes. Platform anti-malware is Microsoft's responsibility.",
        "expected_value": "N/A — PaaS; anti-malware is Microsoft's responsibility",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#es-2-use-modern-anti-malware-software",
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "ES-3",
        "feature": "Ensure Anti-Malware Software and Signatures are Updated",
        "status": "UNKNOWN",
        "actual_value": "PaaS service — anti-malware signature updates on Azure Firewall infrastructure are managed by Microsoft. Customers have no visibility into or control over platform-level anti-malware health.",
        "expected_value": "N/A — PaaS; update management is Microsoft's responsibility",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#es-3-ensure-anti-malware-software-and-signatures-are-updated",
    }
