"""
Endpoint Security checks for Azure Bastion (MCSB v3).

ES-1/2/3: UNKNOWN static — all feature_supported=Not Applicable, final_verdict=not_applicable.
    EDR and anti-malware target compute workloads (VMs, Arc servers).
    Azure Bastion is a managed PaaS jump host; no customer-accessible compute substrate.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_PAAS_NOTE = "Azure Bastion is a managed PaaS jump host — no customer-accessible compute substrate; "


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "ES-1",
        "feature": "Endpoint Detection and Response (EDR)",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "EDR (Microsoft Defender for Endpoint) targets compute workloads. Enable MDE on the VMs accessed via Bastion — not on Bastion itself. not_applicable.",
        "expected_value": "N/A — PaaS managed service; EDR not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "ES-2",
        "feature": "Anti-Malware Solution",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "anti-malware (Microsoft Defender Antivirus, MDE) targets compute workloads with accessible file systems. Bastion has no customer-accessible OS. Deploy anti-malware on the VMs accessed via Bastion. not_applicable.",
        "expected_value": "N/A — PaaS managed service; anti-malware not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "ES-3",
        "feature": "Anti-Malware Solution Health Monitoring",
        "status": "UNKNOWN",
        "actual_value": _PAAS_NOTE + "anti-malware health monitoring presupposes anti-malware deployment on compute. Bastion has no customer-accessible OS or compute. not_applicable.",
        "expected_value": "N/A — PaaS managed service; health monitoring not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }
