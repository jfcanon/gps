"""
PV checks for Azure Virtual Desktop (MCSB v3).

PV-3: Custom VM images → UNKNOWN (compute-level).
PV-5: Vulnerability assessment → UNKNOWN (session host VM-level via Defender).

Read-only. Zero ARM writes.
"""


def check_pv3_automation(c, s, r, n):
    return {"resource": n or "all", "control_id": "PV-3",
            "feature": "Establish Secure Configurations for Compute Resources — Custom VM Images",
            "status": "UNKNOWN",
            "actual_value": "Custom golden images for AVD session hosts are managed via Azure Compute Gallery or managed images — not tracked at the AVD workspace ARM resource level.",
            "expected_value": "Hardened custom images stored in Azure Compute Gallery; host pool points to gallery image",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#pv-3-establish-secure-configurations-for-compute-resources"}


def check_pv5_defender_va(c, s, r, n):
    return {"resource": n or "all", "control_id": "PV-5",
            "feature": "Perform Vulnerability Assessments — Microsoft Defender VA on Session Hosts",
            "status": "UNKNOWN",
            "actual_value": "Vulnerability assessment for AVD session hosts is performed by Defender for Endpoint (Microsoft Threat and Vulnerability Management) at the VM level. Not readable from AVD workspace ARM.",
            "expected_value": "Defender VA enabled on all session host VMs via Defender for Cloud",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#pv-5-perform-vulnerability-assessments"}
