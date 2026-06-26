"""
ES checks for Azure Virtual Desktop (MCSB v3).

Session hosts are Windows VMs. EDR/antimalware state is at VM level,
not readable from AVD workspace ARM resource.
"""


def check_es1_edr(c, s, r, n):
    return {"resource": n or "all", "control_id": "ES-1",
            "feature": "EDR Solution — Microsoft Defender for Endpoint on Session Hosts",
            "status": "UNKNOWN",
            "actual_value": "MDE deployment on AVD session hosts (Windows VMs) is managed via Intune or Defender for Cloud. Not readable from AVD workspace ARM resource.",
            "expected_value": "MDE enrolled on all session host VMs",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#es-1-use-endpoint-detection-and-response-edr"}


def check_es2_antimalware(c, s, r, n):
    return {"resource": n or "all", "control_id": "ES-2",
            "feature": "Anti-Malware Solution — Microsoft Defender Antivirus on Session Hosts",
            "status": "UNKNOWN",
            "actual_value": "Microsoft Defender Antivirus is built into Windows 10/11 and Windows Server multi-session used by AVD. Its active state on session hosts is not readable from AVD workspace ARM resource.",
            "expected_value": "Defender Antivirus active and reporting on all session hosts",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#es-2-use-centrally-managed-modern-anti-malware-software"}


def check_es3_antimalware_health(c, s, r, n):
    return {"resource": n or "all", "control_id": "ES-3",
            "feature": "Anti-Malware Solution Health Monitoring",
            "status": "UNKNOWN",
            "actual_value": "Antimalware health monitoring for AVD session hosts is via Defender for Cloud / MDE. Not readable from AVD workspace ARM resource.",
            "expected_value": "Defender Antivirus health monitored via Defender for Cloud",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#es-3-ensure-anti-malware-software-and-signatures-are-updated"}
