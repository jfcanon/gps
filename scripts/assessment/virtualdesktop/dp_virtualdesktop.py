"""
Data Protection checks for Azure Virtual Desktop (MCSB v3).

DP-1: Purview data classification — UNKNOWN (tenant-level).
DP-2: DLP policies — UNKNOWN (tenant-level).
DP-3: Static PASS (TLS enforced for all AVD connections).
DP-4: Static PASS (session host VM disks + storage encrypted by default).

Read-only. Zero ARM writes.
"""


def check_dp1_sensitive_data(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-1",
            "feature": "Sensitive Data Discovery and Classification",
            "status": "UNKNOWN",
            "actual_value": "Data classification for AVD user data (profile data in Azure Files/Azure NetApp Files) is managed via Microsoft Purview at tenant level. Not readable per AVD workspace.",
            "expected_value": "Sensitive data in FSLogix storage discovered via Microsoft Purview",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#dp-1-discover-classify-and-label-sensitive-data"}


def check_dp2_data_leakage(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-2",
            "feature": "Data Leakage/Loss Prevention",
            "status": "UNKNOWN",
            "actual_value": "DLP for AVD is implemented via Microsoft Purview Information Protection and Windows Information Protection at session host OS level. Not ARM-readable per workspace.",
            "expected_value": "DLP policy applied to session hosts via Intune/GPO",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data"}


def check_dp3_tls_transit(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-3",
            "feature": "Encrypt Data in Transit",
            "status": "PASS",
            "actual_value": "Azure Virtual Desktop connections use TLS 1.2+ for all RDP over HTTPS transport (RDP Shortpath or reverse connect). Not ARM-configurable off.",
            "expected_value": "TLS 1.2+ enforced (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#dp-3-encrypt-sensitive-data-in-transit"}


def check_dp4_platform_keys(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-4",
            "feature": "Encrypt Data at Rest with Platform-Managed Keys",
            "status": "PASS",
            "actual_value": "AVD session host VM OS disks, data disks, and Azure Files FSLogix shares are encrypted at rest with Microsoft-managed keys by default.",
            "expected_value": "Microsoft-managed encryption (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-desktop/security-baseline#dp-4-enable-data-at-rest-encryption-by-default"}
