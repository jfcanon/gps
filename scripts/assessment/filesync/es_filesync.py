"""ES checks for Azure File Sync (MCSB v3). Hybrid service — ARM side is PaaS, server agents assessed at OS level."""


def _u(n, c, f, u): return {"resource": n or "all", "control_id": c, "feature": f, "status": "UNKNOWN",
                              "actual_value": "Server-side agents run on on-premises or IaaS VMs — assessed at OS level, not on StorageSyncService ARM resource", "expected_value": "N/A", "evidence_url": u}


def check_es1_edr(c, s, r, n): return _u(n, "ES-1", "EDR Solution", "https://learn.microsoft.com/en-us/azure/defender-for-cloud/endpoint-detection-response")
def check_es2_antimalware(c, s, r, n): return _u(n, "ES-2", "Anti-Malware Solution", "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
def check_es3_antimalware_health(c, s, r, n): return _u(n, "ES-3", "Anti-Malware Health Monitoring", "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
