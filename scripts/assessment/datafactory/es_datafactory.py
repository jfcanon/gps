"""ES checks for Azure Data Factory (MCSB v3). PaaS — all UNKNOWN."""


def _u(n, c, f, u): return {"resource": n or "all", "control_id": c, "feature": f, "status": "UNKNOWN",
                              "actual_value": "PaaS orchestration service — no customer compute on factory ARM resource (self-hosted IR is customer-managed VM)",
                              "expected_value": "N/A for factory; apply EDR on self-hosted IR VMs", "evidence_url": u}


def check_es1_edr(c, s, r, n): return _u(n, "ES-1", "EDR Solution", "https://learn.microsoft.com/en-us/azure/defender-for-cloud/endpoint-detection-response")
def check_es2_antimalware(c, s, r, n): return _u(n, "ES-2", "Anti-Malware Solution", "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
def check_es3_antimalware_health(c, s, r, n): return _u(n, "ES-3", "Anti-Malware Health Monitoring", "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
