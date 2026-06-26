"""Endpoint Security checks for Azure CDN / AFD (MCSB v3). PaaS edge — all UNKNOWN."""


def _u(pn, cid, feat, url):
    return {"resource": pn or "all", "control_id": cid, "feature": feat, "status": "UNKNOWN",
            "actual_value": "PaaS edge service — no customer compute layer", "expected_value": "N/A",
            "evidence_url": url}


def check_es1_edr(c, s, r, p): return _u(p, "ES-1", "EDR Solution", "https://learn.microsoft.com/en-us/azure/defender-for-cloud/endpoint-detection-response")
def check_es2_antimalware(c, s, r, p): return _u(p, "ES-2", "Anti-Malware Solution", "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
def check_es3_antimalware_health(c, s, r, p): return _u(p, "ES-3", "Anti-Malware Health Monitoring", "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
