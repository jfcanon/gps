"""Posture and Vulnerability Management for Azure CDN / AFD (MCSB v3). PaaS — all UNKNOWN."""


def _u(pn, cid, feat, url):
    return {"resource": pn or "all", "control_id": cid, "feature": feat, "status": "UNKNOWN",
            "actual_value": "PaaS service — Microsoft manages infrastructure", "expected_value": "N/A",
            "evidence_url": url}


def check_pv3_automation(c, s, r, p): return _u(p, "PV-3", "Azure Automation State Configuration", "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")
def check_pv5_defender_va(c, s, r, p): return _u(p, "PV-5", "Vulnerability Assessment", "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")
def check_pv6_update_mgmt(c, s, r, p): return _u(p, "PV-6", "Azure Automation Update Management", "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
