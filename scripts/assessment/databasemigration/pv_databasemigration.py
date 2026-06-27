"""PV checks for Azure Database Migration Service (MCSB v3). Managed migration service — all UNKNOWN."""


def _u(n, c, f, u): return {"resource": n or "all", "control_id": c, "feature": f, "status": "UNKNOWN",
                              "actual_value": "DMS infrastructure managed by Microsoft — transient migration service", "expected_value": "N/A", "evidence_url": u}


def check_pv3_automation(c, s, r, n): return _u(n, "PV-3", "Azure Automation State Configuration", "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")
def check_pv5_defender_va(c, s, r, n): return _u(n, "PV-5", "Vulnerability Assessment", "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")
def check_pv6_update_mgmt(c, s, r, n): return _u(n, "PV-6", "Update Management", "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
