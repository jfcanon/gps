"""PV checks for Azure Databricks (MCSB v3). Ephemeral cluster VMs — all UNKNOWN at workspace ARM level."""


def _u(n, c, f, u): return {"resource": n or "all", "control_id": c, "feature": f, "status": "UNKNOWN",
                              "actual_value": "Databricks cluster VMs are ephemeral — apply patching/VA via Databricks Runtime version selection or init scripts, not ARM",
                              "expected_value": "N/A at ARM level — use latest Databricks Runtime LTS", "evidence_url": u}


def check_pv3_automation(c, s, r, n): return _u(n, "PV-3", "Azure Automation State Configuration", "https://learn.microsoft.com/en-us/azure/automation/automation-dsc-overview")
def check_pv5_defender_va(c, s, r, n): return _u(n, "PV-5", "Vulnerability Assessment", "https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-defender-vulnerability-management")
def check_pv6_update_mgmt(c, s, r, n): return _u(n, "PV-6", "Update Management", "https://learn.microsoft.com/en-us/azure/automation/update-management/overview")
