"""BR checks for Azure Virtual WAN (MCSB v3)."""


def check_br1_azure_backup(c, s, r, n):
    return {"resource": n or "all", "control_id": "BR-1", "feature": "Ensure Regular Automated Backups",
            "status": "UNKNOWN",
            "actual_value": "Virtual WAN configuration (hubs, VPN sites, connections) is recoverable via IaC (ARM templates/Bicep/Terraform). No Azure Backup integration for WAN resource.",
            "expected_value": "N/A — export WAN configuration as ARM template to source control",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/security-baseline"}
