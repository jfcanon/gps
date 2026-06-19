"""
Backup and Recovery checks for Azure DNS (MCSB v3).

BR-1: Azure Backup not supported for DNS Zones.
      DNS zones are quickly recreatable from IaC or zone file export.
      Both checks UNKNOWN static (not_applicable_paas).

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_br1_azure_backup(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "BR-1",
        "feature": "Azure Backup",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Backup does not support DNS Zones. "
            "DNS zone records can be exported via 'az network dns zone export -g <rg> -n <zone> -f zone.txt' "
            "and stored in version-controlled IaC. IaC (ARM/Bicep/Terraform) is the primary backup mechanism. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — Azure Backup not supported; use IaC + zone file export as compensating control",
        "evidence_url": _EVIDENCE,
    }


def check_br1_native_backup(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "BR-1",
        "feature": "Service Native Backup Capability",
        "status": "UNKNOWN",
        "actual_value": (
            "No native backup product for Azure DNS. "
            "Zone file export ('az network dns zone export') produces RFC 1035 zone file format. "
            "DNS zones are recreatable from zone files or IaC with low RTO. "
            "Compensating control: export zone files to Storage Account on schedule. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no native backup; zone file export + IaC as compensating controls",
        "evidence_url": _EVIDENCE,
    }
