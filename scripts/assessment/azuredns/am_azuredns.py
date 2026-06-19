"""
Asset Management checks for Azure DNS (MCSB v3).

AM-2: Tags presence proxy for Azure Policy governance coverage — LIVE check.
AM-5: Defender AAC — targets VMs only → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.dns import DnsManagementClient


def _get_dns_zones(client: DnsManagementClient, resource_group: str | None, zone_name: str | None) -> list:
    if resource_group and zone_name:
        return [client.zones.get(resource_group, zone_name)]
    elif resource_group:
        return list(client.zones.list_by_resource_group(resource_group))
    else:
        return list(client.zones.list())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for Azure Policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/dns/dns-overview",
    }
    try:
        client = DnsManagementClient(credential, subscription_id)
        zones = _get_dns_zones(client, resource_group, zone_name)
        if not zones:
            return {**base, "resource": zone_name or "none", "status": "PASS",
                    "actual_value": "No DNS Zones found in scope"}
        first_pass = None
        for zone in zones:
            tags = getattr(zone, "tags", None) or {}
            if tags:
                r = {**base, "resource": zone.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": zone.name, "status": "FAIL",
                        "actual_value": (
                            "tags={} — no resource tags; Azure Policy governance tagging not confirmed. "
                            f"Zone type: {getattr(zone, 'zone_type', 'Unknown')}. "
                            "Apply environment/owner/cost-center tags via Azure Policy."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": zone_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "AM-5",
        "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC",
        "status": "UNKNOWN",
        "actual_value": "PaaS DNS hosting service — Adaptive Application Controls target VMs and Arc-enabled servers; not applicable to Azure DNS Zone.",
        "expected_value": "N/A — PaaS; AAC not applicable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
