"""
Network Security checks for Azure DNS (MCSB v3).

All NS controls: DNS Zone is PaaS managed by Azure's global anycast infrastructure.
No NSG, no VNet integration, no Private Link concept, no public toggle on zone resource.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DNS Zone is a PaaS resource hosted on Microsoft's global anycast DNS infrastructure. "
            "NSGs apply to subnets and NICs — the DNS Zone has no VNet presence and no NIC. "
            "DNS query traffic is routed to Azure's anycast DNS resolvers, not through customer-managed subnets. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — PaaS DNS Zone; NSG applies to client subnets, not the zone resource",
        "evidence_url": _EVIDENCE,
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "UNKNOWN",
        "actual_value": (
            "Public DNS Zones have no VNet integration — they are globally accessible by design. "
            "Private DNS Zones have Virtual Network Links (registration and resolution links) but these are "
            "product functionality enabling private name resolution, not an NS-1 network segmentation control. "
            "VNet Link state is not a security posture check for NS-1. Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — Public DNS global by design; Private DNS VNet links are product feature, not NS control",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/dns/private-dns-virtual-network-links",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DNS Zone itself has no Private Link concept. "
            "Note: Private DNS Zones ARE used to resolve privatelink.* FQDNs for other services' private endpoints, "
            "but the DNS Zone resource itself does not expose a private endpoint. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — DNS Zone has no private endpoint; it resolves PEs for other services",
        "evidence_url": _EVIDENCE,
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Public DNS Zones are globally accessible by design — their purpose is global DNS resolution. "
            "There is no public_network_access property on the DNS Zone resource. "
            "Private DNS Zones resolve only within linked VNets — they are private by design with no toggle. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no public network access toggle; Public DNS global by design, Private DNS private by design",
        "evidence_url": _EVIDENCE,
    }
