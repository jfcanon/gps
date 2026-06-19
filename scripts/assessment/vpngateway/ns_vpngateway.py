"""
Network Security checks for Azure VPN Gateway (MCSB v3).

NS-1 NSG: True, True, microsoft_managed → PASS static.
    VPN GW subnets are in customer VNet; VNet subnet traffic respects NSG rules by default.
    Note: Microsoft explicitly advises NOT placing an NSG on GatewaySubnet — doing so breaks connectivity.
    NSG protection is on spoke/workload subnets, not GatewaySubnet itself.

NS-1 VNet: True, True, microsoft_managed → PASS static.
    VPN GW always deployed into customer GatewaySubnet within a VNet; VNet integration inherent.

NS-2 Private Link: False, Not Applicable → UNKNOWN static (still_not_applicable).
    VPN GW IS the private connectivity service; Private Endpoint not applicable on VPN GW itself.

NS-2 Disable Public: Not Applicable → UNKNOWN static (still_not_applicable).
    VPN GW requires a public IP for IKE negotiation; no public_network_access toggle.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "PASS",
        "actual_value": (
            "VPN GW subnets are in customer VNet; VNet subnet traffic respects NSG rules by default. "
            "feature_supported=True, enabled_by_default=True, responsibility=microsoft_managed. "
            "Note: Microsoft explicitly recommends NOT placing an NSG on GatewaySubnet — "
            "NSG on GatewaySubnet can break VPN connectivity. "
            "NSG protection is applied on spoke/workload subnets, not on GatewaySubnet itself."
        ),
        "expected_value": "VNet NSG rules respected by default (microsoft_managed — no customer action required)",
        "evidence_url": _EVIDENCE,
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "PASS",
        "actual_value": (
            "VPN GW always deployed into customer GatewaySubnet within a VNet — VNet integration is inherent. "
            "feature_supported=True, enabled_by_default=True, responsibility=microsoft_managed. "
            "GatewaySubnet (/27 or larger) is required; VPN GW cannot be deployed outside a VNet."
        ),
        "expected_value": "VPN GW always in customer VNet (microsoft_managed — no customer action required)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-create-gateway-portal",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "VPN Gateway IS the private connectivity service — it provides secure IPsec tunnels between "
            "on-premises networks/clients and Azure VNets. "
            "Private Endpoint is not applicable on the VPN GW resource itself. "
            "feature_supported=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — VPN GW is private connectivity infrastructure; PE not applicable on GW itself",
        "evidence_url": _EVIDENCE,
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": (
            "VPN GW requires a public IP address for IKE peer negotiation (S2S VPN) and "
            "P2S client connections — the public IP is the VPN tunnel endpoint. "
            "Disabling public access is not possible; no public_network_access toggle exists. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — public IP inherent to VPN GW function; no disable-public toggle",
        "evidence_url": _EVIDENCE,
    }
