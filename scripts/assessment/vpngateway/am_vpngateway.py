"""
Asset Management checks for Azure VPN Gateway (MCSB v3).

AM-2: True, False, customer → LIVE — tags proxy for Azure Policy governance.
AM-5: Not Applicable — PaaS network service; no compute for Adaptive Application Controls.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_vpn_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        gw = client.virtual_network_gateways.get(resource_group, gateway_name)
        return [gw] if getattr(gw, "gateway_type", "") == "Vpn" else []
    elif resource_group:
        return [g for g in client.virtual_network_gateways.list(resource_group)
                if getattr(g, "gateway_type", "") == "Vpn"]
    else:
        raise ValueError("--resource-group required: VirtualNetworkGateways have no subscription-wide list()")


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for Azure Policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_vpn_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No VPN Gateway instances found in scope"}
        first_pass = None
        for vng in gateways:
            tags = getattr(vng, "tags", None) or {}
            if tags:
                r = {**base, "resource": vng.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": vng.name, "status": "FAIL",
                        "actual_value": (
                            "tags={} — no resource tags; Azure Policy governance tagging not confirmed. "
                            "Apply environment/owner/cost-center tags via Azure Policy to enforce AM-2."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "AM-5",
        "feature": "Microsoft Defender for Cloud — Adaptive Application Controls",
        "status": "UNKNOWN",
        "actual_value": "PaaS network service — Adaptive Application Controls target VMs and Arc-enabled servers; not applicable to VPN Gateway.",
        "expected_value": "N/A — PaaS; AAC not applicable to VPN GW",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }
