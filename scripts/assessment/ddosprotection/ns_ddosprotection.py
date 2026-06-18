"""
Network Security checks for Azure DDoS Protection (MCSB v3).

NS-1 NSG: DDoS plan is a control-plane grouping resource; NSG not applicable → UNKNOWN static.
NS-1 VNet Coverage: virtual_networks list non-empty → plan actively protecting VNets → PASS;
                    empty list → plan exists but not protecting anything → FAIL.
NS-2 Private Link: Control-plane resource only; no network exposure or private endpoint → UNKNOWN static.
NS-2 Disable Public: Control-plane only; no public/private network toggle applies → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_ddos_plans(client: NetworkManagementClient, resource_group: str | None, plan_name: str | None) -> list:
    if resource_group and plan_name:
        return [client.ddos_protection_plans.get(resource_group, plan_name)]
    elif resource_group:
        return list(client.ddos_protection_plans.list_by_resource_group(resource_group))
    else:
        return list(client.ddos_protection_plans.list())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {
        "resource": plan_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DDoS Protection is a control-plane grouping resource that enables DDoS Standard protection "
            "for VNets. NSG rules apply to the subnets and NICs within the protected VNets — not to the DDoS "
            "Protection Plan resource itself. NSG assignment is not readable via the DDoS plan ARM resource."
        ),
        "expected_value": "N/A — NSG applies to protected VNet subnets, not to the DDoS plan resource",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview",
    }


def check_ns1_vnet_coverage(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    base = {
        "control_id": "NS-1",
        "feature": "Virtual Network Integration — DDoS Plan VNet Coverage",
        "expected_value": "virtual_networks list non-empty (at least one VNet actively protected by this plan)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        plans = _get_ddos_plans(client, resource_group, plan_name)
        if not plans:
            return {**base, "resource": plan_name or "none", "status": "PASS",
                    "actual_value": "No DDoS Protection Plan instances found in scope"}
        first_pass = None
        for plan in plans:
            vnets = getattr(plan, "virtual_networks", None) or []
            vnet_count = len(vnets)
            if vnet_count > 0:
                r = {**base, "resource": plan.name, "status": "PASS",
                     "actual_value": f"{vnet_count} VNet(s) actively protected by this DDoS plan"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": plan.name, "status": "FAIL",
                        "actual_value": "virtual_networks=[] — DDoS Protection Plan exists but has no VNets associated; plan is not protecting any network; subscription is paying for unused protection"}
        return first_pass
    except Exception as e:
        return {**base, "resource": plan_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {
        "resource": plan_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DDoS Protection Plan is a control-plane resource that stores protection configuration — "
            "it has no network exposure and does not support Private Link. "
            "The protection itself is applied at the VNet level via plan association."
        ),
        "expected_value": "N/A — control-plane resource; no network exposure; Private Link not applicable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview",
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, plan_name: str | None) -> dict:
    return {
        "resource": plan_name or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DDoS Protection Plan is an ARM control-plane resource with no public network exposure. "
            "There is no public/private network access toggle — the resource is purely a policy grouping object "
            "accessible only via ARM management API with Entra ID authentication."
        ),
        "expected_value": "N/A — control-plane only; no public network access concept applicable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview",
    }
