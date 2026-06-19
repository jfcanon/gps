"""
Network Security checks for Azure Front Door (MCSB v3).

NS-1 NSG: False, Not Applicable — PaaS global anycast CDN; no NSG applicable.
NS-1 VNet: False, Not Applicable — AFD Classic no VNet integration; Premium supports PL to origins not AFD itself.
NS-2 Private Link: False, Not Applicable — AFD has no private endpoint.
NS-2 WAF/IP filtering: True, True — WAF policy link on frontend endpoints — LIVE check.

Read-only. Zero ARM writes.
"""
from azure.mgmt.frontdoor import FrontDoorManagementClient

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview"


def _get_front_doors(client: FrontDoorManagementClient, resource_group: str | None, front_door_name: str | None) -> list:
    if resource_group and front_door_name:
        return [client.front_doors.get(resource_group, front_door_name)]
    elif resource_group:
        return list(client.front_doors.list_by_resource_group(resource_group))
    else:
        return list(client.front_doors.list())


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Front Door is a global anycast PaaS CDN/WAF service. "
            "It has no VNet NIC and cannot be placed in a subnet — there is no surface to attach an NSG. "
            "NSGs apply to backend origin subnets routing traffic after AFD. Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — PaaS global CDN; NSG applies to backend origin subnets, not AFD resource",
        "evidence_url": _EVIDENCE,
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "UNKNOWN",
        "actual_value": (
            "AFD Classic has no VNet integration. "
            "AFD Standard/Premium supports Private Link origins (AFD initiates PE to backend origins), "
            "but the AFD resource itself does not join a VNet — it remains a global PaaS endpoint. "
            "Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — AFD does not join a VNet; Private Link origins are backend concern",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/private-link",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "AFD Classic has no private endpoint. "
            "AFD Standard/Premium can send traffic TO origins via Private Link, but the AFD resource itself "
            "does not expose a private endpoint for clients. Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — AFD resource has no private endpoint; Private Link applies to origin backends",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/private-link",
    }


def check_ns2_waf_policy(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    base = {
        "control_id": "NS-2",
        "feature": "Native IP Filtering via WAF Policy",
        "expected_value": "WAF policy linked to at least one frontend endpoint (IP filtering + managed rules)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/web-application-firewall",
    }
    try:
        client = FrontDoorManagementClient(credential, subscription_id)
        front_doors = _get_front_doors(client, resource_group, front_door_name)
        if not front_doors:
            return {**base, "resource": front_door_name or "none", "status": "PASS",
                    "actual_value": "No Front Door instances found in scope"}
        first_pass = None
        for fd in front_doors:
            endpoints = getattr(fd, "frontend_endpoints", None) or []
            waf_linked = [
                ep.name for ep in endpoints
                if getattr(ep, "web_application_firewall_policy_link", None)
            ]
            if waf_linked:
                r = {**base, "resource": fd.name, "status": "PASS",
                     "actual_value": f"WAF policy linked on endpoint(s): {waf_linked}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fd.name, "status": "FAIL",
                        "actual_value": (
                            f"No WAF policy linked on any of {len(endpoints)} frontend endpoint(s). "
                            "IP filtering and managed rule protection not active. "
                            "Link a WAF policy in Prevention mode to all frontend endpoints."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": front_door_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
