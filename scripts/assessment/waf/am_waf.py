"""
Asset Management checks for Azure WAF Policy (MCSB v3).

AM-2: LIVE-DIRECT — policy.tags proxy for Azure Policy governance.
AM-5: UNKNOWN static — PaaS; no compute; AAC targets VMs/Arc servers.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/web-application-firewall/shared/waf-azure-policy"


def _get_waf_policies(client, resource_group, policy_name):
    if resource_group and policy_name:
        return [client.web_application_firewall_policies.get(resource_group, policy_name)]
    elif resource_group:
        return list(client.web_application_firewall_policies.list(resource_group))
    else:
        return list(client.web_application_firewall_policies.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Azure Policy Support (tags proxy)",
        "expected_value": "WAF Policy has non-empty tags",
        "evidence_url": _EVIDENCE,
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            tags = getattr(policy, 'tags', None) or {}
            if tags:
                r = {**base, "resource": policy.name, "status": "PASS",
                     "actual_value": f"Tags present: {list(tags.keys())}"}
            else:
                return {**base, "resource": policy.name, "status": "FAIL",
                        "actual_value": "No tags on WAF Policy; tags required for Azure Policy governance and cost management"}
            first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No policies found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "AM-5",
        "feature": "Microsoft Defender for Cloud — Adaptive Application Controls",
        "status": "UNKNOWN",
        "actual_value": "Adaptive Application Controls targets VMs and Azure Arc-enabled servers. WAF Policy is a PaaS configuration resource with no compute substrate. not_applicable.",
        "expected_value": "N/A — PaaS; no compute; AAC not applicable",
        "evidence_url": _EVIDENCE,
    }
