"""
Network Security checks for Azure Firewall Manager (MCSB v3).

AFM is a management-plane service over Firewall Policies (ARM resources).
All NS controls N/A: no NSG, no VNet integration, no Private Link, no public toggle.
All UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_ns1_nsg(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "NS-1",
        "feature": "Network Security Group Support",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall Manager manages Firewall Policies — ARM configuration objects for Azure Firewall. "
            "NSG does not apply to the Firewall Policy resource itself; NSGs are applied to subnets within "
            "the VNets protected by Azure Firewall."
        ),
        "expected_value": "N/A — management-plane policy resource; NSG applies to protected VNet subnets",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview",
    }


def check_ns1_vnet(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "NS-1",
        "feature": "Virtual Network Integration",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall Manager / Firewall Policy is an ARM configuration resource; it does not "
            "integrate into a VNet. The Azure Firewall instances that consume this policy are deployed "
            "into VNets — VNet integration applies to those, not to the policy object."
        ),
        "expected_value": "N/A — policy resource; VNet integration applies to Azure Firewall instances",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview",
    }


def check_ns2_private_link(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "NS-2",
        "feature": "Azure Private Link",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall Manager is an ARM management-plane service; Firewall Policy has no data-plane "
            "endpoint that could be exposed via Private Link. All access is via ARM API with Entra ID."
        ),
        "expected_value": "N/A — ARM management-plane; Private Link not applicable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview",
    }


def check_ns2_disable_public(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "NS-2",
        "feature": "Disable Public Network Access",
        "status": "UNKNOWN",
        "actual_value": (
            "Firewall Policy is an ARM configuration resource with no public network access toggle. "
            "All management access is via ARM with Entra ID authentication. "
            "There is no public/private network mode switch for Firewall Policy objects."
        ),
        "expected_value": "N/A — ARM management-plane only; no public network access toggle",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall-manager/overview",
    }
