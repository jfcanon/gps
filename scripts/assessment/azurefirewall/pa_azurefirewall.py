"""
Privileged Access checks for Azure Firewall (MCSB v3).

PA-1: No local admin concept — ARM RBAC controls all management operations → UNKNOWN.
PA-7: No data plane; ARM RBAC is the only access model — no data-plane RBAC to configure → UNKNOWN.
PA-8: Azure Firewall not in Customer Lockbox supported services GA list → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PA-1",
        "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall is a fully managed PaaS service with no local admin account concept. "
            "All administrative operations are performed via ARM using Entra ID identities. "
            "Privileged access is controlled by Azure RBAC roles (Network Contributor, Owner, etc.) at the subscription/resource group level."
        ),
        "expected_value": "N/A — no local admin; ARM RBAC with Entra ID is the only access model",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pa-1-separate-and-limit-highly-privilegedadministrative-users",
    }


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — Azure RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall has no customer-accessible data plane requiring RBAC. "
            "Network traffic routing through the firewall is not subject to user identity-based access control. "
            "Management plane access is controlled via ARM RBAC (control plane only)."
        ),
        "expected_value": "N/A — no data plane RBAC; management via ARM RBAC only",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/firewall/security-baseline#pa-7-follow-just-enough-administration-least-privilege-principle",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, firewall_name: str | None) -> dict:
    return {
        "resource": firewall_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure Firewall is not listed in the Customer Lockbox supported services GA list. "
            "Microsoft support access to firewall configuration is governed by standard Microsoft support policies. "
            "Lockbox enablement is at subscription level and does not cover Azure Firewall specifically."
        ),
        "expected_value": "N/A — Azure Firewall not in Customer Lockbox supported services list",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }
