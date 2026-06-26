"""Privileged Access checks for Azure CDN / AFD (MCSB v3). All UNKNOWN — ARM RBAC level."""


def check_pa8_customer_lockbox(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Azure CDN/AFD Customer Lockbox support depends on subscription-level enablement. Not readable per profile via ARM.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }
