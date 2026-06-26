"""
Identity Management checks for Azure CDN / Azure Front Door (MCSB v3).
CDN/AFD management plane uses ARM RBAC. Data plane is edge-cached content — no identity concept.
"""


def check_im3_managed_identities(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "status": "UNKNOWN",
        "actual_value": "AFD Standard/Premium supports managed identity for Key Vault certificate retrieval. Classic CDN does not. Check profile.identity via CdnManagementClient.profiles.get().",
        "expected_value": "profile.identity.type assigned for AFD profiles using Key Vault certs",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/managed-identity",
    }


def check_im7_conditional_access(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Azure CDN/AFD is a transit service — no authentication challenge issued to end users. Conditional Access applies to the origin application, not the CDN layer.",
        "expected_value": "N/A at CDN layer — enforce Conditional Access at origin application",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cdn/security-baseline",
    }
