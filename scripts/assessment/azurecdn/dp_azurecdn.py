"""
Data Protection checks for Azure CDN / Azure Front Door (MCSB v3).
CDN is a transit/edge service — DP controls are mostly static PASS or UNKNOWN.
"""


def check_dp3_tls_transit(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit — TLS on CDN/AFD Endpoints",
        "status": "UNKNOWN",
        "actual_value": "Azure CDN/AFD endpoints support HTTPS with TLS 1.2 minimum. Per-endpoint min TLS version is set in the custom domain HTTPS settings (minimumTlsVersion). Enumerate via CdnManagementClient.custom_domains or afd_custom_domains.",
        "expected_value": "minimumTlsVersion == 'TLS12' on all custom domains",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cdn/cdn-custom-ssl",
    }


def check_dp4_platform_keys(credential, subscription_id, resource_group, profile_name):
    return {
        "resource": profile_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure CDN/AFD is a transit/caching service. Cached content at edge nodes is encrypted at rest with Microsoft-managed keys.",
        "expected_value": "Microsoft-managed platform key encryption (default for edge cache)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }
