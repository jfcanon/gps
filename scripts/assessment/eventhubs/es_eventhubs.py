"""
Endpoint Security checks for Azure Event Hubs (MCSB v3).
PaaS messaging service — no customer compute. All UNKNOWN.
"""


def _paas_na(namespace_name, control_id, feature, url):
    return {
        "resource": namespace_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": "PaaS messaging service — no customer-accessible compute layer; endpoint security agents not applicable to Event Hubs infrastructure",
        "expected_value": "N/A",
        "evidence_url": url,
    }


def check_es1_edr(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "ES-1", "EDR Solution",
                    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/endpoint-detection-response")


def check_es2_antimalware(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "ES-2", "Anti-Malware Solution",
                    "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")


def check_es3_antimalware_health(credential, subscription_id, resource_group, namespace_name):
    return _paas_na(namespace_name, "ES-3", "Anti-Malware Solution Health Monitoring",
                    "https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware")
