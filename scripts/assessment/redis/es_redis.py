"""
Endpoint Security checks for Azure Cache for Redis.

ES-1, ES-2, ES-3: All return UNKNOWN/N-A — Redis is fully managed PaaS with no
customer-accessible OS or compute layer. EDR agents and anti-malware cannot be
deployed by customers. Microsoft manages the underlying OS internally.
"""
from typing import Callable


def _paas_not_applicable(redis_name: str | None, control_id: str, feature: str, evidence_url: str) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": control_id,
        "feature": feature,
        "status": "UNKNOWN",
        "actual_value": "PaaS service — no customer-accessible OS/compute layer; control not applicable",
        "expected_value": "N/A",
        "evidence_url": evidence_url,
    }


def check_es1_edr(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "ES-1", "EDR Solution",
        "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-overview"
    )


def check_es2_antimalware(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "ES-2", "Anti-Malware Solution",
        "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-overview"
    )


def check_es3_antimalware_health(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return _paas_not_applicable(
        redis_name, "ES-3", "Anti-Malware Solution Health Monitoring",
        "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-overview"
    )
