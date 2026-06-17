"""
Data Protection checks for Azure Cache for Redis.

DP-2: Data Leakage/Loss Prevention (proxy: publicNetworkAccess)
DP-3: Data in Transit Encryption (TLS enforcement — enableNonSslPort + minimumTlsVersion)
DP-4: Data at Rest Encryption Using Platform Keys (microsoft_managed; C0/C1 exception)
DP-5: Data at Rest Encryption Using CMK (UNKNOWN — Enterprise tier only, GA Feb 2024)
DP-6: Key Management in Azure Key Vault (UNKNOWN — Enterprise tier only)
DP-7: Certificate Management in Azure Key Vault (UNKNOWN — Microsoft-managed TLS only)
"""
from azure.mgmt.redis import RedisManagementClient


def _rg_from_id(resource_id: str) -> str:
    return resource_id.split("/resourceGroups/")[1].split("/")[0]


def _get_caches(client: RedisManagementClient, resource_group: str | None, redis_name: str | None):
    if resource_group and redis_name:
        return [client.redis.get(resource_group, redis_name)]
    elif resource_group:
        return list(client.redis.list_by_resource_group(resource_group))
    else:
        return list(client.redis.list_by_subscription())


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "expected_value": "publicNetworkAccess: Disabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-private-link",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            pna = getattr(cache.properties, "public_network_access", None) if cache.properties else None
            if pna == "Disabled":
                r = {**base, "resource": cache.name, "status": "PASS",
                     "actual_value": "publicNetworkAccess: Disabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL",
                        "actual_value": f"publicNetworkAccess: {pna or 'Enabled'} — data exfiltration risk via public endpoint"}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "expected_value": "enableNonSslPort: False, minimumTlsVersion: 1.2",
        "evidence_url": "https://docs.microsoft.com/azure/azure-cache-for-redis/cache-configure#access-ports",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            non_ssl = getattr(cache.properties, "enable_non_ssl_port", None) if cache.properties else None
            min_tls = getattr(cache.properties, "minimum_tls_version", None) if cache.properties else None
            actual = f"enableNonSslPort: {non_ssl}, minimumTlsVersion: {min_tls}"
            if non_ssl is False and min_tls in ("1.2", "1.3"):
                r = {**base, "resource": cache.name, "status": "PASS", "actual_value": actual}
                first_pass = first_pass or r
            else:
                return {**base, "resource": cache.name, "status": "FAIL", "actual_value": actual}
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "expected_value": "Microsoft-managed disk encryption enabled",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-encryption",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "PASS", "actual_value": "No Redis caches found in scope"}

        first_pass = None
        for cache in caches:
            sku = cache.properties.sku if cache.properties else None
            sku_name = sku.name if sku else None
            capacity = sku.capacity if sku else None
            if sku_name in ("Basic", "Standard") and capacity in (0, 1):
                return {**base, "resource": cache.name, "status": "UNKNOWN",
                        "actual_value": f"C{capacity} SKU — disk encryption not available per Microsoft docs"}
            r = {**base, "resource": cache.name, "status": "PASS",
                 "actual_value": f"Platform-managed key encryption enabled by default (SKU: {sku_name} C{capacity})"}
            first_pass = first_pass or r
        return first_pass
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "expected_value": "Enterprise tier with CMK encryption configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-encryption",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "UNKNOWN", "actual_value": "No Redis caches found in scope"}

        for cache in caches:
            sku = cache.properties.sku.name if cache.properties and cache.properties.sku else None
            return {**base, "resource": cache.name, "status": "UNKNOWN",
                    "actual_value": f"CMK not supported on {sku} tier; Enterprise tier required (Microsoft.Cache/redisEnterprise)"}
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN",
                "actual_value": "CMK requires Enterprise tier; not assessable via standard Redis SDK"}
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp6_key_management_kv(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    base = {
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "expected_value": "Enterprise tier with Key Vault CMK configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-encryption",
    }
    try:
        client = RedisManagementClient(credential, subscription_id)
        caches = _get_caches(client, resource_group, redis_name)
        if not caches:
            return {**base, "resource": "none", "status": "UNKNOWN", "actual_value": "No Redis caches found in scope"}

        for cache in caches:
            sku = cache.properties.sku.name if cache.properties and cache.properties.sku else None
            return {**base, "resource": cache.name, "status": "UNKNOWN",
                    "actual_value": f"Key Vault key management not supported on {sku} tier; Enterprise tier required"}
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN",
                "actual_value": "Key Vault key management requires Enterprise tier; not assessable via standard Redis SDK"}
    except Exception as e:
        return {**base, "resource": redis_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> dict:
    return {
        "resource": redis_name or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": (
            "Customer-managed TLS certificates via Key Vault not supported for Azure Cache for Redis; "
            "TLS certificates are Microsoft-managed"
        ),
        "expected_value": "Key Vault certificate integration configured",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-remove-tls-10-11",
    }
