"""
Data Protection checks for Azure Front Door (MCSB v3).

DP-3: True, True → PASS static (TLS/HTTPS enforced end-to-end by platform).
DP-4: True, True → PASS static (platform-managed keys for AFD metadata at rest).
DP-7: True, False → LIVE — KV cert check on frontend endpoints.
DP-1/2/5/6: UNKNOWN static (AFD is CDN proxy; no customer data store; no CMK/KV key mgmt).

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


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification",
        "status": "UNKNOWN",
        "actual_value": "AFD is an ingress/CDN/WAF proxy — no customer PII or business data stored in AFD resource. Purview/AIP data classification not applicable.",
        "expected_value": "N/A — CDN proxy; no persistent customer data in AFD resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": "AFD proxies traffic; no persistent customer data store. DLP not applicable to AFD resource.",
        "expected_value": "N/A — CDN proxy; no customer data store; DLP not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "PASS",
        "actual_value": (
            "TLS/HTTPS enforced end-to-end by AFD platform — feature_supported=True, enabled_by_default=True. "
            "Client-to-AFD: HTTPS with TLS 1.2+ minimum (configurable up to TLS 1.3). "
            "AFD-to-origin: HTTPS enforced; HTTP-only origins can be forced to HTTPS via routing rules. "
            "HTTPS redirect rules configurable per frontend endpoint. Platform-managed."
        ),
        "expected_value": "HTTPS/TLS 1.2+ enforced by platform (microsoft_managed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/end-to-end-tls",
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "PASS",
        "actual_value": (
            "AFD configuration metadata (routing rules, backend pools, caching settings, WAF policy references) "
            "is encrypted at rest with Microsoft-managed keys by default — feature_supported=True, enabled_by_default=True. "
            "No customer action required. Platform-enforced."
        ),
        "expected_value": "Platform-managed keys for AFD metadata at rest (microsoft_managed)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": "CMK not supported for AFD resource. AFD stores routing config and operational metadata only; no CMK encryption capability exposed. Feature=False in MCSB v3 baseline.",
        "expected_value": "N/A — CMK not supported on AFD resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": "AFD uses KV for TLS certificate storage (DP-7/IM-8), not for encryption key management. KV encryption key integration is not applicable to AFD. Feature=False in MCSB v3 baseline.",
        "expected_value": "N/A — KV key management not applicable to AFD; KV used for certs only (see DP-7)",
        "evidence_url": _EVIDENCE,
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    base = {
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "expected_value": "HTTPS enabled on frontend endpoints; certificates from AzureKeyVault source preferred",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-custom-domain-https",
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
            for ep in endpoints:
                cfg = getattr(ep, "custom_https_configuration", None)
                if cfg is None:
                    return {**base, "resource": fd.name, "status": "FAIL",
                            "actual_value": f"Frontend endpoint '{ep.name}': HTTPS not configured — no custom_https_configuration"}
                src = getattr(cfg, "certificate_source", None)
                if src == "AzureKeyVault":
                    kv_params = getattr(cfg, "key_vault_certificate_source_parameters", None)
                    r = {**base, "resource": fd.name, "status": "PASS",
                         "actual_value": f"Endpoint '{ep.name}': certificate_source=AzureKeyVault; KV ref present={kv_params is not None}"}
                    first_pass = first_pass or r
                elif src == "FrontDoor":
                    r = {**base, "resource": fd.name, "status": "PASS",
                         "actual_value": f"Endpoint '{ep.name}': certificate_source=FrontDoor (AFD-managed cert; auto-rotation enabled)"}
                    first_pass = first_pass or r
                else:
                    return {**base, "resource": fd.name, "status": "FAIL",
                            "actual_value": f"Endpoint '{ep.name}': HTTPS not enabled or unknown certificate_source={src!r}"}
            if first_pass is None and not endpoints:
                first_pass = {**base, "resource": fd.name, "status": "PASS",
                              "actual_value": "No frontend endpoints found on this Front Door instance"}
        return first_pass
    except Exception as e:
        return {**base, "resource": front_door_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
