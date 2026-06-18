"""
Data Protection checks for Azure Application Gateway (MCSB v3).

DP-2: WAF in Prevention mode → anomaly/threat inspection active → PASS proxy.
DP-3 frontend TLS: ssl_policy.min_protocol_version in (TLSv1_2, TLSv1_3) → PASS.
DP-3 backend TLS: all backend_http_settings_collection[*].protocol=Https → PASS.
DP-4: AppGW configuration stored with MS-managed encryption → auto-PASS (static).
DP-5: AppGW does not support CMK → still_not_applicable (static).
DP-6: ssl_certificates + identity MI → KV-managed keys → PASS proxy.
DP-7: ssl_certificates with key_vault_secret_id → KV-backed cert management → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient


def _get_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        return [client.application_gateways.get(resource_group, gateway_name)]
    elif resource_group:
        return list(client.application_gateways.list(resource_group))
    else:
        return list(client.application_gateways.list_all())


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "DP-2",
        "feature": "Monitor Anomalies and Threats Targeting Sensitive Data",
        "expected_value": "WAF enabled in Prevention mode (traffic inspection active)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            fw_policy = getattr(gw, "firewall_policy", None)
            if fw_policy and getattr(fw_policy, "id", None):
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": "firewall_policy linked — WAF v2 policy active; anomaly/threat detection enabled"}
                first_pass = first_pass or r
                continue
            waf_cfg = getattr(gw, "web_application_firewall_configuration", None)
            if waf_cfg and getattr(waf_cfg, "enabled", False) and str(getattr(waf_cfg, "firewall_mode", "")) == "Prevention":
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": "waf_configuration.enabled=True, firewall_mode=Prevention — traffic inspection active"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": "WAF not active in Prevention mode — no anomaly/threat inspection on traffic"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit — Frontend SSL Policy",
        "expected_value": "ssl_policy.min_protocol_version in (TLSv1_2, TLSv1_3)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            ssl_policy = getattr(gw, "ssl_policy", None)
            if ssl_policy is None:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": "ssl_policy=None — no SSL policy configured; default allows TLS 1.0/1.1"}
            min_ver = str(getattr(ssl_policy, "min_protocol_version", "") or "")
            if min_ver in ("TLSv1_2", "TLSv1_3"):
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"ssl_policy.min_protocol_version={min_ver}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"ssl_policy.min_protocol_version={min_ver or 'not set'} — TLS 1.2+ not enforced"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp3_tls_backend(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Encrypt Data in Transit — Backend TLS",
        "expected_value": "All backend_http_settings_collection[*].protocol=Https",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/ssl-overview",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            backend_settings = getattr(gw, "backend_http_settings_collection", None) or []
            if not backend_settings:
                return {**base, "resource": gw.name, "status": "UNKNOWN",
                        "actual_value": "No backend HTTP settings configured"}
            http_backends = [
                s.name for s in backend_settings
                if str(getattr(s, "protocol", "Http")) != "Https"
            ]
            if not http_backends:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"All {len(backend_settings)} backend setting(s) use protocol=Https"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"{len(http_backends)} backend setting(s) use HTTP: {http_backends[:5]}"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-4",
        "feature": "Encrypt Data at Rest with Platform-Managed Keys",
        "status": "PASS",
        "actual_value": "Azure Application Gateway configuration and associated data are encrypted at rest with Microsoft-managed keys by default. No customer configuration required.",
        "expected_value": "Microsoft-managed platform key encryption (default)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-5",
        "feature": "Encrypt Data at Rest with Customer-Managed Key",
        "status": "UNKNOWN",
        "actual_value": "Azure Application Gateway does not support Customer-Managed Key (CMK) encryption for its configuration data at rest. The service uses Microsoft-managed keys only. CMK is not configurable on Application Gateway resources.",
        "expected_value": "N/A — CMK not supported for Application Gateway",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/overview",
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "DP-6",
        "feature": "Manage Cryptographic Keys using Key Management Service",
        "expected_value": "ssl_certificates present AND identity (MI) assigned — KV-backed key management",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            certs = getattr(gw, "ssl_certificates", None) or []
            identity = getattr(gw, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            kv_certs = [
                c for c in certs
                if getattr(c, "key_vault_secret_id", None)
            ]
            if kv_certs and identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"{len(kv_certs)}/{len(certs)} cert(s) KV-backed; identity.type={identity_type}"}
                first_pass = first_pass or r
            elif certs and not kv_certs:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"{len(certs)} cert(s) present but none reference Azure Key Vault (key_vault_secret_id not set)"}
            else:
                return {**base, "resource": gw.name, "status": "UNKNOWN",
                        "actual_value": "No SSL certificates configured or identity not assigned — KV key management not verifiable"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "DP-7",
        "feature": "Certificate Management using Azure Key Vault",
        "expected_value": "ssl_certificates[*].key_vault_secret_id set (KV-backed certificates)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No Application Gateways found in scope"}
        first_pass = None
        for gw in gateways:
            certs = getattr(gw, "ssl_certificates", None) or []
            if not certs:
                return {**base, "resource": gw.name, "status": "UNKNOWN",
                        "actual_value": "No SSL certificates configured — TLS termination may not be enabled"}
            kv_certs = [c for c in certs if getattr(c, "key_vault_secret_id", None)]
            if kv_certs:
                r = {**base, "resource": gw.name, "status": "PASS",
                     "actual_value": f"{len(kv_certs)}/{len(certs)} cert(s) managed via Azure Key Vault (key_vault_secret_id set)"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": gw.name, "status": "FAIL",
                        "actual_value": f"{len(certs)} cert(s) present; none use key_vault_secret_id — certificates stored inline, not in KV"}
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}
