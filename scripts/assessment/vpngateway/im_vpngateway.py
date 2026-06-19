"""
Identity Management checks for Azure VPN Gateway (MCSB v3).

IM-1 AAD: True, False, customer → LIVE — check vpn_client_configuration.vpn_auth_types for 'AAD'.
    S2S-only gateways (vpn_client_configuration is None) → UNKNOWN (P2S not configured; AAD N/A).

IM-1 local auth: Not Applicable → UNKNOWN static.
IM-3 MI/SP: False, N/A → UNKNOWN static.
IM-7 CA: True, False → UNKNOWN static (CA in Entra ID; not checkable via read-only ARM).
IM-8: False, N/A → UNKNOWN static.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"


def _get_vpn_gateways(client: NetworkManagementClient, resource_group: str | None, gateway_name: str | None) -> list:
    if resource_group and gateway_name:
        gw = client.virtual_network_gateways.get(resource_group, gateway_name)
        return [gw] if getattr(gw, "gateway_type", "") == "Vpn" else []
    elif resource_group:
        return [g for g in client.virtual_network_gateways.list(resource_group)
                if getattr(g, "gateway_type", "") == "Vpn"]
    else:
        raise ValueError("--resource-group required: VirtualNetworkGateways have no subscription-wide list()")


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-1",
        "feature": "Disable Local Authentication Methods",
        "status": "UNKNOWN",
        "actual_value": (
            "No local auth concept exists on VPN GW. "
            "S2S VPN uses IKE PSK or certificates (not local user accounts). "
            "P2S VPN uses AAD (Entra ID), certificates, or RADIUS — not local credentials. "
            "Management plane enforces Entra ID via ARM. Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no local auth concept on VPN GW; data plane uses PSK/cert/AAD",
        "evidence_url": _EVIDENCE,
    }


def check_im1_aad_auth_required(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Azure AD Authentication Required for Data Plane Access",
        "expected_value": "P2S VPN configured with AAD (Entra ID) auth — vpn_auth_types contains 'AAD'",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/vpn-gateway/openvpn-azure-ad-tenant",
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        gateways = _get_vpn_gateways(client, resource_group, gateway_name)
        if not gateways:
            return {**base, "resource": gateway_name or "none", "status": "PASS",
                    "actual_value": "No VPN Gateway instances found in scope"}
        first_pass = None
        for vng in gateways:
            cfg = getattr(vng, "vpn_client_configuration", None)
            if cfg is None:
                r = {**base, "resource": vng.name, "status": "UNKNOWN",
                     "actual_value": (
                         "vpn_client_configuration is None — S2S-only gateway; "
                         "P2S VPN not configured; AAD authentication not applicable to this gateway."
                     )}
                first_pass = first_pass or r
                continue
            auth_types = getattr(cfg, "vpn_auth_types", None) or []
            if "AAD" in auth_types:
                aad_tenant = getattr(cfg, "aad_tenant", None)
                r = {**base, "resource": vng.name, "status": "PASS",
                     "actual_value": f"P2S AAD auth enabled; vpn_auth_types={auth_types}; aad_tenant={aad_tenant}"}
                first_pass = first_pass or r
            elif auth_types:
                return {**base, "resource": vng.name, "status": "FAIL",
                        "actual_value": (
                            f"P2S configured with vpn_auth_types={auth_types} — Entra ID (AAD) auth not enabled. "
                            "P2S clients authenticate via certificate or RADIUS only. "
                            "Configure AAD auth in vpn_client_configuration for Entra ID-backed P2S connections."
                        )}
            else:
                r = {**base, "resource": vng.name, "status": "UNKNOWN",
                     "actual_value": "vpn_client_configuration present but vpn_auth_types is empty — P2S may not be fully configured"}
                first_pass = first_pass or r
        return first_pass
    except Exception as e:
        return {**base, "resource": gateway_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-3",
        "feature": "Managed Identities",
        "status": "UNKNOWN",
        "actual_value": (
            "VPN GW makes no outbound calls to Azure services requiring Managed Identity. "
            "feature_supported=False in MCSB v3 baseline. "
            "VPN GW does not integrate with Key Vault or other services via MI."
        ),
        "expected_value": "N/A — VPN GW has no outbound service calls requiring MI; feature_supported=False",
        "evidence_url": _EVIDENCE,
    }


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-3",
        "feature": "Service Principals",
        "status": "UNKNOWN",
        "actual_value": "VPN GW resource makes no outbound service calls requiring SP identity. Operators use SP/MI to manage VPN GW via ARM — that is PA-7 scope, not IM-3 data plane access.",
        "expected_value": "N/A — VPN GW resource has no SP data plane concept; operator SP usage is PA-7 scope",
        "evidence_url": _EVIDENCE,
    }


def check_im7_conditional_access(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-7",
        "feature": "Conditional Access for Data Plane",
        "status": "UNKNOWN",
        "actual_value": (
            "Conditional Access for P2S VPN with AAD is supported at Entra ID level — "
            "CA policies are stored and enforced in Entra ID, not in VPN GW ARM resource. "
            "No per-gateway CA property checkable via read-only ARM API. "
            "feature_supported=True, enabled_by_default=False (customer must configure in Entra ID). "
            "If aad_tenant is set on vpn_client_configuration, CA policies CAN be applied to P2S clients "
            "but enforcement is not verifiable without Microsoft Graph API scope."
        ),
        "expected_value": "CA configured in Entra ID for P2S+AAD VPN clients — not verifiable via ARM API alone",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/vpn-gateway/openvpn-azure-ad-mfa",
    }


def check_im8_keyvault_secrets(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "IM-8",
        "feature": "Service Credential and Secrets Support Integration in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": (
            "PSK (pre-shared key) is stored directly in the VPN GW resource — not in Azure Key Vault. "
            "feature_supported=False in MCSB v3 baseline. "
            "No KV-backed secret storage integration exists for VPN GW credentials or PSKs."
        ),
        "expected_value": "N/A — PSK stored in VPN GW resource; no KV integration; feature_supported=False",
        "evidence_url": _EVIDENCE,
    }
