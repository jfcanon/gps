"""
Data Protection checks for Azure VPN Gateway (MCSB v3).

DP-3: True, True, microsoft_managed → PASS static.
    IPsec/IKEv2 encryption is the core function of VPN GW — always enabled.

DP-4: False, Not Applicable → UNKNOWN static (still_not_applicable).
    feature_supported=False in baseline; VPN GW stores no persistent customer data at rest.

DP-1/2/5/6/7: UNKNOWN static (still_not_applicable).
    Routing/tunnel service; no customer data store; PSK not KV-backed; IKE certs not in KV.

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpngateways"


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification",
        "status": "UNKNOWN",
        "actual_value": "VPN GW is a routing/tunneling service — no persistent customer PII or business data stored in VPN GW resource. Microsoft Purview data classification not applicable.",
        "expected_value": "N/A — tunnel routing service; no persistent customer data in VPN GW resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": "VPN GW routes encrypted IPsec tunnels; no persistent customer data store. DLP solution not applicable to VPN GW resource.",
        "expected_value": "N/A — tunnel routing; no customer data store; DLP not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "PASS",
        "actual_value": (
            "IPsec/IKEv2 encryption is the core function of VPN Gateway — all tunnel traffic always encrypted. "
            "feature_supported=True, enabled_by_default=True, responsibility=microsoft_managed. "
            "S2S VPN: AES-256/GCM-AES-256 IKEv2 by default (custom IPsec policy configurable). "
            "P2S VPN: OpenVPN (TLS 1.2+) or IKEv2. Encryption cannot be disabled — inherent to protocol."
        ),
        "expected_value": "IPsec/IKEv2 encryption always enabled (microsoft_managed — no customer action required)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-compliance-crypto",
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "UNKNOWN",
        "actual_value": (
            "feature_supported=False in MCSB v3 baseline. "
            "VPN GW is a routing/tunneling service — no persistent customer data store at rest. "
            "PSK (pre-shared key) is stored in the VPN GW resource metadata but is not "
            "customer data in the DP-4 sense (no platform-key encryption toggle exposed to customer)."
        ),
        "expected_value": "N/A — feature_supported=False in baseline; no persistent customer data at rest",
        "evidence_url": _EVIDENCE,
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": "CMK not applicable to VPN GW. VPN GW stores no customer data requiring CMK encryption. Not Applicable in MCSB v3 baseline.",
        "expected_value": "N/A — CMK not supported; no customer data at rest in VPN GW resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": (
            "PSK stored directly in VPN GW resource — no Azure Key Vault key management integration. "
            "feature_supported=False in MCSB v3 baseline. "
            "IKEv2/P2S certificates are uploaded directly to VPN GW — not managed via KV key management."
        ),
        "expected_value": "N/A — KV key management not applicable; PSK stored directly in resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, gateway_name: str | None) -> dict:
    return {
        "resource": gateway_name or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": (
            "IKE/P2S certificates are uploaded to VPN GW directly — not managed via Azure Key Vault. "
            "feature_supported=False in MCSB v3 baseline. "
            "No KV certificate integration exists for VPN GW tunnel authentication certificates."
        ),
        "expected_value": "N/A — KV cert management not supported; certs uploaded directly to VPN GW",
        "evidence_url": _EVIDENCE,
    }
