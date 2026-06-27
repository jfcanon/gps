"""IM checks for Azure Virtual WAN (MCSB v3). IM-8 KV secrets → UNKNOWN."""


def check_im8_keyvault_secrets(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-8", "feature": "Restrict the Exposure of Credentials and Secrets",
            "status": "UNKNOWN",
            "actual_value": "Virtual WAN itself does not store credentials in ARM. VPN pre-shared keys are stored in VPN gateway resources (not the WAN resource). Use Azure-managed key negotiation (IKEv2) or reference PSK via Key Vault in automation scripts.",
            "expected_value": "VPN PSKs generated per-session or stored in Key Vault by IaC tooling",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/security-baseline"}
