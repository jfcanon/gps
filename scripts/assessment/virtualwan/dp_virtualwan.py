"""
Data Protection checks for Azure Virtual WAN (MCSB v3).

DP-3: Static PASS (Virtual WAN encrypts IPsec VPN tunnels + VXLAN between hubs).
DP-6: UNKNOWN (VirtualWAN does not hold CMK configuration directly).

Read-only. Zero ARM writes.
"""


def check_dp3_tls_transit(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-3", "feature": "Encrypt Data in Transit",
            "status": "PASS",
            "actual_value": "Azure Virtual WAN encrypts all branch-to-hub VPN connections with IPsec/IKEv2 (AES-256). Hub-to-hub traffic uses encrypted VXLAN. ExpressRoute traffic is not encrypted by default — use MACsec or IPsec over ER.",
            "expected_value": "IPsec encryption enabled (default for VPN connections)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/security-baseline#dp-3-encrypt-sensitive-data-in-transit"}


def check_dp6_key_mgmt(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-6", "feature": "Manage Cryptographic Keys using Key Management Service",
            "status": "UNKNOWN",
            "actual_value": "Virtual WAN does not hold CMK-encrypted data directly. IPsec key management uses IKEv2 with Azure-managed keys. ExpressRoute MACsec can use customer-managed keys but is configured on the circuit, not the WAN resource.",
            "expected_value": "N/A — Azure manages IPsec session keys; ExpressRoute MACsec CMK is on circuit resource",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-wan/security-baseline"}
