"""Phase 57 Step 3 — Add Q2 new supplement rows.

Q2 WebSearch audit (June 2026) found 2 new GA features for NS domain services:

1. virtualnetwork: Private Subnet Default (defaultOutboundAccess=false) GA March 31, 2026
   — New VNet subnets default to private (no outbound internet access unless explicit method configured).
   → NS-2-SUPPLEMENT

2. virtualwan: Forced Tunneling for Virtual WAN Secure Hubs — GA 2025
   — Route internet traffic through NVA/SASE in spoke VNet for centralized inspection.
   → NS-7-SUPPLEMENT-VIRTUALWAN

Pattern mirrors scripts/phase56_supplement_rows.py — idempotent (skip if ID already present).
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

SUPPLEMENTS = [
    {
        "path": "data/outputs/ns/virtualnetwork.final.csv",
        "row": {
            "asb_control_id":                      "NS-2-SUPPLEMENT",
            "feature_name":                        "Private Subnet Default — defaultOutboundAccess=false (March 2026)",
            "feature_supported_original":          "False",
            "feature_enabled_by_default_original": "False",
            "status_2025":                         "gap",
            "verdict_2025":                        "now_applicable_native",
            "azure_api_property":                  "subnets[].properties.defaultOutboundAccess",
            "script_module":                       "",
            "script_function":                     "",
            "notes":                               (
                "v2 gap: Azure VNet subnets created after March 31 2026 default to private "
                "(defaultOutboundAccess=false), blocking outbound internet access unless an explicit "
                "outbound method is configured (NAT Gateway, Azure Firewall, or Load Balancer with outbound rules). "
                "This enforces NS-2 private network access controls at the subnet level by default. "
                "Existing subnets and VNets created before March 31 2026 retain prior behavior. "
                "Customer action: configure explicit outbound method if internet egress required. "
                "Source: https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access | "
                "Q2-D WebSearch June 2026 confirmed GA March 31 2026."
            ),
            "service":                             "virtualnetwork",
            "severity":                            "High",
            "blast_radius":                        "Wide",
            "risk_rank":                           "5",
        },
    },
    {
        "path": "data/outputs/ns/virtualwan.final.csv",
        "row": {
            "asb_control_id":                      "NS-7-SUPPLEMENT-VIRTUALWAN",
            "feature_name":                        "Forced Tunneling for Virtual WAN Secure Hubs via NVA/SASE",
            "feature_supported_original":          "False",
            "feature_enabled_by_default_original": "False",
            "status_2025":                         "gap",
            "verdict_2025":                        "conditional",
            "azure_api_property":                  "properties.routingConfiguration.propagatedRouteTables",
            "script_module":                       "",
            "script_function":                     "",
            "notes":                               (
                "v2 gap: Virtual WAN Secure Hub now supports forced tunneling — routes internet-bound "
                "traffic from spoke VNets through a Network Virtual Appliance (NVA) or SASE solution "
                "deployed in a spoke VNet connected to Virtual WAN. Enables centralized internet traffic "
                "inspection (NS-7: centralized network security management) for all connected workloads. "
                "Conditional: requires Secure Hub deployment with Azure Firewall or NVA; routing "
                "configuration must explicitly set next-hop to NVA private IP for 0.0.0.0/0 route. "
                "Source: https://learn.microsoft.com/en-us/azure/virtual-wan/whats-new | "
                "Q2-D WebSearch June 2026 confirmed GA."
            ),
            "service":                             "virtualwan",
            "severity":                            "High",
            "blast_radius":                        "Wide",
            "risk_rank":                           "5",
        },
    },
]


def add_supplement(supplement: dict) -> str:
    csv_path = pathlib.Path(supplement["path"])
    if not csv_path.exists():
        return "FILE_NOT_FOUND"

    rows = list(csv.DictReader(open(csv_path)))
    new_id = supplement["row"]["asb_control_id"]

    if any(r["asb_control_id"] == new_id for r in rows):
        return "ALREADY_EXISTS"

    rows.append(supplement["row"])

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return "ADDED"


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 57 Step 3 — Q2 supplement rows")
    print("=" * 60)

    for s in SUPPLEMENTS:
        result = add_supplement(s)
        slug = pathlib.Path(s["path"]).stem.replace(".final", "")
        ctrl_id = s["row"]["asb_control_id"]
        feat = s["row"]["feature_name"][:55]
        print(f"  [{result}] {slug:<22} {ctrl_id:<30} {feat}")

    print()
    print("Done.")
