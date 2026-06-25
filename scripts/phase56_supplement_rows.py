"""Phase 56 Step 3 — Add Q2 new supplement rows.

Q2 Exa audit (June 2026) found 3 new GA features:
1. azuredns: DNS Security Policy with Threat Intelligence feed (VNet-level DNS filtering) → NS-1-SUPPLEMENT
2. appgateway: Private Application Gateway — no public IP deployment → NS-7-SUPPLEMENT-APPGW
3. frontdoor: WAF Default Ruleset 2.2 (DRS 2.2) — OWASP CRS 3.3.4 GA Feb 2026 → NS-2-SUPPLEMENT

Pattern mirrors scripts/phase55_add_supplements.py — idempotent (skip if ID already present).
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
        "path": "data/outputs/ns/azuredns.final.csv",
        "row": {
            "asb_control_id":                   "NS-1-SUPPLEMENT",
            "feature_name":                     "DNS Security Policy — Threat Intelligence Domain Filtering (VNet-Level)",
            "feature_supported_original":       "False",
            "feature_enabled_by_default_original": "False",
            "status_2025":                      "gap",
            "verdict_2025":                     "now_applicable_native",
            "azure_api_property":               "properties.dnsSecurityPolicy.domainLists",
            "script_module":                    "",
            "script_function":                  "",
            "notes":                            (
                "v2 gap: DNS Security Policy GA in Azure DNS — enables VNet-level DNS query filtering "
                "with Microsoft Threat Intelligence feed at no additional cost. "
                "Supports Allow/Block/Alert modes; domain lists up to 100k entries; Threat Intel toggle opt-in. "
                "Applies to all workloads using the VNet's DNS resolver (resolves to 168.63.129.16). "
                "Customer must create DNS Security Policy, associate with VNet, configure domain lists. "
                "Source: https://learn.microsoft.com/en-us/azure/dns/dns-security-policy | "
                "Q2 NS-8/NS-1 Exa search June 2026 confirmed GA."
            ),
            "service":                          "azuredns",
            "severity":                         "Medium",
            "blast_radius":                     "Narrow",
            "risk_rank":                        "2",
        },
    },
    {
        "path": "data/outputs/ns/appgateway.final.csv",
        "row": {
            "asb_control_id":                   "NS-7-SUPPLEMENT-APPGW",
            "feature_name":                     "Private Application Gateway — No Public IP Deployment",
            "feature_supported_original":       "False",
            "feature_enabled_by_default_original": "False",
            "status_2025":                      "gap",
            "verdict_2025":                     "conditional",
            "azure_api_property":               "properties.frontendIPConfigurations[].privateIPAddress",
            "script_module":                    "",
            "script_function":                  "",
            "notes":                            (
                "v2 gap: Application Gateway v2 now supports private-only frontend IP configuration "
                "(no public IP required) — closes NS-7 public network access disable gap. "
                "Requires: v2 SKU (Standard_v2 or WAF_v2), subnet delegation to "
                "Microsoft.Network/applicationGateways (mandatory from May 5 2025), "
                "private-only frontend IP config (no PublicIPAddress property). "
                "Conditional: opt-in at deployment time; existing AppGW with public IP requires rebuild. "
                "Source: https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-private-deployment | "
                "Q2 NS-7 Exa search June 2026 confirmed GA."
            ),
            "service":                          "appgateway",
            "severity":                         "High",
            "blast_radius":                     "Wide",
            "risk_rank":                        "6",
        },
    },
    {
        "path": "data/outputs/ns/frontdoor.final.csv",
        "row": {
            "asb_control_id":                   "NS-2-SUPPLEMENT",
            "feature_name":                     "WAF Default Ruleset 2.2 (DRS 2.2) — OWASP CRS 3.3.4 + Threat Intelligence",
            "feature_supported_original":       "False",
            "feature_enabled_by_default_original": "False",
            "status_2025":                      "gap",
            "verdict_2025":                     "conditional",
            "azure_api_property":               "properties.managedRules.managedRuleSets[].ruleSetVersion",
            "script_module":                    "",
            "script_function":                  "",
            "notes":                            (
                "v2 gap: WAF DRS 2.2 (Default Ruleset 2.2) GA February 2026 for Azure Front Door WAF. "
                "Based on OWASP CRS 3.3.4 with Microsoft Threat Intelligence rules. "
                "Paranoia level configuration now available. "
                "DRS 1.x end of new-policy-creation June 1 2026; end-of-support Feb 26 2027. "
                "WAF ruleset support policy updated Feb 2026 to rolling N/N-1/N-2 model. "
                "Conditional: requires explicit policy migration from DRS 1.x — not automatic. "
                "Source: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs | "
                "Q1-B Exa search June 2026 confirmed DRS 2.2 GA Feb 2026."
            ),
            "service":                          "frontdoor",
            "severity":                         "High",
            "blast_radius":                     "Wide",
            "risk_rank":                        "6",
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
    print("Phase 56 Step 3 — Q2 supplement rows")
    print("=" * 60)

    for s in SUPPLEMENTS:
        result = add_supplement(s)
        slug = pathlib.Path(s["path"]).stem.replace(".final", "")
        ctrl_id = s["row"]["asb_control_id"]
        feat = s["row"]["feature_name"][:55]
        print(f"  [{result}] {slug:<22} {ctrl_id:<30} {feat}")

    print()
    print("Done.")
