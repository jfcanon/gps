#!/usr/bin/env python3
"""Azure Cognitive Search — MCSB v3 compliance assessment runner. Read-only."""
import argparse, json, logging, os, sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_cognitivesearch, dp_cognitivesearch, im_cognitivesearch, lt_cognitivesearch
import br_cognitivesearch, am_cognitivesearch, es_cognitivesearch, pv_cognitivesearch

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    "NS-1:nsg":                     ns_cognitivesearch.check_ns1_nsg,
    "NS-2:private_link":            ns_cognitivesearch.check_ns2_private_link,
    "NS-2:disable_public_access":   ns_cognitivesearch.check_ns2_disable_public_access,
    "DP-3:tls_transit":             dp_cognitivesearch.check_dp3_tls_transit,
    "DP-4:platform_keys":           dp_cognitivesearch.check_dp4_platform_keys,
    "DP-5:cmk":                     dp_cognitivesearch.check_dp5_cmk,
    "DP-6:key_mgmt_kv":             dp_cognitivesearch.check_dp6_key_mgmt,
    "IM-1:aad_auth_required":       im_cognitivesearch.check_im1_aad_auth,
    "IM-1:local_auth_disabled":     im_cognitivesearch.check_im1_local_auth_methods,
    "IM-3:service_principals":      im_cognitivesearch.check_im3_service_principals,
    "IM-7:conditional_access":      im_cognitivesearch.check_im7_conditional_access,
    "PA-7:rbac_data_plane":         im_cognitivesearch.check_pa7_rbac_data_plane,
    "PA-8:customer_lockbox":        im_cognitivesearch.check_pa8_customer_lockbox,
    "LT-1:defender":                lt_cognitivesearch.check_lt1_defender,
    "LT-4:resource_logs":           lt_cognitivesearch.check_lt4_resource_logs,
    "BR-1:azure_backup":            br_cognitivesearch.check_br1_azure_backup,
    "AM-2:policy_support":          am_cognitivesearch.check_am2_policy,
    "ES-1:edr":                     es_cognitivesearch.check_es1_edr,
    "ES-2:antimalware":             es_cognitivesearch.check_es2_antimalware,
    "ES-3:antimalware_health":      es_cognitivesearch.check_es3_antimalware_health,
    "PV-3:automation":              pv_cognitivesearch.check_pv3_automation,
    "PV-5:defender_va":             pv_cognitivesearch.check_pv5_defender_va,
    "PV-6:update_mgmt":             pv_cognitivesearch.check_pv6_update_mgmt,
}


def run_checks(credential, subscription_id, resource_group, service_name):
    results = []
    for key, fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            results.append(fn(credential, subscription_id, resource_group, service_name))
        except Exception as e:
            log.error(f"{key}: {e}")
            results.append({"resource": service_name or "UNKNOWN", "control_id": key.split(":")[0],
                            "feature": key, "status": "UNKNOWN", "actual_value": None,
                            "expected_value": None, "evidence_url": None, "error": str(e)})
    return results


def main():
    parser = argparse.ArgumentParser(description="MCSB v3 checks for Azure Cognitive Search")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", default=None)
    parser.add_argument("--service-name", default=None)
    parser.add_argument("--output-dir", default="data/outputs/assessment_results")
    args = parser.parse_args()
    from azure.identity import DefaultAzureCredential
    credential = DefaultAzureCredential()
    log.info(f"Running {len(CHECK_REGISTRY)} checks")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.service_name)
    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(args.output_dir, f"cognitivesearch_{args.subscription_id}_{ts}.json")
    summary = {"service": "azure-cognitive-search", "version": "v1",
               "subscription_id": args.subscription_id, "resource_group": args.resource_group,
               "service_name": args.service_name, "run_timestamp": ts,
               "total_checks": len(results),
               "pass": sum(1 for r in results if r.get("status") == "PASS"),
               "fail": sum(1 for r in results if r.get("status") == "FAIL"),
               "unknown": sum(1 for r in results if r.get("status") == "UNKNOWN"),
               "results": results}
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    log.info(f"Results → {out}  PASS={summary['pass']} FAIL={summary['fail']} UNKNOWN={summary['unknown']}")


if __name__ == "__main__":
    main()
