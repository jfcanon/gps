#!/usr/bin/env python3
"""Azure CDN / Azure Front Door — MCSB v3 compliance assessment runner. Read-only."""
import argparse, json, logging, os, sys
from datetime import datetime, timezone
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ns_azurecdn, dp_azurecdn, im_azurecdn, lt_azurecdn, br_azurecdn, am_azurecdn, pa_azurecdn, es_azurecdn, pv_azurecdn

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

CHECK_REGISTRY: dict[str, Callable] = {
    "NS-1:nsg":                     ns_azurecdn.check_ns1_nsg,
    "NS-2:private_link":            ns_azurecdn.check_ns2_private_link,
    "NS-2:disable_public_access":   ns_azurecdn.check_ns2_disable_public_access,
    "DP-3:tls_transit":             dp_azurecdn.check_dp3_tls_transit,
    "DP-4:platform_keys":           dp_azurecdn.check_dp4_platform_keys,
    "IM-3:managed_identities":      im_azurecdn.check_im3_managed_identities,
    "IM-7:conditional_access":      im_azurecdn.check_im7_conditional_access,
    "LT-1:defender":                lt_azurecdn.check_lt1_defender,
    "LT-4:resource_logs":           lt_azurecdn.check_lt4_resource_logs,
    "BR-1:azure_backup":            br_azurecdn.check_br1_azure_backup,
    "AM-2:policy_support":          am_azurecdn.check_am2_policy,
    "PA-8:customer_lockbox":        pa_azurecdn.check_pa8_customer_lockbox,
    "ES-1:edr":                     es_azurecdn.check_es1_edr,
    "ES-2:antimalware":             es_azurecdn.check_es2_antimalware,
    "ES-3:antimalware_health":      es_azurecdn.check_es3_antimalware_health,
    "PV-3:automation":              pv_azurecdn.check_pv3_automation,
    "PV-5:defender_va":             pv_azurecdn.check_pv5_defender_va,
    "PV-6:update_mgmt":             pv_azurecdn.check_pv6_update_mgmt,
}


def run_checks(credential, subscription_id, resource_group, profile_name):
    results = []
    for key, fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            results.append(fn(credential, subscription_id, resource_group, profile_name))
        except Exception as e:
            cid = key.split(":")[0]
            log.error(f"{key}: {e}")
            results.append({"resource": profile_name or "UNKNOWN", "control_id": cid, "feature": key,
                            "status": "UNKNOWN", "actual_value": None, "expected_value": None,
                            "evidence_url": None, "error": str(e)})
    return results


def main():
    parser = argparse.ArgumentParser(description="MCSB v3 checks for Azure CDN / Front Door")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", default=None)
    parser.add_argument("--profile-name", default=None)
    parser.add_argument("--output-dir", default="data/outputs/assessment_results")
    args = parser.parse_args()
    from azure.identity import DefaultAzureCredential
    credential = DefaultAzureCredential()
    log.info(f"Running {len(CHECK_REGISTRY)} checks")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.profile_name)
    os.makedirs(args.output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(args.output_dir, f"azurecdn_{args.subscription_id}_{ts}.json")
    summary = {"service": "azure-cdn", "version": "v1", "subscription_id": args.subscription_id,
               "resource_group": args.resource_group, "profile_name": args.profile_name,
               "run_timestamp": ts, "total_checks": len(results),
               "pass": sum(1 for r in results if r.get("status") == "PASS"),
               "fail": sum(1 for r in results if r.get("status") == "FAIL"),
               "unknown": sum(1 for r in results if r.get("status") == "UNKNOWN"),
               "results": results}
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    log.info(f"Results → {out}  PASS={summary['pass']} FAIL={summary['fail']} UNKNOWN={summary['unknown']}")


if __name__ == "__main__":
    main()
