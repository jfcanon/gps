"""Phase 55 Step 1 — Transfer evidence from JSON caches to .final.csv notes fields.

Handles LIST-format caches (azuredns, azurefirewall, bastion, frontdoor,
privatelink, redis, vpngateway, waf). Fills notes with evidence_url + summary.
Flips still_not_applicable → now_applicable_native where cache verdict_2026 says so.
"""
import csv
import json
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

SEV_SCORE = {"High": 3, "Medium": 2, "Low": 1}
BR_SCORE  = {"Wide": 2, "Narrow": 1}


def compute_blast_radius(row: dict) -> str:
    api = row.get("azure_api_property", "").strip()
    no_api = not api or api.upper() in ("", "N/A", "NA")
    if (row["verdict_2025"] == "conditional"
            or no_api
            or row.get("feature_enabled_by_default_original", "") == "False"):
        return "Wide"
    return "Narrow"


def compute_risk_rank(row: dict) -> str:
    sev = SEV_SCORE.get(row.get("severity", "Medium"), 2)
    br  = BR_SCORE.get(row.get("blast_radius", "Narrow"), 1)
    return str(sev * br)


def transfer_list_cache(slug: str, cache_path: pathlib.Path, csv_path: pathlib.Path) -> dict:
    """Transfer evidence from LIST-format cache to CSV. Returns stats."""
    cache_data = json.load(open(cache_path))

    # Build lookup: (asb_control_id, feature_name) → entry
    # Also build feature_name-only lookup for fuzzy match
    exact_map: dict = {}
    fname_map: dict = {}
    for d in cache_data:
        if not isinstance(d, dict):
            continue
        key = (d.get("asb_control_id", "").strip(), d.get("feature_name", "").strip())
        exact_map[key] = d
        fname = d.get("feature_name", "").strip()
        if fname not in fname_map:
            fname_map[fname] = d

    rows = list(csv.DictReader(open(csv_path)))

    stats = {"transferred": 0, "flipped": 0, "skipped_already_has_url": 0,
             "no_cache_match": 0, "no_cache_url": 0}

    for row in rows:
        current_notes = row.get("notes", "")
        # Skip if already has URL
        if "http" in current_notes:
            stats["skipped_already_has_url"] += 1
            continue

        # Only process still_not_applicable and now_applicable_native gaps
        verdict = row["verdict_2025"]
        if verdict not in ("still_not_applicable", "now_applicable_native"):
            continue

        # Match to cache entry
        key = (row["asb_control_id"].strip(), row["feature_name"].strip())
        cached = exact_map.get(key) or fname_map.get(row["feature_name"].strip())

        if cached is None:
            stats["no_cache_match"] += 1
            continue

        ev_url = str(cached.get("evidence_url", "")).strip()
        if not ev_url.startswith("http"):
            stats["no_cache_url"] += 1
            continue

        verdict_2026 = cached.get("verdict_2026", "").strip()
        cache_notes  = str(cached.get("notes", "")).strip()
        ev_date      = str(cached.get("evidence_date", "2026")).strip()
        r_date       = str(cached.get("research_date", "2026-06")).strip()

        if verdict == "still_not_applicable":
            if verdict_2026 == "now_applicable_native":
                # Flip verdict
                row["verdict_2025"] = "now_applicable_native"
                row["notes"] = (
                    f"now_applicable_native as of {ev_date}: {cache_notes} "
                    f"Source: {ev_url}"
                )
                row["blast_radius"] = compute_blast_radius(row)
                row["risk_rank"]    = compute_risk_rank(row)
                stats["flipped"] += 1
            else:
                # Keep still_not_applicable, add evidence
                row["notes"] = (
                    f"{current_notes.rstrip()} | "
                    f"Exa {r_date}: {cache_notes} Source: {ev_url}"
                ).lstrip(" |")
                stats["transferred"] += 1

        elif verdict == "now_applicable_native":
            # Add URL to confirm
            row["notes"] = (
                f"{current_notes.rstrip()} "
                f"Source: {ev_url} (evidence_date: {ev_date})"
            ).strip()
            stats["transferred"] += 1

    # Write updated CSV
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return stats


def transfer_dict_cache(slug: str, cache_path: pathlib.Path, csv_path: pathlib.Path) -> dict:
    """Transfer rationale from DICT-format cache (appgateway, servicebus) — no URLs available.
    Populates notes with rationale text so Exa search later has context.
    """
    data = json.load(open(cache_path))
    pb = data.get("path_b_verdicts", [])

    # Build lookup by control_id + feature (DICT format has 'control_id' not 'asb_control_id')
    rationale_map: dict = {}
    for d in pb:
        if not isinstance(d, dict):
            continue
        feat = str(d.get("feature", "")).strip()
        cid  = str(d.get("control_id", "")).strip()
        rationale_map[(cid, feat)] = d
        rationale_map[feat] = d  # fuzzy by feature name

    rows = list(csv.DictReader(open(csv_path)))
    stats = {"rationale_added": 0, "no_match": 0, "skipped": 0}

    for row in rows:
        current_notes = row.get("notes", "")
        verdict = row["verdict_2025"]
        # Only handle rows without Exa evidence
        if verdict not in ("still_not_applicable", "now_applicable_native"):
            continue
        if "http" in current_notes or "Exa" in current_notes:
            stats["skipped"] += 1
            continue

        key = (row["asb_control_id"].strip(), row["feature_name"].strip())
        cached = rationale_map.get(key) or rationale_map.get(row["feature_name"].strip())

        if cached is None:
            stats["no_match"] += 1
            continue

        rationale = str(cached.get("rationale", "")).strip()
        if rationale:
            row["notes"] = f"{current_notes.rstrip()} | Phase48-cache: {rationale} [NEEDS-EXA-URL]".lstrip(" |")
            stats["rationale_added"] += 1
        else:
            stats["no_match"] += 1

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return stats


def audit_gaps(slug: str, csv_path: pathlib.Path) -> dict:
    """Count remaining gaps after cache transfer."""
    rows = list(csv.DictReader(open(csv_path)))
    still_na = [r for r in rows if r["verdict_2025"] == "still_not_applicable"]
    now_app  = [r for r in rows if r["verdict_2025"] == "now_applicable_native"]
    na_no_ev = [r for r in still_na
                if not any(x in r.get("notes", "").lower()
                           for x in ["http", "source:", "exa", "2025", "2026", "phase48"])]
    na_no_url = [r for r in now_app if "http" not in r.get("notes", "")]
    return {
        "rows": len(rows),
        "still_na": len(still_na),
        "na_no_evidence": len(na_no_ev),
        "now_app": len(now_app),
        "now_app_no_url": len(na_no_url),
    }


if __name__ == "__main__":
    base = pathlib.Path("data/outputs")
    ns   = base / "ns"

    # --- Group 1: LIST format with URLs ---
    list_slugs = ["azuredns", "azurefirewall", "bastion", "frontdoor",
                  "privatelink", "vpngateway", "waf"]

    print("=" * 70)
    print("GROUP 1 — LIST format caches (URL transfer)")
    print("=" * 70)
    for slug in list_slugs:
        cache_path = base / f"{slug}_na_research.json"
        csv_path   = ns   / f"{slug}.final.csv"
        if not cache_path.exists():
            print(f"  {slug:<20} SKIP — no cache file")
            continue
        stats = transfer_list_cache(slug, cache_path, csv_path)
        gaps  = audit_gaps(slug, csv_path)
        print(f"  {slug:<20} transferred={stats['transferred']:>3} flipped={stats['flipped']:>3} "
              f"| remaining_gaps: still_na_no_ev={gaps['na_no_evidence']:>3} "
              f"now_app_no_url={gaps['now_app_no_url']:>3}")

    # --- Group 2: redis (LIST partial) ---
    print()
    print("=" * 70)
    print("GROUP 2 — redis (LIST format, partial cache)")
    print("=" * 70)
    slug = "redis"
    cache_path = base / f"{slug}_na_research.json"
    csv_path   = ns   / f"{slug}.final.csv"
    stats = transfer_list_cache(slug, cache_path, csv_path)
    gaps  = audit_gaps(slug, csv_path)
    print(f"  {slug:<20} transferred={stats['transferred']:>3} flipped={stats['flipped']:>3} "
          f"no_cache_match={stats['no_cache_match']:>3} "
          f"| remaining_gaps: still_na_no_ev={gaps['na_no_evidence']:>3} "
          f"now_app_no_url={gaps['now_app_no_url']:>3}")

    # --- Group 3: DICT format (appgateway, servicebus) ---
    print()
    print("=" * 70)
    print("GROUP 3 — DICT format caches (rationale only, no URLs)")
    print("=" * 70)
    for slug in ["appgateway", "servicebus"]:
        cache_path = base / f"{slug}_na_research.json"
        csv_path   = ns   / f"{slug}.final.csv"
        if not cache_path.exists():
            print(f"  {slug:<20} SKIP — no cache")
            continue
        stats = transfer_dict_cache(slug, cache_path, csv_path)
        gaps  = audit_gaps(slug, csv_path)
        print(f"  {slug:<20} rationale_added={stats['rationale_added']:>3} "
              f"no_match={stats['no_match']:>3} "
              f"| remaining_gaps: still_na_no_ev={gaps['na_no_evidence']:>3} "
              f"now_app_no_url={gaps['now_app_no_url']:>3}")

    # --- Group 4: NO CACHE ---
    print()
    print("=" * 70)
    print("GROUP 4 — No cache (full Exa needed)")
    print("=" * 70)
    for slug in ["ddosprotection", "firewallmanager", "networkwatcher", "publicip"]:
        csv_path = ns / f"{slug}.final.csv"
        gaps = audit_gaps(slug, csv_path)
        print(f"  {slug:<20} still_na={gaps['still_na']:>3} na_no_ev={gaps['na_no_evidence']:>3} "
              f"now_app={gaps['now_app']:>3} now_app_no_url={gaps['now_app_no_url']:>3}")

    print()
    print("Cache transfer complete. Run audit to see remaining Exa-search work queue.")
