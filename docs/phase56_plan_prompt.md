# Phase 56 — NS Domain 14 CSVs: URL Backfill + June 2026 Re-search + Exhaustive New-Row Audit
## Plan Prompt (Persistent — reuse in new sessions)

**Last updated**: 2026-06-24
**Status**: READY FOR EXECUTION — pending new Claude session
**Continues from**: `docs/phase52_plan_prompt.md`
**Target confidence**: 95%+ on Q1 (web search) + Q2 (new rows considered)
**Current confidence**: ~78% (Q1+Q2 combined, per Phase 55 close-out assessment)

---

## Context You Must Read First (in this order)

1. `CLAUDE.md` — full phase log, scope gates, workflow protocol
2. `ado/activity.log` — tail for latest completed phases (Phase 55 is latest)
3. `data/outputs/context.md` — inventory including new Section 5 (ns/ folder)
4. `data/outputs/ns/` — the 14 `.final.csv` files to enrich (DO NOT recreate — enrich only)
5. `docs/phase52_plan_prompt.md` — prior plan structure to mirror

---

## What Phase 56 Is

Bring the 14 NS `.final.csv` files in `data/outputs/ns/` from ~78% to 95%+ evidence confidence.

Three workstreams (run in parallel where possible):

### Q1-A: URL Backfill for `implemented` rows (103 rows, no URL)

The 103 uncovered rows are mostly `implemented` verdicts that inherited their verdict from the xlsx `True/True` pattern but never received a source URL. The MCSB v3 baseline pages are the authoritative source for these.

**Pattern**: For each service slug, ONE Exa search on its MCSB security baseline page is enough to cover ALL implemented rows for that service.
**URL pattern**: `https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/{service-name}-security-baseline`

Services with uncovered rows and their approximate count:
| Service slug | Uncovered rows | Priority |
|---|---|---|
| servicebus | 13 | HIGH |
| redis | 12 | HIGH |
| appgateway | 12 | HIGH |
| waf | 10 | HIGH |
| frontdoor | 8 | MEDIUM |
| azurefirewall | 8 | MEDIUM |
| bastion | 7 | MEDIUM |
| vpngateway | 7 | MEDIUM |
| networkwatcher | 5 | MEDIUM |
| privatelink | 5 | MEDIUM |
| azuredns | 4 | LOW |
| ddosprotection | 4 | LOW |
| firewallmanager | 4 | LOW |
| publicip | 4 | LOW |

**Action per service**: Exa search the MCSB baseline page → verify `implemented` rows match baseline `True/True` or `True/False` → add `Source: {url}` to notes. Do NOT change verdict.

**Special case rows** (need individual verification, not bulk baseline URL):
- appgateway IM-3 Service Principals: `still_not_applicable` — verify still False in June 2026 baseline
- appgateway PV-3 (×3): `still_not_applicable` — Azure Automation State Config, Policy Guest Config, Custom Container Images — verify
- appgateway PV-5: `still_not_applicable` — Vulnerability Assessment via Defender — verify
- servicebus PV-3: `still_not_applicable` — verify
- servicebus PV-5: `still_not_applicable` — verify
- ddosprotection DP-3: `still_not_applicable` — DDoS plan has no data-in-transit concept — verify
- vpngateway IM-7: `conditional` — Conditional Access for Data Plane — needs URL
- vpngateway PA-7: `implemented` — RBAC for data plane — needs URL
- azuredns PA-7: `conditional` — DNS Zone Management RBAC — needs URL
- frontdoor PA-7: `conditional` — AFD Management RBAC — needs URL

### Q1-B: June 2026 Re-search for stale cache entries

azuredns and frontdoor had their `now_applicable_native` / `still_not_applicable` evidence sourced from Phase 48 caches (evidence dates: 2025). Re-search with June 2026 queries to confirm or update.

**azuredns** (31 rows have URLs, 4 uncovered):
- Re-verify: LT-1 (Defender for DNS), LT-4 (Resource Logs), AM-2 (Policy), PA-7 (conditional)
- Source: `https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-dns-security-baseline`
- Exa query: "Azure DNS MCSB security baseline 2025 2026 Defender Policy RBAC"

**frontdoor** (27 rows have URLs, 8 uncovered):
- Re-verify: NS-2 (IP Filtering via WAF), DP-3/4/7, IM-8, LT-4, AM-2, PA-7
- Source: `https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-front-door-security-baseline`
- Exa query: "Azure Front Door MCSB security baseline 2025 2026"

### Q2: Exhaustive New-Row Audit (2025–2026 NS sub-controls)

Check whether any new NS sub-controls or features were GA'd in 2025–2026 that are NOT yet represented as rows in these 14 CSVs. Specifically:

**Known NS sub-controls to audit per service**:
- NS-1: NSG, VNet integration, Threat Intelligence, IDPS (already have NS-6-SUPPLEMENT for azurefirewall)
- NS-2: Private Link, Disable Public Network Access (already have NS-7-SUPPLEMENT for redis+servicebus)
- NS-3: Service-to-service firewall rules (Defender for Cloud network map) — check per service
- NS-4: Encryption in transit (TLS 1.3 enforcement, deprecation of TLS 1.0/1.1 — any new GA?)
- NS-5: DDoS Protection Standard GA changes — new tiers?
- NS-6: IDPS — any services added IDPS in 2025-2026 beyond Azure Firewall Premium?
- NS-7: Public endpoint disable — any services added this in 2025-2026 beyond redis/servicebus?
- NS-8: DNS security (Private DNS zones) — check waf, appgateway, bastion

**Exa queries** (run per NS sub-control, not per service):
1. "Azure NS-3 network firewall rules service-to-service 2025 2026 new"
2. "Azure TLS 1.3 enforcement NS-4 Application Gateway WAF Bastion VPN 2025 2026"
3. "Azure DDoS Protection NS-5 Standard Network 2025 2026 new tier"
4. "Azure IDPS NS-6 services 2025 2026 beyond Azure Firewall"
5. "Azure public network access disable NS-7 new services 2025 2026"
6. "Azure Private DNS NS-8 WAF AppGateway Bastion 2025 2026"

For each finding: if a new capability exists → add new row with same 14-col schema (SUPPLEMENT suffix on asb_control_id).

---

## What Phase 56 Is NOT

- NOT re-creating any CSV from scratch
- NOT changing validated verdicts without MCSB baseline evidence
- NOT writing assessment scripts
- NOT ADO import
- NOT enriching Phase 52 NS CSVs (those are Phase 57/54 scope)

---

## Output Files

Same 14 files, enriched in-place:
```
data/outputs/ns/appgateway.final.csv
data/outputs/ns/azuredns.final.csv
data/outputs/ns/azurefirewall.final.csv
data/outputs/ns/bastion.final.csv
data/outputs/ns/ddosprotection.final.csv
data/outputs/ns/firewallmanager.final.csv
data/outputs/ns/frontdoor.final.csv
data/outputs/ns/networkwatcher.final.csv
data/outputs/ns/privatelink.final.csv
data/outputs/ns/publicip.final.csv
data/outputs/ns/redis.final.csv
data/outputs/ns/servicebus.final.csv
data/outputs/ns/vpngateway.final.csv
data/outputs/ns/waf.final.csv
```

---

## Scripts to Write

### `scripts/phase56_url_backfill.py`

```python
# Applies MCSB baseline URL to all `implemented` rows without URL
# Input: Exa findings dict {slug: baseline_url}
# Action: append "Source: {url}" to notes for uncovered implemented rows
# Does NOT change verdict
```

### `scripts/phase56_supplement_rows.py`

```python
# Adds Q2 new-row SUPPLEMENT entries if Exa finds new 2025-2026 features
# Same pattern as phase55_add_supplements.py
# asb_control_id format: NS-{N}-SUPPLEMENT-{slug} for per-service; NS-{N}-SUPPLEMENT if universal
```

---

## Execution Order

1. **Exa batch 1** — Fetch all 14 MCSB baseline pages (one search per service slug)
2. **Exa batch 2** — Re-search azuredns + frontdoor specific items (PA-7, LT items)
3. **Exa batch 3** — NS sub-control sweep (Q2 new-row audit, 6 queries)
4. **Write** `scripts/phase56_url_backfill.py` — apply baseline URLs to 103 uncovered rows
5. **Write** `scripts/phase56_supplement_rows.py` — add Q2 new supplement rows if found
6. **Run quality gate** — all 14 CSVs must PASS
7. **Commit** — all changed CSVs + scripts
8. **Update** `ado/activity.log` — Phase 56 entry
9. **Update** `CLAUDE.md` — Phase 56 one-liner
10. **STOP** — do not start Phase 57

---

## Quality Gate (run after every write pass)

```python
python3 -c "
import csv, pathlib
ALLOWED = {'implemented','now_applicable_native','upgraded_implemented',
           'still_not_applicable','conditional','not_applicable_paas','not_applicable_arm'}
slugs = ['appgateway','azuredns','azurefirewall','bastion','ddosprotection',
         'firewallmanager','frontdoor','networkwatcher','privatelink','publicip',
         'redis','servicebus','vpngateway','waf']
all_ok = True
for s in slugs:
    rows = list(csv.DictReader(open(f'data/outputs/ns/{s}.final.csv')))
    bad = {r['verdict_2025'] for r in rows} - ALLOWED
    no_url = [r for r in rows if r['verdict_2025']=='now_applicable_native'
              and 'http' not in r.get('notes','')]
    uncovered = [r for r in rows
                 if 'http' not in r.get('notes','')
                 and 'Source' not in r.get('notes','')
                 and not any(x in r.get('notes','').lower()
                             for x in ['infrastructure','azure platform','no customer',
                                       'not applicable','monitoring service'])]
    ok = not bad and not no_url and len(uncovered) < 5
    if not ok: all_ok = False
    print(f'[{\"OK\" if ok else \"FAIL\"}] {s:<22} rows={len(rows):>3} bad={bad or \"-\":10} no_url={len(no_url):>2} uncovered={len(uncovered):>3}')
print()
print('QUALITY GATE:', 'PASS' if all_ok else 'FAIL')
"
```

**Pass criteria for Phase 56**:
- All 14: zero bad verdicts
- All 14: zero `now_applicable_native` without URL
- All 14: `uncovered` count < 5 (allow up to 4 rows that are genuinely hard to source)
- Any `still_not_applicable` PV-3 / PV-5 rows: must have standard rationale note

---

## Constraints

- Never hardcode secrets
- ADO_PAT env var only — not relevant here (no ADO ops in Phase 56)
- Do not flip any `implemented` verdict to something else without MCSB evidence
- Do not delete or recreate CSVs — enrich in-place only
- Process 14 service URL backfill FIRST (fast, high coverage gain), then Q2 audit
- git add with `-f` flag needed for `data/outputs/ns/` (covered by .gitignore — tracked files still stage fine with force)

---

## Success Criteria

- Uncovered rows: < 5 per CSV (down from 4–13 currently)
- All now_applicable_native rows: URL present
- Q2 audit complete: documented finding (new rows added OR explicit "no new features found" note in activity.log)
- azuredns + frontdoor: June 2026 evidence confirmed or updated
- Commits: changed CSVs + scripts + activity.log + CLAUDE.md

---

## JSONLD Version

See `docs/phase56_plan_prompt_jsonld.json`
