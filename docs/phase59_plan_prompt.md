# Phase 59 — IM Domain 9 CSVs: Copy, URL Backfill, Q2 Audit
## Plan Prompt (Human-Readable)

**Created**: 2026-06-24
**Status**: READY FOR EXECUTION — pass to /eccplan then /eccimplement
**Continues from**: Phase 58 (Session 6) — NS domain complete
**Target confidence**: ~85%+ per-row evidence depth on all 9 IM CSVs
**Current confidence**: ~15% (v2 schema, Phase 45 content, zero URL coverage on 8/9)
**Phase number**: 59

---

## Context Read Order (MANDATORY before any action)

1. `CLAUDE.md` — phase log through Phase 58, scope gates
2. `ado/activity.log` — tail Phase 58 entry
3. `data/outputs/context.md` — Section 5 im/ inventory (does not exist yet; note gap)
4. `scripts/phase57_copy_to_final.py` — copy pattern
5. `scripts/phase57_url_backfill.py` — URL backfill pattern
6. `scripts/phase58_individual_patches.py` — individual patch pattern
7. The 9 source CSVs in `data/outputs/`

---

## What Phase 59 Is

IM domain = Identity Management. 9 services assessed in Phase 45 (2026-06-22).
All 9 CSVs exist as `data/outputs/{slug}_rechecked_controls_v2.csv` (14-col v2, 309 rows total).
Zero URL coverage on 8/9 services. 1 `now_applicable_native` row (apimanagement LT-1 — already has source URL).

Phase 59 mirrors the NS Phase 57+58 combined approach but is lighter:
- Only 1 now_applicable_native row (already covered)
- 0 conditional rows
- Heavy N/A profile: cloudshell=33 na, trustedhardwareim=35 na (all N/A), intelligentrecommendations=32 na
- Some services are retired/niche (intelligentrecommendations retired ~2023, trustedhardwareim infrastructure)

---

## The 9 Target Source Files

```
data/outputs/addds_rechecked_controls_v2.csv                (35 rows)
data/outputs/apimanagement_rechecked_controls_v2.csv        (35 rows — 2 rows already have URLs)
data/outputs/attestation_rechecked_controls_v2.csv          (35 rows)
data/outputs/botservice_rechecked_controls_v2.csv           (35 rows)
data/outputs/cloudshell_rechecked_controls_v2.csv           (35 rows — 33 N/A)
data/outputs/intelligentrecommendations_rechecked_controls_v2.csv (38 rows — retired service)
data/outputs/spatialanchors_rechecked_controls_v2.csv       (36 rows)
data/outputs/trustedhardwareim_rechecked_controls_v2.csv    (35 rows — ALL 35 N/A)
data/outputs/universalprint_rechecked_controls_v2.csv       (35 rows)
```

**Output path**: `data/outputs/im/{slug}.final.csv`
**Directory**: `data/outputs/im/` — CREATE if not exists (`mkdir -p data/outputs/im/`)

---

## Step 1 — Copy to Final

Mirror `scripts/phase57_copy_to_final.py`:
- Source: `data/outputs/{slug}_rechecked_controls_v2.csv`
- Dest: `data/outputs/im/{slug}.final.csv`
- Idempotent: skip if dest exists
- Script: `scripts/phase59_copy_to_final.py`

Slugs: addds, apimanagement, attestation, botservice, cloudshell, intelligentrecommendations, spatialanchors, trustedhardwareim, universalprint

---

## Step 2 — MCSB URL Verification (HEAD requests)

Verify 9 MCSB IM baseline URLs before backfill. Pattern: Python urllib HEAD requests (same as Phase 57).

**Expected URL candidates** (verify before writing backfill script):

| Slug | Expected MCSB slug | Risk |
|---|---|---|
| addds | `active-directory-domain-services` | Medium |
| apimanagement | `api-management` | Low |
| attestation | `azure-attestation` | Medium |
| botservice | `azure-bot-service` | Medium |
| cloudshell | `cloud-shell` | Medium |
| intelligentrecommendations | LIKELY 404 — service retired | HIGH |
| spatialanchors | `azure-spatial-anchors` | Medium |
| trustedhardwareim | `trusted-hardware-identity-management` | High |
| universalprint | `universal-print` | Low |

**For 404 slugs**: set BASELINE_URLS[slug] = "" and use `has_evidence()` fallback logic to cover rows with existing notes content (N/A rows). Do NOT invent URLs.

**Fallback pattern for retired/no-baseline services**: Notes should contain "Service retired" or "no MCSB v3 baseline available" — these will pass the QG uncov check via the `not applicable` exemption in the notes.

---

## Step 3 — Bulk URL Backfill

Mirror `scripts/phase57_url_backfill.py`:
- Script: `scripts/phase59_url_backfill.py`
- For each slug: open `data/outputs/im/{slug}.final.csv`, backfill URL into notes where `has_evidence()` returns False
- `has_evidence()` function same as phase57 — returns True for rows already containing:
  `http`, `source:`, `infrastructure`, `azure platform`, `no customer`, `not applicable`, `monitoring service`, `phase48`, `retired`
- For services with no MCSB baseline (intelligentrecommendations, trustedhardwareim): skip URL injection, leave existing notes
- Expected coverage: ~220-260 rows backfilled across 9 CSVs (many N/A rows already have "not applicable" notes)

---

## Step 4 — Per-Row Research (Q1-A/B/C)

**Q1-A: now_applicable_native rows** — only 1 total:
- `apimanagement` LT-1: already has source URL. No enrichment needed.

**Q1-B: conditional rows** — 0 across all 9 CSVs. Skip.

**Q1-C: still_not_applicable verification** — spot-check high-value N/A rows:

| Slug | Ctrl | Feature | Q1-C query |
|---|---|---|---|
| addds | IM-3 | Managed Identity | "Azure AD Domain Services managed identity support 2025" |
| cloudshell | NS-2 | Azure Private Link | "Azure Cloud Shell private endpoint 2025" |
| botservice | IM-7 | Conditional Access | "Azure Bot Service Entra ID Conditional Access 2025" |
| universalprint | IM-1 | Azure AD Auth | "Azure Universal Print Entra ID authentication 2025" |

If any N/A confirmed flipped → update verdict + add source.

---

## Step 5 — Q2 New-Feature Audit 2025-2026

3 grouped searches. Focus on IM-domain controls (IM-1 through IM-8).

### Group A — Identity services (MEDIUM priority)
```
Q2-A: "Azure API Management Bot Service new identity management feature IM-1 IM-3 IM-7 managed identity 2025 2026"
```
Focus: API Management Entra integration improvements, Bot Service managed identity expansion.

### Group B — Attestation + Hardware (LOW priority)
```
Q2-B: "Azure Attestation Trusted Hardware Identity Management new security feature 2025 2026"
```
Focus: Attestation policy updates, THIM service changes.

### Group C — Niche/retired services (LOW priority)
```
Q2-C: "Azure Spatial Anchors Cloud Shell Universal Print new security identity feature 2025 2026"
```
Focus: Spatial Anchors deprecation, Cloud Shell private endpoint, Universal Print Entra.

**Supplement row format**: Mirror phase58_supplement_rows.py. Only add if feature is GA and maps to an IM control (IM-1 through IM-8).

---

## Scripts to Write

| Script | Purpose | Pattern |
|---|---|---|
| `scripts/phase59_copy_to_final.py` | Copy 9 source CSVs → data/outputs/im/ | Mirror phase57_copy_to_final.py |
| `scripts/phase59_url_backfill.py` | Bulk MCSB URL backfill for 9 IM CSVs | Mirror phase57_url_backfill.py |
| `scripts/phase59_individual_patches.py` | Q1-C patches (if any N/A flipped) | Mirror phase58_individual_patches.py |
| `scripts/phase59_supplement_rows.py` | Q2 new SUPPLEMENT rows (if found) | Mirror phase58_supplement_rows.py |

Scripts 3 and 4 are conditional — only write if research finds something to patch/add.

---

## Execution Order

```
1.  Read context files (CLAUDE.md, activity.log, 9 source CSVs)
2.  Write + run scripts/phase59_copy_to_final.py
3.  Python urllib HEAD-verify 9 MCSB IM baseline URLs
4.  Write + run scripts/phase59_url_backfill.py
5.  WebSearch Q1-C: 4 key still_not_applicable spot-checks (parallel)
6.  WebSearch Q2-A/B/C: 3 grouped new-feature searches (parallel)
7.  If Q1-C found flips: write + run scripts/phase59_individual_patches.py
8.  If Q2 found new features: write + run scripts/phase59_supplement_rows.py
9.  Run quality gate — all 9 must PASS
10. Fix any FAIL rows
11. git add -f data/outputs/im/ scripts/phase59_*.py && git commit
12. Update ado/activity.log — Phase 59 entry
13. Update CLAUDE.md — Phase 59 one-liner
14. STOP — do not start IM ADO import or Phase 60 without user confirmation
```

---

## Quality Gate

```python
python3 -c "
import csv
ALLOWED={'implemented','now_applicable_native','upgraded_implemented','still_not_applicable',
         'conditional','not_applicable_paas','not_applicable_arm'}
slugs=['addds','apimanagement','attestation','botservice','cloudshell',
       'intelligentrecommendations','spatialanchors','trustedhardwareim','universalprint']
all_ok=True
for s in slugs:
    rows=list(csv.DictReader(open(f'data/outputs/im/{s}.final.csv')))
    bad={r['verdict_2025'] for r in rows}-ALLOWED
    no_url=[r for r in rows if r['verdict_2025']=='now_applicable_native' and 'http' not in r.get('notes','')]
    uncov=[r for r in rows if 'http' not in r.get('notes','') and 'Source' not in r.get('notes','')
           and not any(x in r.get('notes','').lower()
                       for x in ['infrastructure','azure platform','no customer','not applicable',
                                  'monitoring service','retired','no mcsb'])]
    ok=not bad and not no_url and len(uncov)<5
    if not ok: all_ok=False
    print(f'[{\"OK\" if ok else \"FAIL\"}] {s:<28} rows={len(rows):>3} no_url={len(no_url):>2} uncov={len(uncov):>3}')
print()
print('QUALITY GATE:','PASS' if all_ok else 'FAIL')
"
```

**Extra QG exemption vs NS**: added `'retired','no mcsb'` to uncov exemption — covers intelligentrecommendations and trustedhardwareim rows.

**Pass criteria**:
- Zero bad verdicts
- Zero `now_applicable_native` without URL
- Uncovered < 5 per CSV
- trustedhardwareim exception: 35 N/A rows — all should pass via `not applicable` exemption in notes

---

## Constraints

| Constraint | Rule |
|---|---|
| No verdict flip | Without evidence |
| No CSV recreation | Enrich in-place only |
| git add im/ | Needs `-f` flag |
| intelligentrecommendations | Retired service — do NOT fabricate MCSB URL. Use "Service retired ~2023" note. |
| trustedhardwareim | All 35 N/A — expected. No enrichment needed beyond URL attempt. |
| No ADO ops | Phase 53 IM ADO import blocked on user providing User Story IDs |
| Cost hook | Ignore — user standing green light |

---

## Success Criteria

- All 9 CSVs: `data/outputs/im/*.final.csv` created
- Quality gate 9/9 PASS
- Research confidence: ~85%+ for all 9 (from ~15%)
- CLAUDE.md + activity.log updated
- Commit pushed

---

## JSON-LD Version

See `docs/phase59_plan_prompt_jsonld.json`
