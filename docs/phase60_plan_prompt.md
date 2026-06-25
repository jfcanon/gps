# Phase 60 — BR Domain 2 CSVs: Copy, URL Backfill, Q2 Audit + ADO Import Guide Update
## Plan Prompt (Human-Readable)

**Created**: 2026-06-25
**Status**: READY FOR EXECUTION — pass to /eccplan then /eccimplement
**Continues from**: Phase 59 (IM domain complete)
**Target confidence**: ~85%+ per-row evidence depth on both BR CSVs
**Current confidence**: ~20% (v2 schema, Phase 46 content, zero URL coverage)
**Phase number**: 60

---

## Context Read Order (MANDATORY before any action)

1. `CLAUDE.md` — phase log through Phase 59, scope gates
2. `ado/activity.log` — tail Phase 59 entry
3. `data/outputs/context.md` — inventory; br/ folder does not yet exist
4. `scripts/phase59_copy_to_final.py` — copy pattern (mirror for phase60)
5. `scripts/phase59_url_backfill.py` — URL backfill pattern (mirror for phase60)
6. `scripts/phase59_individual_patches.py` — individual patch pattern (for Q1-C if needed)
7. `docs/avd_task_import_guide.md` — current ADO import guide to update with BR services
8. `data/outputs/backup_rechecked_controls_v2.csv` — source CSV (read header + all rows)
9. `data/outputs/siterecovery_rechecked_controls_v2.csv` — source CSV (read header + all rows)

---

## What Phase 60 Is

BR domain = Backup and Recovery. 2 services assessed in Phase 46 (2026-06-24).
Both CSVs exist as `data/outputs/{slug}_rechecked_controls_v2.csv` (14-col v2, 71 rows total).
Zero URL coverage on both. 1 `now_applicable_native` row (backup IM-3 — already has partial note,
no HTTP source URL).

Phase 60 is the lightest domain so far:
- Only 2 services
- 1 now_applicable_native row (backup IM-3 Managed Identity — needs URL added)
- 0 conditional rows
- Moderate N/A: backup=22 na, siterecovery=23 na

**Also in scope**: Update `docs/avd_task_import_guide.md` to add BR domain section and copilot
prompt. This completes the import guide for all assessed domains (NS 34 + IM 9 + BR 2 = 45 services).

---

## The 2 Target Source Files

```
data/outputs/backup_rechecked_controls_v2.csv        (36 rows)
  verdicts: now_applicable_native=1, implemented=13, still_not_applicable=22
  uncov before backfill: 15 rows (LIVE-DIRECT and microsoft_managed rows lacking URL)
  backup IM-3 Managed Identity: now_applicable_native — note says "Azure Backup gained
    system-assigned managed identity" but NO HTTP source URL yet

data/outputs/siterecovery_rechecked_controls_v2.csv  (35 rows)
  verdicts: implemented=12, still_not_applicable=23
  uncov before backfill: 17 rows
  no now_applicable_native rows
```

**Output path**: `data/outputs/br/{slug}.final.csv`
**Directory**: `data/outputs/br/` — CREATE if not exists (`mkdir -p data/outputs/br/`)

---

## Step 1 — Copy to Final

Mirror `scripts/phase59_copy_to_final.py`:
- Source: `data/outputs/{slug}_rechecked_controls_v2.csv`
- Dest: `data/outputs/br/{slug}.final.csv`
- Idempotent: skip if dest exists
- Script: `scripts/phase60_copy_to_final.py`
- SLUGS: backup, siterecovery

---

## Step 2 — MCSB URL Verification (HEAD requests)

Verify 2 MCSB BR baseline URLs before backfill. Pattern: Python urllib HEAD requests.

**Expected URL candidates** (verify before writing backfill script):

| Slug | Expected MCSB slug | Risk |
|---|---|---|
| backup | `azure-backup` | Low |
| siterecovery | `azure-site-recovery` | Low |

For any 404: set `BASELINE_URLS[slug] = ""` — do NOT fabricate URLs.

---

## Step 3 — Bulk URL Backfill

Mirror `scripts/phase59_url_backfill.py`:
- Script: `scripts/phase60_url_backfill.py`
- Extended EVIDENCE_MARKERS: same as phase59 (includes `"retired"`, `"no mcsb"`)
- Expected coverage: ~32 of 71 rows (15+17 UNCOV rows get URLs; remainder already have evidence)

---

## Step 4 — Per-Row Research (Q1-A/B/C)

**Q1-A: now_applicable_native rows** — 1 total:
- `backup` IM-3 Managed Identity: note says "Azure Backup gained system-assigned managed identity"
  but NO source URL. **MUST add source URL.**
  Query: "Azure Backup system-assigned managed identity GA date ARM property 2024 2025"
  Expected ARM: `Microsoft.RecoveryServices/vaults` (identity property or MSI assignment)
  Expected URL: MCSB backup baseline + Azure Backup managed identity docs

**Q1-B: conditional rows** — 0 across both CSVs. Skip.

**Q1-C: still_not_applicable verification** — spot-check 3 high-value N/A rows:

| Slug | Ctrl | Feature | Q1-C query |
|---|---|---|---|
| backup | PA-7 | Azure RBAC | "Azure Backup RBAC roles data plane management plane 2025" |
| backup | NS-2 | Azure Private Link | "Azure Backup private endpoint supported 2024 2025" |
| siterecovery | IM-8 | Service Credentials / Secrets in KV | "Azure Site Recovery Run As account service principal Key Vault 2025" |

Note: backup NS-2 Private Link may have flipped — Azure Backup added PE support. Check carefully.

---

## Step 5 — Q2 New-Feature Audit 2025-2026

2 grouped searches. Focus on BR controls (BR-1, BR-2, BR-3) and adjacent IM/NS/DP controls.

### Group A — Backup new features (MEDIUM priority)
```
Q2-A: "Azure Backup new feature BR-1 BR-2 immutable vault cross-region restore 2025 2026"
```
Focus: Immutable vault GA, Enhanced policy, Cross-region restore expansion, Backup center improvements.

### Group B — Site Recovery new features (MEDIUM priority)
```
Q2-B: "Azure Site Recovery new feature DR automation managed identity 2025 2026"
```
Focus: Managed identity support in ASR, enhanced replication policies, zone-to-zone DR.

**Supplement row format**: Mirror `phase59_individual_patches.py`. Only add if feature is GA
and maps to a BR control (BR-1, BR-2, BR-3) or significantly updates IM/NS/DP coverage for these services.

---

## Step 6 — ADO Import Guide Update

After BR CSVs pass QG, update `docs/avd_task_import_guide.md`:

1. Add BR domain section (2 services) to the "All CSVs" table:
   - backup: `data/outputs/br/backup.final.csv`
   - siterecovery: `data/outputs/br/siterecovery.final.csv`

2. Add AVD Copilot Prompt — BR Domain (2 services) section

3. Update import totals: NS 34 + IM 9 + BR 2 = **45 services, ~1566 tasks**

---

## Scripts to Write

| Script | Purpose | Pattern |
|---|---|---|
| `scripts/phase60_copy_to_final.py` | Copy 2 source CSVs → data/outputs/br/ | Mirror phase59_copy_to_final.py |
| `scripts/phase60_url_backfill.py` | Bulk MCSB URL backfill for 2 BR CSVs | Mirror phase59_url_backfill.py |
| `scripts/phase60_individual_patches.py` | Q1-A URL add + any Q1-C flips | Mirror phase59_individual_patches.py |
| `scripts/phase60_supplement_rows.py` | Q2 new SUPPLEMENT rows (if found) | Mirror phase59 supplement pattern — conditional |

Scripts 3 is likely required (backup IM-3 needs URL). Script 4 is conditional.

---

## Execution Order

```
1.  Read context files (CLAUDE.md, activity.log, 2 source CSVs, avd_task_import_guide.md)
2.  Write + run scripts/phase60_copy_to_final.py
3.  Python urllib HEAD-verify 2 MCSB BR baseline URLs
4.  Write + run scripts/phase60_url_backfill.py
5.  WebSearch Q1-A: backup IM-3 Managed Identity source URL (find ARM property + docs URL)
6.  WebSearch Q1-C: 3 spot-checks (backup PA-7, backup NS-2, siterecovery IM-8) — parallel
7.  WebSearch Q2-A/B: 2 grouped new-feature searches — parallel
8.  Write + run scripts/phase60_individual_patches.py (at minimum: backup IM-3 URL patch)
9.  If Q2 found new GA features: write + run scripts/phase60_supplement_rows.py
10. Run quality gate — both must PASS
11. Fix any FAIL rows
12. Update docs/avd_task_import_guide.md — add BR section + copilot prompt
13. git add -f data/outputs/br/ scripts/phase60_*.py docs/avd_task_import_guide.md && git commit
14. Update ado/activity.log — Phase 60 entry
15. Update CLAUDE.md — Phase 60 one-liner
16. git commit + push
17. STOP — do not start next domain or Phase 61 without user confirmation
```

---

## Quality Gate

```python
python3 -c "
import csv
ALLOWED={'implemented','now_applicable_native','upgraded_implemented','still_not_applicable',
         'conditional','not_applicable_paas','not_applicable_arm'}
slugs=['backup','siterecovery']
all_ok=True
for s in slugs:
    rows=list(csv.DictReader(open(f'data/outputs/br/{s}.final.csv')))
    bad={r['verdict_2025'] for r in rows}-ALLOWED
    no_url=[r for r in rows if r['verdict_2025']=='now_applicable_native' and 'http' not in r.get('notes','')]
    uncov=[r for r in rows if 'http' not in r.get('notes','') and 'Source' not in r.get('notes','')
           and not any(x in r.get('notes','').lower()
                       for x in ['infrastructure','azure platform','no customer','not applicable',
                                  'monitoring service','retired','no mcsb'])]
    ok=not bad and not no_url and len(uncov)<5
    if not ok: all_ok=False
    print(f'[{\"OK\" if ok else \"FAIL\"}] {s:<16} rows={len(rows):>3} no_url={len(no_url):>2} uncov={len(uncov):>3}')
print()
print('QUALITY GATE:','PASS' if all_ok else 'FAIL')
"
```

**Pass criteria**:
- Zero bad verdicts
- Zero `now_applicable_native` without URL (backup IM-3 MUST have HTTP source)
- Uncovered < 5 per CSV

---

## Constraints

| Constraint | Rule |
|---|---|
| No verdict flip | Without evidence |
| No CSV recreation | Enrich in-place only |
| git add br/ | Needs `-f` flag |
| backup IM-3 | now_applicable_native — MUST have HTTP source URL before QG |
| backup NS-2 | Check carefully — PE support may mean flip to now_applicable_native |
| No ADO operations | Script is ready (`import_assessment_tasks_to_ado.py`); user provides --parent-id when running |
| Cost hook | Ignore — user standing green light |

---

## ADO Import Readiness (current state going into Phase 60)

| Item | Status |
|---|---|
| `scripts/import_assessment_tasks_to_ado.py` | ✅ Ready |
| `requirements.txt` | ✅ Ready |
| `ado_config.py` | ⚠️ Needs `ADO_ORG` + `ADO_PROJECT` filled on AVD |
| `docs/avd_task_import_guide.md` | ✅ NS 34 + IM 9 covered; BR to be added in Phase 60 |
| NS CSVs (34 services) | ✅ `data/outputs/ns/*.final.csv` — 1176 rows |
| IM CSVs (9 services) | ✅ `data/outputs/im/*.final.csv` — 319 rows |
| BR CSVs (2 services) | 🔄 Phase 60 creates `data/outputs/br/*.final.csv` — 71 rows |
| **Total after Phase 60** | **45 services, ~1566 ADO tasks** |

---

## Success Criteria

- Both CSVs: `data/outputs/br/*.final.csv` created (71 rows total)
- Quality gate 2/2 PASS
- backup IM-3: HTTP source URL in notes
- Research confidence: ~85%+ for both
- `docs/avd_task_import_guide.md` updated with BR section + copilot prompt
- `CLAUDE.md` + `ado/activity.log` updated
- Commit pushed

---

## JSON-LD Version

See `docs/phase60_plan_prompt_jsonld.json`
