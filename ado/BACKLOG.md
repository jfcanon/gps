# ADO Work Item Backlog — Deferred Work

Items parked here are confirmed in design but NOT yet implemented.
Revisit after current sprint (features + user stories enrichment) is complete.

---

## BACKLOG-1: Task Generation from v3 Excel Rows

**Status**: Parked — implement after Feature + User Story enrichment done
**Decided**: 2026-06-12

### What

Generate one ADO Task per row in each of the 118 MCSB v3 Azure resource Excel files.
Each Task = one granular security control assessed against one Azure resource.
Tasks live under their parent v3 User Story (or v2 User Story if v2→v3→Task hierarchy chosen).

Expected volume: ~3,000 Tasks (118 resources × avg ~25 rows/file)

### Why

v3 Excel rows contain the implementation-level details:
- Which specific feature/control applies to the resource
- Whether a built-in Azure Policy exists (Feature Policy Name column)
- Whether the control is supported (True/False/Not Applicable)
- Actionability: "Assign built-in policy X" vs "Create custom control"

v3 "Not Applicable" rows need staleness review — many were marked NA at v3 release time
(~2021-2022) but 2026 services now support those controls.
Example: Storage ES-2/ES-3 marked NA in v3, but Defender for Storage and new 2026
endpoint security products now apply to Storage workloads.

### Task Classification Logic (decided)

```
if Feature_Supported == "True" and Feature_Policy_Name not empty:
    task_type = "Assign Built-in Policy"
    title = "[{resource}] {Feature_Name} — Assign: {Feature_Policy_Name}"

if Feature_Supported == "True" and Feature_Policy_Name empty:
    task_type = "Manual Control"
    title = "[{resource}] {Feature_Name} — Manual: {Feature_Description[:80]}"

if Feature_Supported == "Not Applicable":
    task_type = "Staleness Review"
    title = "[{resource}] {Feature_Name} — REVIEW: v3 marked NA (verify 2026 state)"
    tags += "staleness-review; v3-na-flag"

if Feature_Supported == "False":
    task_type = "Not Supported"
    title = "[{resource}] {Feature_Name} — N/A: Not supported by this resource"
```

### Files to Create (when ready)

| File | Description |
|---|---|
| scripts/generate_ado_tasks.py | Reads v3 Excel files from data/inputs/v3_excels/, outputs ado_tasks.csv |
| scripts/export_ado_tasks_csv.py | Formats ado_tasks.csv into ADO bulk import format |
| ado/ado_import_tasks.csv | ADO bulk import: Work Item Type=Task, ~3000 rows |

### Input Required

Download all 118 v3 Excel files from:
https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Security%20Benchmark/3.0

Place in: data/inputs/v3_excels/

Filename pattern: {resource}-azure-security-benchmark-v3-latest-security-baseline.xlsx
Example: storage-azure-security-benchmark-v3-latest-security-baseline.xlsx

### Script Logic (designed, not built)

```python
# generate_ado_tasks.py outline
CONTROL_TO_STORY = {
    "NS-1":  "[SEC-NS-1] Establish Network Segmentation Boundaries",
    "NS-2":  "[SEC-NS-2] Secure Cloud Native Services with Network Controls",
    # ... all 80 v2 controls mapped
}

for xlsx_file in Path("data/inputs/v3_excels").glob("*.xlsx"):
    resource_name = infer_resource_name(xlsx_file.stem)
    df = pd.read_excel(xlsx_file, skiprows=1)  # skip header row
    for _, row in df.iterrows():
        control_id = row["Security Control ID"]   # e.g. "NS-2"
        feature_name = row["Feature Name"]
        feature_supported = row["Feature Supported"]   # True/False/Not Applicable
        policy_name = row["Feature Policy Name"]
        parent_story = CONTROL_TO_STORY.get(control_id, "UNMAPPED")
        task_type, title, staleness = classify_task(feature_supported, policy_name, resource_name, feature_name)
        write_row(ado_tasks_csv, ...)
```

### Pipeline Integration

Add to scripts/run_pipeline.sh as step 10/10:
```bash
echo "[10/10] Generating ADO tasks from v3 Excel rows..."
if [ -d "data/inputs/v3_excels" ] && ls data/inputs/v3_excels/*.xlsx 1>/dev/null 2>&1; then
    python3 scripts/generate_ado_tasks.py
    python3 scripts/export_ado_tasks_csv.py
else
    echo "SKIP: data/inputs/v3_excels/ empty — download xlsx files from SecurityBenchmarks repo"
fi
```

---

## BACKLOG-2: v2 Native Control Task Generation

**Status**: Parked — implement alongside BACKLOG-1

### What

v2 native controls (NS-1 through GS-10) also have implementation sub-tasks:
- Azure Policy built-in assignments
- Manual configuration steps
- Verification queries (Resource Graph, Defender for Cloud)

These are NOT in the v3 Excel files (v3 is resource-level only).
Source: MCSB v2 guidance on MS Learn + Azure Policy built-in catalog.

### How (when ready)

Script fetches v2 control implementation details from:
- scripts/fetch_mcsb_v2.py output (already written)
- Azure Policy built-in catalog API (filter by MCSB v2 control ID metadata)
- Output: Tasks under each v2 User Story (not under v3 child User Stories)

---

## ADO Hierarchy Decision Log

**2026-06-12**: Decided current sprint scope = Feature + User Story only (no Tasks yet).

**Final agreed hierarchy** (current sprint):
```
Feature (12 security domains)
  └── User Story Level 1: v2 controls (80 — from MS Learn MCSB v2 page)
      └── User Story Level 2: v3 resources (118 — one per Azure resource file)
```

**ADO constraint noted**: Standard Agile backlog = Epic → Feature → User Story.
User Story → User Story parent is non-standard (works via parent link, invisible in Sprint backlog).
Alternate clean mapping = Epic (domain) → Feature (v2) → User Story (v3).
Decision deferred to user — plan supports both options via Parent Title column in CSV.

**Tasks = BACKLOG-1** (deferred): ~3,000 rows from v3 Excel files, one per control row.
