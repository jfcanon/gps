# Plan: Phase 45 — PA + ES Domain Bulk

**Source**: Phase 45 autonomous bulk continuation
**Complexity**: Large (PA=140 rows/44 files, ES=244+ rows/77+ files)

## Summary

Apply Phase 43 dual-path pattern (PATH B = N/A reclassification, PATH A = script generation)
to two full MCSB v3 security domains: PA (Privileged Access) and ES (Endpoint Security).
All services, all rows, all committed. Generator approach from AM domain bulk reused.

## Patterns to Mirror

| Category | Source | Pattern |
|---|---|---|
| Generator | AM domain bulk (session, d7eef2f) | Python heredoc generator, 1 bash call = N×11 files |
| LIVE checks | `scripts/assessment/apimanagement/lt_apimanagement.py` | imports inside fn, try/except, base dict pattern |
| Static N/A | `scripts/assessment/apimanagement/es_apimanagement.py` | PATH B rationale in actual_value |
| Runner | `scripts/assessment/apimanagement/run_apimanagement_assessment.py` | CHECK_REGISTRY dict[str,Callable] |
| DiagSettings | `scripts/assessment/bastion/lt_bastion.py` | monitor.diagnostic_settings.list(resource_uri) |
| Defender plan | `scripts/assessment/resourcemanager/lt_resourcemanager.py` | pricings.get("PlanKey") |

## Files to Change

| Dir | Action | Count |
|---|---|---|
| `scripts/assessment/automation/` | CREATE | 11 |
| `scripts/assessment/azurelighthouse/` | CREATE | 11 |
| `scripts/assessment/cloudshell/` | CREATE | 11 |
| `scripts/assessment/customerlockbox/` | CREATE | 11 |
| `scripts/assessment/azuresphere/` | CREATE | 11 |
| `scripts/assessment/akshci/` | CREATE | 11 |
| `scripts/assessment/containerinstances/` | CREATE | 11 |
| `scripts/assessment/arck8s/` | CREATE | 11 |
| `scripts/assessment/arcservers/` | CREATE | 11 |
| `scripts/assessment/containerregistry/` | CREATE | 11 |
| `scripts/assessment/vmss/` | CREATE | 11 |
| `scripts/assessment/{6-missing-es-svcs}/` | CREATE | 66 |
| `ado/activity.log` | APPEND | — |

## Tasks

### Task 1: PA domain — 4 services (1 generator call)
- **Action**: Write Python generator with CONTROLS×PA_SERVICES matrix. LIVE overrides for automation (15 fn), lighthouse (3), cloudshell (2), customerlockbox (2).
- **Key facts**:
  - `automation`: AutomationClient. LT-4 = JobLogs+JobStreams DiagSettings. LT-1 = Defender for Arm. NS-2 = publicNetworkAccess + PE. MI via account.identity.type. RunAs SP = deprecated Sep 2023 → `now_applicable_native` in PATH B.
  - `azurelighthouse`: ManagedServicesClient. 32/35 N/A. LIVE: PA-7 RBAC on delegation, IM-1 AAD static_pass, IM-3 SP check delegation authorizations.
  - `cloudshell`: No resource-level ARM SDK. 33/35 N/A. LIVE: NS-2 PE check (VNet injection), IM-3 MI = live→UNKNOWN.
  - `customerlockbox`: 33/35 N/A. LIVE: PA-8 = GET .../providers/Microsoft.CustomerLockbox/enableLockbox. AM-2 = subscription tags.
- **Validate**: AST per file. 0 errors required.
- **Commit**: `feat: Phase 45 — PA domain assessment scripts (4 services, 140 rows)`

### Task 2: ES name resolution
- **Action**: Run step1_name_resolution query on v3 CSV. Identify exact csv_name for: virtual-machines, azure-kubernetes-service, azure-red-hat-openshift, defender-for-iot, azure-iot-hub, azure-iot-central.
- **Command**: `python3 -c "import csv; svcs=sorted(set(r['service_name'].strip() for r in csv.DictReader(open('data/outputs/v3_service_controls_reclassified.csv')))); [print(s) for s in svcs if any(k in s for k in ['virtual-machine','kubernetes','openshift','iot','sphere','defender','arc'])]"`
- **Validate**: List resolved names + row counts.

### Task 3: ES trivial + easy batch (azure-sphere + akshci)
- **Action**: Generator. azure-sphere = 35/35 N/A. akshci = 5 LIVE (MI, PE, tags, TLS static_pass, Defender for Kubernetes).
- **SDK akshci**: `azure-mgmt-hybridcontainerservice` (ProvisionedClustersClient).
- **Commit**: `feat: Phase 45 — ES domain batch 1 (azure-sphere, aks-hci)`

### Task 4: ES medium batch (container-instances + arc-kubernetes)
- **Action**: Generator. 10 LIVE each.
  - `containerinstances`: ContainerInstanceManagementClient. Checks: MI, tags, PE, TLS static_pass, no NSG/VNet (N/A PaaS container).
  - `arck8s`: ConnectedKubernetesClient. Checks: MI, PE, tags, Defender for Kubernetes (pricings.get("KubernetesService")), DiagSettings, RBAC.
- **Commit**: `feat: Phase 45 — ES domain batch 2 (container-instances, arc-kubernetes)`

### Task 5: ES high batch (arc-servers + container-registry)
- **Action**: Generator. 12-15 LIVE.
  - `arcservers`: HybridComputeManagementClient. Checks: extension list (MDE=ES-1, AMA=ES-2), MI, PE, DiagSettings, Defender for Servers (pricings.get("VirtualMachines")), RBAC.
  - `containerregistry`: ContainerRegistryManagementClient. Checks: MI, PE, disable public (publicNetworkAccess), CMK, Defender for Container Registries (pricings.get("ContainerRegistry")), DiagSettings, RBAC, TLS/DP-3 static_pass.
- **PATH B note**: ES-1 EDR, ES-2 antimalware — arc-servers v3 baseline says False but MDE auto-provision via Defender for Servers GA → classify as `now_applicable_native`.
- **Commit**: `feat: Phase 45 — ES domain batch 3 (arc-servers, container-registry)`

### Task 6: ES hardest batch (vmss — 27 LIVE)
- **Action**: Generator. ComputeManagementClient.virtual_machine_scale_sets.
  - 27 LIVE checks: MI, NSG, VNet, PE, disable public, DiagSettings (VMScaleSetBootDiagnostics), Defender for Servers, EDR/MDE extension, AMA extension, antimalware extension, update management, guest config, backup, CMK, AAD login extension, RBAC, tags, TLS static_pass, DP-4 static_pass, Lockbox UNKNOWN, LT-1 Defender for VMs.
  - 8 N/A: ES-3 antimalware health, PV-3 custom containers, DP-1 sensitive data, IM-5, some PA rows.
- **PATH B**: ES-1/ES-2 on VMSS — MDE/AMA now available via Defender for Servers auto-provisioning → `now_applicable_native`.
- **Commit**: `feat: Phase 45 — ES domain batch 4 (vmss, 27 LIVE checks)`

### Task 7: ES missing services (6 resolved names)
- **Action**: After Task 2 resolution, generate scripts for 6 remaining ES services (VM, AKS, ARO, IoT, etc.)
- **Complexity**: TBD based on resolved row counts.
- **Commit**: `feat: Phase 45 — ES domain batch 5 (resolved missing services)`

### Task 8: activity.log append
- **Action**: Append PA + ES domain completion summary to `ado/activity.log`. Append-only.

## Validation

```bash
# After each generator call:
for f in scripts/assessment/{slug}/*.py; do
  python3 -c "import ast; ast.parse(open('$f').read()); print('OK', '$f')"
done
# All must print OK. Zero SyntaxError allowed.
```

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| 6 ES services not in CSV under expected names | HIGH | Task 2 resolves before scripting |
| automation RunAs SP: deprecated → now_applicable_native classification | MEDIUM | Pre-decided: classify as now_applicable_native in PATH B |
| vmss 27 LIVE checks = very large generator template | HIGH | Split into batches; generator handles per-fn_suf override dict |
| Cloud Shell has no ARM resource SDK | MEDIUM | Use live→UNKNOWN for both LIVE rows; note reason in actual_value |
| ES-1/ES-2 on compute: False in v3 but now native via MDE | MEDIUM | Pre-decided: now_applicable_native with GA reference |

## Acceptance

- [ ] PA: 4 services committed, 44 files, all AST-clean
- [ ] ES: all 7 confirmed + resolved missing services committed
- [ ] PATH B: every False/N/A row classified with rationale
- [ ] `ado/activity.log` appended with PA + ES summary
- [ ] No files under `data/` committed (gitignored)

---

## AI-Executable Prompt (copy-paste to new session)

```json
{
  "phase": "45",
  "parts": ["PA-bulk", "ES-bulk"],
  "repo": "/Users/nahuelavalos/Repo/NewSecGap/",
  "pattern_reference": {
    "generator": "AM domain bulk commit d7eef2f — Python heredoc 1 bash call = 44 files",
    "live_checks": "scripts/assessment/apimanagement/ — imports inside fn, try/except",
    "diag_settings": "scripts/assessment/bastion/lt_bastion.py",
    "runner": "scripts/assessment/apimanagement/run_apimanagement_assessment.py"
  },
  "constraints": [
    "AST-only validation (no Azure SDK locally): python3 -c \"import ast; ast.parse(open('$f').read())\"",
    "data/inputs/ + data/outputs/ gitignored — never git add",
    "ado/activity.log append-only — never rewrite lines",
    "Generator: 1 bash call per batch. CONTROLS list × SERVICES dict with per-fn overrides."
  ],
  "domain_PA": {
    "services": [
      {"csv_name":"automation","slug":"automation","live":15,"na":20,"sdk":"azure-mgmt-automation.AutomationClient","path_b_flag":"IM-3 SP RunAs deprecated Sep 2023 → now_applicable_native"},
      {"csv_name":"azure-lighthouse","slug":"azurelighthouse","live":3,"na":32,"sdk":"azure-mgmt-managedservices.ManagedServicesClient"},
      {"csv_name":"cloud-shell","slug":"cloudshell","live":2,"na":33,"sdk":"none — live→UNKNOWN for both"},
      {"csv_name":"customer-lockbox-for-microsoft-azure","slug":"customerlockbox","live":2,"na":33,"sdk":"ARM REST Microsoft.CustomerLockbox/enableLockbox"}
    ],
    "commit": "feat: Phase 45 — PA domain assessment scripts (4 services, 140 rows)"
  },
  "domain_ES": {
    "step1_name_resolution": "python3 -c \"import csv; svcs=sorted(set(r['service_name'].strip() for r in csv.DictReader(open('data/outputs/v3_service_controls_reclassified.csv')))); [print(s) for s in svcs if any(k in s for k in ['virtual-machine','kubernetes','openshift','iot','sphere'])]\"",
    "services_confirmed": [
      {"csv_name":"azure-sphere","slug":"azuresphere","live":0,"na":35},
      {"csv_name":"azure-kubernetes-service-on-azure-stack-hci","slug":"akshci","live":5,"na":30,"sdk":"azure-mgmt-hybridcontainerservice"},
      {"csv_name":"container-instances","slug":"containerinstances","live":10,"na":25,"sdk":"azure-mgmt-containerinstance"},
      {"csv_name":"azure-arc-enabled-kubernetes","slug":"arck8s","live":10,"na":25,"sdk":"azure-mgmt-hybridkubernetes"},
      {"csv_name":"azure-arc-enabled-servers","slug":"arcservers","live":12,"na":23,"sdk":"azure-mgmt-hybridcompute","path_b_flag":"ES-1/ES-2 now_applicable_native via MDE Defender for Servers"},
      {"csv_name":"container-registry","slug":"containerregistry","live":15,"na":19,"sdk":"azure-mgmt-containerregistry","path_b_flag":"LT-1 Defender for ContainerRegistry GA → now_applicable_native"},
      {"csv_name":"virtual-machine-scale-sets","slug":"vmss","live":27,"na":8,"sdk":"azure-mgmt-compute","path_b_flag":"ES-1/ES-2 now_applicable_native via MDE auto-provision"}
    ],
    "services_missing": ["virtual-machines","azure-kubernetes-service","azure-red-hat-openshift","defender-for-iot","azure-iot-hub","azure-iot-central"],
    "batch_commits": [
      "feat: Phase 45 — ES batch 1 (azure-sphere, aks-hci)",
      "feat: Phase 45 — ES batch 2 (container-instances, arc-kubernetes)",
      "feat: Phase 45 — ES batch 3 (arc-servers, container-registry)",
      "feat: Phase 45 — ES batch 4 (vmss — 27 LIVE)",
      "feat: Phase 45 — ES batch 5 (resolved missing services)"
    ]
  }
}
```
