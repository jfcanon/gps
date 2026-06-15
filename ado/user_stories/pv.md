# Posture and Vulnerability Management (PV) — User Stories

7 user stories: 2 combined (v2+v3, one per resource) + 5 pure v2.
Phase 22 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-PV] Posture and Vulnerability Management — MCSB v2

---

## [SEC-PV] Posture and Vulnerability Management — 7 Controls, 7 Stories

### 1 Run Automated Vulnerability Scans [1 combined]

**[SEC-1] Run Automated Vulnerability Scans: Defender for Cloud**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Defender for Cloud vulnerability scanning coverage — Defender for Servers P2 enablement with integrated vulnerability assessment solution (Qualys or MDE-based), Secure Score baseline and critical finding coverage, Critical CVE (CVSS ≥9.0) patch SLA adherence (48-hour), High CVE (CVSS 7.0–8.9) patch SLA adherence (7-day), and container image vulnerability findings resolution via Defender for Containers — so that PV-1 gaps in automated vulnerability detection coverage and remediation SLA compliance are identified. Key Azure Policy built-ins applicable: ["Vulnerability assessment solution should be enabled on your virtual machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["A vulnerability assessment solution should be enabled on virtual machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Container registry images should have vulnerability findings resolved"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Defender for Cloud PV-1 configuration assessed against MCSB baseline and subscriptions without Defender for Servers P2 integrated VA solution, VMs with unresolved Critical CVEs beyond 48-hour SLA, or container registries with unresolved High/Critical image vulnerabilities identified.
- Azure Policy compliance evaluated for: ["Vulnerability assessment solution should be enabled on your virtual machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["A vulnerability assessment solution should be enabled on virtual machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Container registry images should have vulnerability findings resolved"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected VA solution deployment, CVE SLA breach instances, and container image vulnerability configurations noted.

---

### 2 Run Automated OS Patch Management [pure v2]

**[SEC-2] Run Automated OS Patch Management**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Update Manager patch coverage — patch assessment and deployment schedule configuration for all Windows and Linux VMs, maintenance window definition per environment tier, critical patch deployment SLA adherence (48-hour), monthly patch compliance report generation, and Arc-enabled server coverage under the same Update Manager policy scope — so that PV-2 gaps in automated OS patching consistency and SLA compliance across hybrid infrastructure are identified. Key Azure Policy built-ins applicable: ["System updates should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ⚠️ ["Configure periodic checking for missing system updates on azure virtual machines"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Azure Update Manager PV-2 configuration assessed against MCSB baseline and VMs without active patch assessment schedules, environments without defined maintenance windows, critical patch SLA breaches, or Arc-enabled servers excluded from Update Manager policy scope identified.
- Azure Policy compliance evaluated for: ["System updates should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference); ⚠️ Update Manager schedule policy display name flagged for verification.
- Gap findings documented with remediation scope and affected VM patch schedules, maintenance window configurations, and Arc-enabled server Update Manager policy coverage noted.

---

### 3 Establish Secure Configurations for Compute Resources [pure v2]

**[SEC-3] Establish Secure Configurations for Compute Resources**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess secure baseline configuration coverage for compute resources — CIS Benchmark Level 1 application status for all Windows and Linux VMs, golden VM image hardening (unnecessary services disabled, pre-hardened OS), Azure Machine Configuration (Guest Policy) continuous OS configuration assessment deployment, container base image standards (distroless or hardened baseline), and AKS security profile enablement (AppArmor and seccomp profiles) — so that PV-3 gaps in compute baseline hardening and configuration standard adherence are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for CIS Benchmark Machine Configuration baselines in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Azure Machine Configuration Guest Policy assignment and golden image build pipeline manual audit.

**Acceptance Criteria:**
- Secure configuration PV-3 baseline assessed across compute resources and VMs without CIS Level 1 benchmark application, environments without golden image hardening standards, or AKS clusters without AppArmor and seccomp security profiles enabled identified.
- Azure Policy coverage for compute secure configuration baselines evaluated; built-ins absent for this control — assessment relies on Azure Machine Configuration Guest Policy assignment scope and AKS security profile configuration manual audit.
- Gap findings documented with remediation scope and affected VM image hardening, Machine Configuration Guest Policy assignments, container base image standards, and AKS security profile configurations noted.

---

### 4 Audit and Enforce Secure Configurations for Compute Resources [pure v2]

**[SEC-4] Audit and Enforce Secure Configurations for Compute Resources**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Policy Machine Configuration enforcement coverage — CIS benchmark audit and enforce policy assignment scope across VMs, automated remediation task scheduling for non-compliant resources, Defender for Cloud recommendation remediation workflow integration, and container security OPA Gatekeeper policy deployment on AKS (deny privileged pods, require resource limits) — so that PV-4 gaps in continuous configuration compliance enforcement and deviation remediation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Machine Configuration audit/enforce CIS benchmarks in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Azure Policy Machine Configuration assignment and OPA Gatekeeper constraint template manual audit.

**Acceptance Criteria:**
- Machine Configuration enforcement PV-4 configuration assessed against MCSB baseline and VMs without audit/enforce CIS benchmark policy assignments, environments without automated remediation tasks for non-compliant resources, or AKS clusters without OPA Gatekeeper constraints for privileged pod denial and resource limits identified.
- Azure Policy coverage for Machine Configuration CIS enforcement evaluated; built-ins absent for this control — assessment relies on Azure Policy Machine Configuration assignment scope and OPA Gatekeeper constraint template coverage manual audit.
- Gap findings documented with remediation scope and affected Machine Configuration policy assignments, remediation task schedules, and AKS OPA Gatekeeper constraint configurations noted.

---

### 5 Perform Vulnerability Assessments [1 combined]

**[SEC-5] Perform Vulnerability Assessments: Advisor**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Advisor security recommendation governance — security recommendation review cadence and remediation tracking (ADO work item integration), recommendation suppression governance (no suppression without documented approval), and integration completeness with Defender for Cloud security recommendation feed — so that PV-5 gaps in vulnerability assessment follow-through and suppression control are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Advisor security recommendation governance in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Advisor recommendation review cadence and suppression approval documentation manual audit.

**Acceptance Criteria:**
- Azure Advisor PV-5 configuration assessed against MCSB baseline and subscriptions with stale unaddressed security recommendations, unapproved recommendation suppressions, or absent ADO work item integration for recommendation remediation tracking identified.
- Azure Policy coverage for Advisor recommendation governance evaluated; built-ins absent for this resource — assessment relies on Advisor recommendation review records, suppression approval documentation, and ADO integration configuration manual audit.
- Gap findings documented with remediation scope and affected recommendation categories, suppression approval records, and ADO remediation tracking workflow configurations noted.

---

### 6 Rapidly and Automatically Remediate Vulnerabilities [pure v2]

**[SEC-6] Rapidly and Automatically Remediate Vulnerabilities**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess automated vulnerability remediation workflow coverage — Defender for Cloud one-click fix availability and usage for applicable recommendations, Azure Policy remediation task scheduling for non-compliant resources, Critical and High CVE to ADO work item automation pipeline status, and container image rebuild automation triggered by base image CVE detection via ACR Task triggers — so that PV-6 gaps in remediation speed and automation coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for automated vulnerability remediation workflows in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Defender for Cloud remediation task configuration and ACR Task trigger manual audit.

**Acceptance Criteria:**
- Automated remediation PV-6 configuration assessed against MCSB baseline and recommendations without one-click fix coverage, non-compliant resources without scheduled remediation tasks, absent CVE-to-ADO work item automation, or container registries without ACR Task-triggered image rebuild on base CVE detection identified.
- Azure Policy coverage for automated remediation workflows evaluated; built-ins absent for this control — assessment relies on Defender for Cloud one-click fix availability, remediation task scheduling, and ACR Task trigger configuration manual audit.
- Gap findings documented with remediation scope and affected Defender for Cloud recommendation types, remediation task schedules, CVE automation pipeline, and ACR Task trigger configurations noted.

---

### 7 Conduct Regular Red Team Operations [pure v2]

**[SEC-7] Conduct Regular Red Team Operations**
Parent: [SEC-PV] Posture and Vulnerability Management — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess red team exercise program maturity — annual red team exercise scope documentation (external attack surface, identity attack paths, lateral movement from compromised workload), purple team follow-up cadence for detection coverage gap remediation, Defender for Cloud attack path analysis and exposure management review status, and attack surface reduction metric tracking — so that PV-7 gaps in proactive security validation and detection coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for red team operations in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on red team exercise documentation and Defender for Cloud attack path analysis manual audit.

**Acceptance Criteria:**
- Red team exercise PV-7 program assessed against MCSB baseline and environments without documented annual red team exercises, absent purple team follow-up remediation records, or Defender for Cloud attack path analysis unused for exposure management identified.
- Azure Policy coverage for red team operation controls evaluated; built-ins absent for this control — assessment relies on red team exercise scope documentation, purple team remediation records, and Defender for Cloud attack path analysis coverage manual audit.
- Gap findings documented with remediation scope and affected red team scope coverage, detection gap remediation records, and attack surface metric tracking configurations noted.
