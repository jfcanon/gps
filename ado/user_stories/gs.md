# Governance and Strategy (GS) — User Stories

10 user stories: 3 combined (v2+v3, one per resource) + 7 pure v2.
Phase 26 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-GS] Governance and Strategy — MCSB v2

---

## [SEC-GS] Governance and Strategy — 10 Controls, 10 Stories

### 1 Align Organization Roles, Responsibilities, and Accountabilities [1 combined]

**[SEC-1] Align Organization Roles, Responsibilities, and Accountabilities: Cost Management**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Cost Management governance alignment — RBAC cost visibility configuration (Cost Management Reader assigned to engineering, no write access), budget alert coverage per subscription and department, cost anomaly detection enablement, and departmental cost chargeback RACI alignment with security domain owners — so that GS-1 gaps in cost accountability assignment and financial governance visibility are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Cost Management RBAC and budget governance in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Cost Management RBAC assignment and budget alert configuration manual audit.

**Acceptance Criteria:**
- Cost Management GS-1 configuration assessed against MCSB baseline and subscriptions with engineering teams lacking Cost Management Reader access, absent budget alerts at subscription or department scope, inactive cost anomaly detection, or unaligned chargeback RACI documentation identified.
- Azure Policy coverage for Cost Management governance controls evaluated; built-ins absent for this resource — assessment relies on Cost Management RBAC role assignment scope, budget alert configuration, and cost anomaly detection enablement manual audit.
- Gap findings documented with remediation scope and affected RBAC role assignments, budget alert coverage, cost anomaly detection configuration, and chargeback RACI documentation noted.

---

### 2 Define and Implement Enterprise Segmentation Strategy [pure v2]

**[SEC-2] Define and Implement Enterprise Segmentation Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess enterprise segmentation strategy implementation — management group hierarchy alignment with business units and environment tiers, separate subscription enforcement for production, development, and sandbox environments, landing zone design enforcement via Azure Blueprints or Terraform, separation of duties controls (DevOps cannot approve own PRs or deploy to production without second approval), and annual segmentation policy documentation review — so that GS-2 gaps in enterprise boundary enforcement and privilege separation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for enterprise segmentation strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on management group hierarchy, subscription structure, and landing zone configuration manual audit.

**Acceptance Criteria:**
- Enterprise segmentation GS-2 strategy assessed against MCSB baseline and environments with misaligned management group hierarchy, shared subscriptions across production and non-production workloads, landing zones without enforced design templates, or absent separation of duties controls for production deployments identified.
- Azure Policy coverage for enterprise segmentation strategy controls evaluated; built-ins absent for this control — assessment relies on management group hierarchy design, subscription isolation review, and landing zone enforcement configuration manual audit.
- Gap findings documented with remediation scope and affected management group alignment, subscription boundary configuration, landing zone template enforcement, and separation of duties control coverage noted.

---

### 3 Define and Implement Data Protection Strategy [pure v2]

**[SEC-3] Define and Implement Data Protection Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess data protection strategy completeness — four-tier data classification policy (Public, Internal, Confidential, Restricted), encryption requirements defined per classification tier, data residency requirements documented and mapped to Azure regions, key management policy (CMK required for Confidential and Restricted data), DLP policy coverage objective, and annual strategy review cadence after regulatory changes — so that GS-3 gaps in data governance framework completeness and classification enforcement are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for data protection strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on data classification policy documentation and encryption standard definition manual audit.

**Acceptance Criteria:**
- Data protection strategy GS-3 assessed against MCSB baseline and environments without a documented four-tier classification policy, undefined encryption requirements per data tier, undocumented data residency requirements, or absent CMK key management policy for Confidential and Restricted data identified.
- Azure Policy coverage for data protection strategy controls evaluated; built-ins absent for this control — assessment relies on data classification policy documentation, per-tier encryption requirement mapping, and CMK policy definition manual audit.
- Gap findings documented with remediation scope and affected data classification tier definitions, encryption requirement coverage, data residency documentation, CMK policy scope, and annual review cadence noted.

---

### 4 Define and Implement Network Security Strategy [pure v2]

**[SEC-4] Define and Implement Network Security Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess network security strategy documentation and implementation alignment — zero-trust network principles adoption, private-by-default configuration standard for all PaaS services, hub-spoke topology as the enforced architecture standard, internet egress restriction to Azure Firewall Premium only, network governance via Azure Virtual Network Manager security admin rules, and annual strategy review after major architecture changes — so that GS-4 gaps in network security governance and architecture standard adherence are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for network security strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on network architecture documentation and AVNM security admin rule coverage manual audit.

**Acceptance Criteria:**
- Network security strategy GS-4 assessed against MCSB baseline and environments without documented zero-trust network principles, PaaS services with public network access enabled by default, deployments outside hub-spoke topology without documented exception, or internet egress paths bypassing Azure Firewall Premium identified.
- Azure Policy coverage for network security strategy controls evaluated; built-ins absent for this control — assessment relies on network strategy documentation completeness, hub-spoke topology enforcement, and AVNM security admin rule assignment manual audit.
- Gap findings documented with remediation scope and affected network topology compliance, PaaS private-by-default configuration, Azure Firewall egress coverage, and AVNM security admin rule governance noted.

---

### 5 Define and Implement Security Posture Management Strategy [1 combined]

**[SEC-5] Define and Implement Security Posture Management Strategy: Policy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess security posture management strategy implementation via Azure Policy — MCSB v2 initiative assignment at management group scope, Regulatory Compliance dashboard review cadence (monthly minimum), Secure Score baseline tracking and target definition, risk acceptance process documentation for policy deviations, and deviation approval workflow governance — so that GS-5 gaps in posture management coverage and compliance governance framework are identified. Key Azure Policy built-ins applicable: ⚠️ ["MCSB initiative should be assigned at management group scope"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Security posture management GS-5 configuration assessed against MCSB baseline and management groups without MCSB v2 initiative assigned, environments without monthly Regulatory Compliance dashboard review evidence, absent Secure Score target documentation, or policy deviation risk acceptance process not documented identified.
- Azure Policy compliance evaluated for MCSB v2 initiative assignment coverage; ⚠️ MCSB initiative display name flagged for verification against current MCSB v2 preview policy list.
- Gap findings documented with remediation scope and affected MCSB v2 initiative assignment scope, compliance dashboard review cadence, Secure Score target configuration, and risk acceptance workflow documentation noted.

---

### 6 Define and Implement Identity and Privileged Access Strategy [pure v2]

**[SEC-6] Define and Implement Identity and Privileged Access Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess identity and privileged access strategy completeness — Entra ID as the sole identity provider with no alternative IdP configurations, PIM coverage for all privileged role assignments (zero standing access), phishing-resistant MFA (FIDO2) enforcement for all administrative accounts, passwordless adoption roadmap with target timeline, identity governance maturity model documentation, and annual strategy review cadence — so that GS-6 gaps in identity strategy alignment and privileged access governance are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for identity strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Entra ID configuration, PIM coverage, and identity strategy documentation manual audit.

**Acceptance Criteria:**
- Identity strategy GS-6 assessed against MCSB baseline and environments with non-Entra ID identity providers active, privileged roles without PIM eligibility coverage, administrative accounts without FIDO2 phishing-resistant MFA, or absent passwordless adoption roadmap identified.
- Azure Policy coverage for identity strategy controls evaluated; built-ins absent for this control — assessment relies on Entra ID sole-IdP configuration, PIM role coverage, FIDO2 authentication policy, and identity governance maturity documentation manual audit.
- Gap findings documented with remediation scope and affected IdP configuration, PIM privileged role coverage, FIDO2 MFA adoption status, passwordless roadmap timeline, and identity governance maturity model noted.

---

### 7 Define and Implement Logging, Threat Detection and IR Strategy [pure v2]

**[SEC-7] Define and Implement Logging, Threat Detection and IR Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess logging, threat detection, and incident response strategy documentation — centralized Sentinel workspace coverage, log retention policy enforcement (90-day interactive and 1-year archive), threat detection coverage map aligned to all MCSB v2 domains, Sentinel as SOAR with playbook library, MTTD and MTTR metric tracking, and annual strategy review after major incidents — so that GS-7 gaps in security operations strategy completeness and metric-driven improvement are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for logging and IR strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Sentinel workspace configuration and IR strategy documentation manual audit.

**Acceptance Criteria:**
- Logging and IR strategy GS-7 assessed against MCSB baseline and environments without centralized Sentinel workspace, log retention below 90-day interactive or 1-year archive thresholds, absent threat detection coverage map against MCSB v2 domains, or IR strategy without documented MTTD and MTTR baseline metrics identified.
- Azure Policy coverage for logging and IR strategy controls evaluated; built-ins absent for this control — assessment relies on Sentinel workspace data coverage, log retention workspace settings, playbook library coverage, and MTTD/MTTR tracking documentation manual audit.
- Gap findings documented with remediation scope and affected Sentinel workspace consolidation, log retention tier configuration, MCSB v2 threat detection coverage mapping, and IR metric tracking documentation noted.

---

### 8 Define and Implement Backup and Recovery Strategy [1 combined]

**[SEC-8] Define and Implement Backup and Recovery Strategy: Managed Applications**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Managed Applications security controls — publisher identity verification process before deployment approval, managed resource group lock enforcement (deny customer modification of managed resources), application definition security review completeness, and managed identity usage for automation within managed applications (no stored credentials) — so that GS-8 gaps in managed application supply chain security and resource protection are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Managed Applications publisher verification in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on managed application deployment approval process and managed resource group lock configuration manual audit.

**Acceptance Criteria:**
- Managed Applications GS-8 configuration assessed against MCSB baseline and environments deploying managed applications without publisher identity verification, managed resource groups without deny-modification lock, application definitions without security review documentation, or managed applications using stored credentials instead of managed identity identified.
- Azure Policy coverage for Managed Applications security controls evaluated; built-ins absent for this resource — assessment relies on managed application deployment approval records, managed resource group lock configuration, and managed identity automation configuration manual audit.
- Gap findings documented with remediation scope and affected managed application publisher verification process, managed resource group lock status, application definition security review records, and managed identity credential configuration noted.

---

### 9 Define and Implement Endpoint Security Strategy [pure v2]

**[SEC-9] Define and Implement Endpoint Security Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess endpoint security strategy completeness — MDE deployment standard for all VMs with EDR telemetry routing to Sentinel, patch SLA definitions (Critical 48-hour, High 7-day), Defender for Containers strategy for container workloads, endpoint lifecycle process (golden image, hardened baseline, decommission), PAW strategy for all privileged users, and annual strategy review — so that GS-9 gaps in endpoint security governance framework and strategy adherence are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for endpoint security strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on endpoint strategy documentation and MDE coverage configuration manual audit.

**Acceptance Criteria:**
- Endpoint security strategy GS-9 assessed against MCSB baseline and environments without documented MDE deployment standard, absent patch SLA definitions for Critical and High CVEs, container workloads without Defender for Containers strategy, or privileged users without PAW strategy documented identified.
- Azure Policy coverage for endpoint security strategy controls evaluated; built-ins absent for this control — assessment relies on endpoint strategy documentation completeness, MDE deployment scope, patch SLA definition, and PAW strategy documentation manual audit.
- Gap findings documented with remediation scope and affected MDE coverage standard, patch SLA documentation, Defender for Containers strategy scope, endpoint lifecycle process, and PAW strategy coverage noted.

---

### 10 Define and Implement DevOps Security Strategy [pure v2]

**[SEC-10] Define and Implement DevOps Security Strategy**
Parent: [SEC-GS] Governance and Strategy — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess DevSecOps strategy completeness — shift-left security implementation (SAST and DAST integrated in CI pipelines), IaC security scanning standard, software supply chain security controls (SBOM generation, signed images via Notary v2), security champion program maturity, security gate enforcement (no Critical findings shipped to production), and DevSecOps roadmap (zero-secret pipelines, signed commits, SLSA Level 2 target) — so that GS-10 gaps in DevOps security governance framework and shift-left adoption are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for DevOps security strategy documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on DevSecOps strategy documentation and CI/CD pipeline security gate configuration manual audit.

**Acceptance Criteria:**
- DevOps security strategy GS-10 assessed against MCSB baseline and environments without documented shift-left security standards, CI pipelines without mandatory SAST and DAST gates, absent SBOM generation or image signing requirements, or security champion program not established identified.
- Azure Policy coverage for DevOps security strategy controls evaluated; built-ins absent for this control — assessment relies on DevSecOps strategy documentation completeness, CI/CD pipeline security gate configuration, SBOM generation pipeline integration, and security champion program maturity manual audit.
- Gap findings documented with remediation scope and affected shift-left security standard adoption, CI/CD security gate completeness, supply chain security controls, security champion program coverage, and DevSecOps roadmap progress noted.
