# DevOps Security (DS) — User Stories

6 user stories: 6 pure v2.
Phase 25 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-DS] DevOps Security — MCSB v2

---

## [SEC-DS] DevOps Security — 6 Controls, 6 Stories

### 1 Conduct Threat Modeling [pure v2]

**[SEC-1] Conduct Threat Modeling**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess threat modeling process maturity — STRIDE methodology adoption for all new infrastructure and application designs, design-phase review timing (not post-deployment), threat model artifact storage in version-controlled repositories, tool usage (Microsoft Threat Modeling Tool or OWASP Threat Dragon), and annual review cadence for existing systems — so that DS-1 gaps in security design validation and threat modeling coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for threat modeling process controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on threat model documentation, version-controlled artifact storage, and design review record manual audit.

**Acceptance Criteria:**
- Threat modeling DS-1 process assessed against MCSB baseline and systems without STRIDE-based design reviews, threat models produced post-deployment rather than at design phase, or absent versioned threat model artifact storage identified.
- Azure Policy coverage for threat modeling controls evaluated; built-ins absent for this control — assessment relies on threat model documentation completeness, design review timing records, and version-controlled artifact repository manual audit.
- Gap findings documented with remediation scope and affected design review cadence, threat model artifact storage, STRIDE methodology adoption, and annual review coverage noted.

---

### 2 Ensure Software Supply Chain Security [pure v2]

**[SEC-2] Ensure Software Supply Chain Security**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess software supply chain security controls — dependency scanning integration (Dependabot or Defender for DevOps) in all CI pipelines, Software Composition Analysis as a CI gate, SBOM generation for all container builds, trusted registry enforcement (ACR with Notary v2 content trust only), package allowlist governance for npm, PyPI, and NuGet, and third-party library review process documentation — so that DS-2 gaps in supply chain integrity and dependency risk management are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for software supply chain security in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on CI pipeline dependency scanning configuration and SBOM generation coverage manual audit.

**Acceptance Criteria:**
- Supply chain security DS-2 configuration assessed against MCSB baseline and pipelines without dependency scanning enabled, missing SCA CI gate enforcement, absent SBOM generation for container builds, or container pulls from untrusted registries without Notary v2 content trust identified.
- Azure Policy coverage for supply chain controls evaluated; built-ins absent for this control — assessment relies on Dependabot or Defender for DevOps pipeline integration, SBOM generation pipeline steps, and ACR content trust configuration manual audit.
- Gap findings documented with remediation scope and affected pipeline dependency scanning coverage, SBOM generation, trusted registry enforcement, and package allowlist governance configurations noted.

---

### 3 Secure DevOps Infrastructure [pure v2]

**[SEC-3] Secure DevOps Infrastructure**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure DevOps organization security configuration — MFA enforcement for all ADO users, absence of PATs in code repositories (secret scanning active), PAT maximum expiry enforcement (90 days), pipeline service connection migration to Workload Identity Federation (no stored secrets), ADO audit log routing to Sentinel, private build agent VNet deployment, and ADO organization policy review (external access restrictions, project isolation) — so that DS-3 gaps in DevOps platform security and pipeline credential exposure are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure DevOps organization security configuration in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on ADO organization policy settings and pipeline service connection configuration manual audit.

**Acceptance Criteria:**
- DevOps infrastructure DS-3 configuration assessed against MCSB baseline and ADO organizations without MFA enforced, service connections using stored secrets instead of Workload Identity Federation, PATs in code repositories detected by secret scanning, or ADO audit logs not routed to Sentinel identified.
- Azure Policy coverage for DevOps infrastructure security evaluated; built-ins absent for this control — assessment relies on ADO organization policy settings, Workload Identity Federation adoption, secret scanning pipeline configuration, and ADO audit log routing manual audit.
- Gap findings documented with remediation scope and affected ADO organization MFA policy, PAT expiry enforcement, service connection credential types, private build agent network configuration, and Sentinel audit log routing noted.

---

### 4 Integrate Static Application Security Testing [pure v2]

**[SEC-4] Integrate Static Application Security Testing**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess SAST integration in CI pipelines — CodeQL deployment for application code scanning, Checkov for IaC scanning (Terraform, Bicep, and ARM), merge blocking on Critical SAST findings with no approved exceptions, secret detection via pre-commit hooks and pipeline scanning, Defender for DevOps IaC scanning integration, and SAST result triage and suppression governance process — so that DS-4 gaps in static security testing coverage and finding remediation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for SAST pipeline gate enforcement in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on CI pipeline SAST tool configuration and merge gate policy manual audit.

**Acceptance Criteria:**
- SAST integration DS-4 configuration assessed against MCSB baseline and pipelines without CodeQL or equivalent SAST tool, IaC pipelines without Checkov scanning, missing merge-blocking on Critical findings, or absent pre-commit and pipeline secret detection identified.
- Azure Policy coverage for SAST pipeline controls evaluated; built-ins absent for this control — assessment relies on CI pipeline SAST tool configuration, branch protection merge gate settings, and suppression approval governance manual audit.
- Gap findings documented with remediation scope and affected pipeline SAST tool coverage, IaC scanning configuration, merge gate enforcement, secret detection scope, and SAST finding suppression governance noted.

---

### 5 Integrate Dynamic Application Security Testing [pure v2]

**[SEC-5] Integrate Dynamic Application Security Testing**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess DAST integration in release pipelines — DAST scan execution on staging environments before production deployment (OWASP ZAP or equivalent), API security testing coverage against OWASP API Top 10, production release blocking on Critical DAST findings, DAST result tracking in ADO work items, and scan cadence for all internet-facing services (every release) — so that DS-5 gaps in dynamic security testing coverage and release gate enforcement are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for DAST pipeline integration in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on release pipeline DAST scan configuration and production gate policy manual audit.

**Acceptance Criteria:**
- DAST integration DS-5 configuration assessed against MCSB baseline and internet-facing services without DAST scans in staging, absent API security testing against OWASP API Top 10, missing production release blocking on Critical DAST findings, or DAST results not tracked in ADO identified.
- Azure Policy coverage for DAST pipeline controls evaluated; built-ins absent for this control — assessment relies on release pipeline DAST tool configuration, production gate blocking policy, and ADO DAST result tracking manual audit.
- Gap findings documented with remediation scope and affected pipeline DAST tool deployment, API security testing coverage, production release gate enforcement, and ADO work item tracking configurations noted.

---

### 6 Enforce Security of Workload Throughout DevOps Lifecycle [pure v2]

**[SEC-6] Enforce Security of Workload Throughout DevOps Lifecycle**
Parent: [SEC-DS] DevOps Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess CI/CD security gate completeness — all mandatory security gates present before production deployment (SAST, DAST, dependency scan, container image scan, IaC scan), branch protection policy enforcement (PR review required and pipeline pass), production deployment approval gate with second approver requirement, and weekly infrastructure drift detection comparing live state against IaC source — so that DS-6 gaps in end-to-end DevOps lifecycle security enforcement are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for CI/CD security gate enforcement in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on pipeline gate configuration, branch protection policy, and drift detection tooling manual audit.

**Acceptance Criteria:**
- CI/CD lifecycle DS-6 configuration assessed against MCSB baseline and pipelines missing any mandatory security gate (SAST, DAST, dependency, container image, or IaC scan), repositories without branch protection requiring PR review and pipeline pass, or production deployments without second-approver gate identified.
- Azure Policy coverage for CI/CD security gate controls evaluated; built-ins absent for this control — assessment relies on pipeline gate configuration, branch protection rule settings, production approval gate policy, and infrastructure drift detection cadence manual audit.
- Gap findings documented with remediation scope and affected pipeline security gate completeness, branch protection configurations, production approval gate setup, and weekly drift detection coverage noted.
