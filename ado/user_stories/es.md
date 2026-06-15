# Endpoint Security (ES) — User Stories

15 user stories: 14 combined (v2+v3, one per resource) + 1 pure v2.
Phase 23 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-ES] Endpoint Security — MCSB v2

---

## [SEC-ES] Endpoint Security — 3 Controls, 15 Stories

### 1 Use Endpoint Detection and Response (EDR) [5 combined]

**[SEC-1] Use Endpoint Detection and Response (EDR): Virtual Machines (Linux)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess MDE for Linux deployment and EDR configuration — Defender for Cloud auto-provisioning status for MDE on Linux VMs, EDR in Block mode enablement, MDE telemetry routing to Sentinel via data connector, real-time protection and threat detection active status, and onboarding compliance across all Linux VM instances — so that ES-1 gaps in Linux endpoint detection and response coverage are identified. Key Azure Policy built-ins applicable: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Endpoint protection health issues should be resolved on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Linux VM ES-1 configuration assessed against MCSB baseline and instances without MDE auto-provisioned via Defender for Cloud, missing EDR Block mode enablement, absent Sentinel telemetry routing, or real-time protection inactive identified.
- Azure Policy compliance evaluated for: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Endpoint protection health issues should be resolved on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected Linux VM MDE deployment, EDR Block mode, and Sentinel connector configurations noted.

---

**[SEC-1] Use Endpoint Detection and Response (EDR): Virtual Machines (Windows)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess MDE for Windows deployment and EDR configuration — Defender for Cloud auto-provisioning status for MDE on Windows VMs, EDR in Block mode enablement, Defender Antivirus real-time protection active, tamper protection enabled, MDE data connector to Sentinel configured, and onboarding compliance across all Windows VM instances — so that ES-1 gaps in Windows endpoint detection and response coverage are identified. Key Azure Policy built-ins applicable: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Endpoint protection health issues should be resolved on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Windows VM ES-1 configuration assessed against MCSB baseline and instances without MDE auto-provisioned, missing EDR Block mode, Defender Antivirus real-time protection inactive, tamper protection disabled, or absent Sentinel data connector identified.
- Azure Policy compliance evaluated for: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Endpoint protection health issues should be resolved on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected Windows VM MDE deployment, tamper protection status, and Sentinel connector configurations noted.

---

**[SEC-1] Use Endpoint Detection and Response (EDR): Virtual Machine Scale Sets**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess MDE deployment in VMSS configuration — MDE extension inclusion in the VMSS model definition (not just existing instances), auto-provisioning behavior for new scale-out instances, uniform EDR telemetry coverage from all active scale set instances, and VMSS security baseline alignment — so that ES-1 gaps in endpoint detection coverage across dynamically scaled workloads are identified. Key Azure Policy built-ins applicable: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Endpoint protection health issues should be resolved on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- VMSS ES-1 configuration assessed against MCSB baseline and scale sets without MDE extension in the model definition, new instances not automatically onboarded, or scale set instances with inconsistent EDR telemetry to Sentinel identified.
- Azure Policy compliance evaluated for: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Endpoint protection health issues should be resolved on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected VMSS model definition MDE extension, auto-provisioning scope, and telemetry coverage configurations noted.

---

**[SEC-1] Use Endpoint Detection and Response (EDR): Arc-enabled Servers**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess MDE onboarding for Arc-enabled servers — MDE deployment via Azure Arc policy extension across all Arc-registered servers, EDR telemetry routing to the same Sentinel workspace as Azure VMs, patch management via Azure Update Manager policy scope, and hybrid endpoint inventory visibility in Defender for Cloud — so that ES-1 gaps in EDR coverage for on-premises and multi-cloud servers managed through Arc are identified. Key Azure Policy built-ins applicable: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ⚠️ ["Configure Arc-enabled machines running Linux with Defender for Endpoint"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Arc-enabled Server ES-1 configuration assessed against MCSB baseline and Arc-registered servers without MDE Arc policy extension deployed, missing Sentinel workspace telemetry routing, or hybrid endpoints absent from Defender for Cloud inventory identified.
- Azure Policy compliance evaluated for: ["Endpoint protection should be installed on your machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference); ⚠️ Arc-specific MDE onboarding policy display name flagged for verification.
- Gap findings documented with remediation scope and affected Arc server MDE extension assignments, Sentinel workspace routing, and Defender for Cloud hybrid inventory configurations noted.

---

**[SEC-1] Use Endpoint Detection and Response (EDR): Arc-enabled Kubernetes**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Defender for Containers coverage on Arc-enabled Kubernetes clusters — Defender for Containers extension deployment on Arc-managed clusters, runtime threat detection enablement for workloads, Kubernetes audit log forwarding to Sentinel, and cluster security posture visibility in Defender for Cloud — so that ES-1 gaps in container endpoint detection and response coverage for Arc-managed Kubernetes are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Defender for Containers on Arc-managed Kubernetes in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Arc Kubernetes extension deployment and Defender for Cloud cluster posture manual audit.

**Acceptance Criteria:**
- Arc Kubernetes ES-1 configuration assessed against MCSB baseline and Arc-managed clusters without Defender for Containers extension, missing runtime threat detection, absent Kubernetes audit log routing to Sentinel, or clusters not visible in Defender for Cloud security posture identified.
- Azure Policy coverage for Defender for Containers on Arc Kubernetes evaluated; built-ins absent for this resource — assessment relies on Arc extension deployment status and Defender for Cloud cluster registration manual audit.
- Gap findings documented with remediation scope and affected Arc cluster Defender for Containers extension, runtime detection, audit log forwarding, and Defender for Cloud posture coverage configurations noted.

---

### 2 Use Modern Anti-Malware Software [pure v2]

**[SEC-2] Use Modern Anti-Malware Software**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess anti-malware coverage across all VM endpoints — Microsoft Defender Antivirus real-time protection and cloud-delivered protection status on all Windows VMs, Defender for Endpoint antimalware solution status on Linux VMs, scheduled scan policy configuration, antimalware exclusion documentation and review cadence (no broad folder exclusions), and weekly coverage compliance report availability — so that ES-2 gaps in anti-malware coverage completeness and exclusion hygiene are identified. Key Azure Policy built-ins applicable: ["Endpoint protection solution should be installed on virtual machine scale sets"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Monitor missing Endpoint Protection in Azure Security Center"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Anti-malware ES-2 configuration assessed against MCSB baseline and Windows VMs without Defender Antivirus real-time or cloud-delivered protection active, Linux VMs without Defender for Endpoint antimalware, absent scheduled scan policies, or undocumented and over-broad antimalware exclusions identified.
- Azure Policy compliance evaluated for: ["Endpoint protection solution should be installed on virtual machine scale sets"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Monitor missing Endpoint Protection in Azure Security Center"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected VM antimalware solution status, exclusion documentation, scan policy configurations, and coverage report availability noted.

---

### 3 Ensure Anti-Malware Software and Signatures Updated [9 combined]

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Container Registry**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Container Registry security controls — Defender for Containers registry scanning coverage, absence of known Critical CVEs in images tagged for production, Notary v2 content trust enforcement (signed images only pulled), and pull-through cache security policy configuration — so that ES-3 gaps in container image vulnerability management and supply chain integrity are identified. Key Azure Policy built-ins applicable: ["Container registry images should have vulnerability findings resolved"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Container Registry ES-3 configuration assessed against MCSB baseline and registries without Defender for Containers scanning enabled, production images with unresolved Critical CVEs, absent Notary v2 content trust enforcement, or pull-through cache without security policy identified.
- Azure Policy compliance evaluated for: ["Container registry images should have vulnerability findings resolved"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected registry scanning configuration, Critical CVE status, content trust enforcement, and pull-through cache policy configurations noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Container Instances**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Container Instances image security controls — image source restriction to trusted ACR only (no Docker Hub or public registry pulls), pre-deployment vulnerability scan evidence, absence of privileged container configurations, and runtime security coverage via Defender for Containers — so that ES-3 gaps in container instance image integrity and runtime protection are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for ACI pre-deployment image scanning in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on container group image source policy and runtime security coverage manual audit.

**Acceptance Criteria:**
- Container Instances ES-3 configuration assessed against MCSB baseline and container groups pulling images from untrusted registries, missing pre-deployment vulnerability scan evidence, privileged container configurations present, or absent Defender for Containers runtime coverage identified.
- Azure Policy coverage for ACI image security controls evaluated; built-ins absent for this resource — assessment relies on container group image source policy, vulnerability scan records, and Defender for Containers runtime configuration manual audit.
- Gap findings documented with remediation scope and affected container group image source policies, privileged container settings, and runtime security coverage configurations noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Kubernetes Service (AKS)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Kubernetes Service container security controls — Defender for Containers runtime threat protection enablement, container image scanning at registry and runtime, OPA Gatekeeper policy enforcement (deny latest tag, no privileged pods, resource limits required), and AppArmor and seccomp security profile deployment on AKS nodes — so that ES-3 gaps in AKS container workload security and image vulnerability management are identified. Key Azure Policy built-ins applicable: ["Kubernetes clusters should have vulnerability findings resolved"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Kubernetes cluster should not allow privileged containers"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- AKS ES-3 configuration assessed against MCSB baseline and clusters without Defender for Containers runtime protection, missing registry or runtime image scanning, absent OPA Gatekeeper constraints for privileged pods or resource limits, or nodes without AppArmor and seccomp profiles identified.
- Azure Policy compliance evaluated for: ["Kubernetes clusters should have vulnerability findings resolved"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Kubernetes cluster should not allow privileged containers"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected AKS Defender for Containers configuration, OPA Gatekeeper constraint templates, image scanning coverage, and node security profile deployments noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Kubernetes Service on Azure Stack HCI**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess AKS on Azure Stack HCI container security controls — Defender for Containers deployment on HCI-managed clusters, container image scanning coverage, Arc-managed security policy enforcement on HCI clusters, and HCI node OS update and patch management cadence — so that ES-3 gaps in container security for on-premises Kubernetes managed via HCI are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for AKS on Azure Stack HCI in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Defender for Containers HCI extension deployment and Arc-managed security policy coverage manual audit.

**Acceptance Criteria:**
- AKS on HCI ES-3 configuration assessed against MCSB baseline and HCI-managed clusters without Defender for Containers extension, missing container image scanning, absent Arc-managed security policy enforcement, or HCI nodes with unpatched OS identified.
- Azure Policy coverage for AKS on HCI container security evaluated; built-ins absent for this resource — assessment relies on HCI Defender for Containers extension deployment, Arc policy assignment scope, and HCI node patch management manual audit.
- Gap findings documented with remediation scope and affected HCI cluster Defender for Containers configuration, Arc policy assignments, and HCI node update cadence noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Red Hat OpenShift (ARO)**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Red Hat OpenShift container security controls — Defender for Containers integration with ARO cluster, container image registry scanning coverage, OCP Security Context Constraints enforcement on all workloads, and MDE deployment for node-level EDR on ARO compute — so that ES-3 gaps in ARO cluster container security and endpoint protection are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Red Hat OpenShift in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Defender for Containers ARO integration and OCP SCC configuration manual audit.

**Acceptance Criteria:**
- ARO ES-3 configuration assessed against MCSB baseline and clusters without Defender for Containers integration, missing image registry scanning, OCP Security Context Constraints not enforced across workloads, or ARO compute nodes without MDE node-level EDR identified.
- Azure Policy coverage for ARO container security evaluated; built-ins absent for this resource — assessment relies on Defender for Containers ARO integration status, OCP SCC policy enforcement, and MDE node coverage manual audit.
- Gap findings documented with remediation scope and affected ARO Defender for Containers configuration, OCP SCC enforcement, image scanning coverage, and MDE node deployment configurations noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Defender for IoT**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Microsoft Defender for IoT OT security controls — OT sensor deployment coverage on OT/ICS network segments, device inventory completeness for all discovered OT assets, anomaly detection enablement for ICS/SCADA protocol traffic (Modbus, DNP3, EtherNet/IP), and alert integration routing to Microsoft Sentinel — so that ES-3 gaps in OT/ICS network threat detection and device visibility are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Defender for IoT OT sensor deployment in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on OT sensor placement, device inventory completeness, and Sentinel integration manual audit.

**Acceptance Criteria:**
- Defender for IoT ES-3 configuration assessed against MCSB baseline and OT/ICS network segments without sensor coverage, incomplete device inventories, ICS protocol anomaly detection inactive, or OT alerts not routed to Sentinel identified.
- Azure Policy coverage for Defender for IoT OT sensor controls evaluated; built-ins absent for this resource — assessment relies on OT sensor network placement, device discovery completeness, protocol anomaly detection configuration, and Sentinel alert integration manual audit.
- Gap findings documented with remediation scope and affected OT network segment sensor coverage, device inventory gaps, ICS protocol detection configurations, and Sentinel routing noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: IoT Hub**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure IoT Hub device security controls — device attestation method coverage (TPM or X.509 certificates), DPS enrollment group security configuration, per-device credential enforcement (no shared symmetric keys across devices), and Defender for IoT integration for device anomaly detection — so that ES-3 gaps in IoT device authentication integrity and anomaly detection coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for IoT Hub device attestation controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on IoT Hub device registration policy and DPS enrollment group configuration manual audit.

**Acceptance Criteria:**
- IoT Hub ES-3 configuration assessed against MCSB baseline and hubs with devices using weak attestation methods, DPS enrollment groups without security hardening, shared symmetric key credential usage, or absent Defender for IoT anomaly detection integration identified.
- Azure Policy coverage for IoT Hub device security controls evaluated; built-ins absent for this resource — assessment relies on IoT Hub device registration policies, DPS enrollment group configuration, and Defender for IoT integration manual audit.
- Gap findings documented with remediation scope and affected device attestation methods, DPS enrollment security settings, per-device credential configurations, and Defender for IoT integration status noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: IoT Central**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure IoT Central device security configuration — device credential security standard (X.509 preferred over SAS tokens), role-based access separation between operator and administrator roles, data export encryption configuration, and Defender for IoT integration for device fleet monitoring — so that ES-3 gaps in IoT Central device credential security and fleet monitoring coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for IoT Central device credential security in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on IoT Central device template credential settings and RBAC configuration manual audit.

**Acceptance Criteria:**
- IoT Central ES-3 configuration assessed against MCSB baseline and applications with devices using SAS token credentials instead of X.509, missing operator/administrator RBAC separation, absent data export encryption, or inactive Defender for IoT fleet monitoring integration identified.
- Azure Policy coverage for IoT Central device security controls evaluated; built-ins absent for this resource — assessment relies on IoT Central device credential configuration, RBAC role assignments, and Defender for IoT integration manual audit.
- Gap findings documented with remediation scope and affected device credential standards, RBAC role separation, data export encryption, and fleet monitoring integration configurations noted.

---

**[SEC-3] Ensure Anti-Malware Software and Signatures Updated: Sphere**
Parent: [SEC-ES] Endpoint Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Sphere device security controls — OS security update enforcement configuration (automatic updates mandatory, no manual update override), certificate-based device authentication status, application allow-listing enforcement (signed apps only, no unsigned application execution), and Sphere Security Service fleet monitoring coverage — so that ES-3 gaps in Sphere device OS integrity and application control are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Sphere security controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Sphere Security Service configuration and OS update policy manual audit.

**Acceptance Criteria:**
- Azure Sphere ES-3 configuration assessed against MCSB baseline and device groups with manual OS update configuration permitted, devices using weak authentication instead of certificate-based auth, unsigned application execution allowed, or devices not covered by Sphere Security Service fleet monitoring identified.
- Azure Policy coverage for Azure Sphere device security controls evaluated; built-ins absent for this resource — assessment relies on Sphere Security Service device group OS update policy, certificate authentication configuration, and application signing enforcement manual audit.
- Gap findings documented with remediation scope and affected Sphere device group OS update settings, certificate authentication configurations, application allow-listing enforcement, and Sphere Security Service fleet coverage noted.
