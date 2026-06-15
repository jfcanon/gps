# Network Security (NS) — User Stories

52 user stories: 50 combined (v2+v3, one per resource) + 2 pure v2.
Phase 15 — Final polish: +20% description (policy sentence), Option C Acceptance Criteria (config/policy/gap), Task Source removed.
Parent Feature: [SEC-NS] Network Security — MCSB v2

---

## [SEC-NS] Network Security — 10 Controls, 52 Stories

### 1 Establish Network Segmentation Boundaries [7 combined]

**[SEC-1] Establish Network Segmentation Boundaries: Virtual Network**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Virtual Network segmentation controls — subnet NSG associations, address space isolation, AVNM admin rules, and hub-spoke peering configuration — so that NS-1 baseline gaps are identified and documented for remediation planning. Key Azure Policy built-ins applicable: "Subnets should be private", "Flow logs should be configured for every network security group".

**Acceptance Criteria:**
- Virtual Network NS-1 configuration assessed against MCSB baseline and deviations from network segmentation standards identified.
- Azure Policy compliance evaluated for: "Subnets should be private", "Flow logs should be configured for every network security group".
- Gap findings documented with remediation scope and affected Virtual Network instances noted.

---

**[SEC-1] Establish Network Segmentation Boundaries: Virtual Network NAT**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Virtual Network NAT outbound configuration — SNAT subnet coverage completeness, public IP prefix management, and port exhaustion alerting — so that segmentation gaps from subnets relying on deprecated default outbound internet access are surfaced before Azure retires default outbound. Key Azure Policy built-ins applicable: ⚠️ "Network interfaces should not have public IPs" (adjacent control — no confirmed NAT Gateway-specific built-in as of MCSB v2 preview).

**Acceptance Criteria:**
- Virtual Network NAT NS-1 configuration assessed against MCSB baseline and subnets without explicit outbound path identified.
- Azure Policy compliance evaluated for applicable public IP and subnet controls across NAT-associated resources.
- Gap findings documented with remediation scope and affected subnet and NAT Gateway instances noted.

---

**[SEC-1] Establish Network Segmentation Boundaries: Virtual WAN**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Virtual WAN hub segmentation — secured hub deployment status, route intent policy coverage, and branch-to-branch isolation configuration — so that spoke-to-spoke lateral traffic paths that bypass hub firewall inspection are identified against NS-1 baseline. Key Azure Policy built-ins applicable: "Virtual Hubs should be protected with Azure Firewall".

**Acceptance Criteria:**
- Virtual WAN NS-1 configuration assessed against MCSB baseline and hubs without Azure Firewall secured-hub configuration identified.
- Azure Policy compliance evaluated for: "Virtual Hubs should be protected with Azure Firewall".
- Gap findings documented with remediation scope and affected Virtual WAN hub instances noted.

---

**[SEC-1] Establish Network Segmentation Boundaries: Load Balancer**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Load Balancer network configuration — internal vs external frontend assignment, Standard SKU compliance, and backend pool subnet NSG restrictions — so that NS-1 gaps where internal workloads are exposed via external or Basic SKU load balancer configurations are identified. Key Azure Policy built-ins applicable: ⚠️ "Load balancers should have diagnostic logs enabled" (logging adjacent — no confirmed NS-1-specific Load Balancer built-in as of MCSB v2 preview).

**Acceptance Criteria:**
- Load Balancer NS-1 configuration assessed against MCSB baseline and externally-fronted internal workloads or Basic SKU instances identified.
- Azure Policy compliance evaluated for applicable SKU and diagnostic controls across Load Balancer resources.
- Gap findings documented with remediation scope and affected Load Balancer frontend configurations noted.

---

**[SEC-1] Establish Network Segmentation Boundaries: Traffic Manager**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Traffic Manager endpoint configuration — HTTPS-only protocol enforcement, geographic routing isolation, and health probe settings — so that NS-1 gaps where unencrypted endpoints or cross-region data residency deviations are present are documented. Key Azure Policy built-ins applicable: ⚠️ "Traffic Manager profiles should have HTTPS protocol configured" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Traffic Manager NS-1 configuration assessed against MCSB baseline and HTTP-only endpoints or misconfigured geographic routing identified.
- Azure Policy compliance evaluated for HTTPS protocol enforcement controls applicable to Traffic Manager profiles.
- Gap findings documented with remediation scope and affected Traffic Manager profile and endpoint configurations noted.

---

**[SEC-1] Establish Network Segmentation Boundaries: Peering Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Peering Service route configuration — prefix filters, BGP community tagging, and unauthorized route change alerting — so that NS-1 gaps in peering route security are identified before unauthorized advertisements affect Azure-bound traffic paths. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure Policy built-ins for Azure Peering Service in MCSB v2 preview — assessment relies on manual BGP prefix and route filter review.

**Acceptance Criteria:**
- Peering Service NS-1 configuration assessed against MCSB baseline and missing prefix filters or unapproved route advertisements identified.
- Azure Policy coverage for Peering Service controls evaluated; gaps in policy automation noted where built-ins are absent.
- Gap findings documented with remediation scope and affected Peering Service and prefix configuration instances noted.

---

**[SEC-1] Establish Network Segmentation Boundaries: NAT Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess NAT Gateway subnet association completeness and operational configuration — public IP prefix rotation policy, SNAT port exhaustion alerts, and idle timeout settings — so that NS-1 segmentation gaps from uncovered subnets and SNAT exhaustion risks are identified and documented. Key Azure Policy built-ins applicable: ⚠️ No confirmed NAT Gateway-specific built-in as of MCSB v2 preview — assessment relies on subnet-level policy and manual NAT Gateway association audit.

**Acceptance Criteria:**
- NAT Gateway NS-1 configuration assessed against MCSB baseline and subnets lacking explicit NAT Gateway association identified.
- Azure Policy coverage for NAT Gateway controls evaluated; gaps in automated subnet outbound path compliance noted.
- Gap findings documented with remediation scope and affected NAT Gateway and subnet association instances noted.

---

### 2 Secure Cloud Native Services with Network Controls [27 combined]

**[SEC-2] Secure Cloud Native Services: App Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess App Service network controls — VNet integration, private endpoint, inbound access restrictions, HTTPS-only enforcement, TLS minimum version, and FTP exposure — so that NS-2 gaps where app workloads are reachable over public networks or unencrypted channels are identified across all App Service deployments. Key Azure Policy built-ins applicable: "App Service apps should only be accessible over HTTPS", "App Service apps should use the latest TLS version".

**Acceptance Criteria:**
- App Service NS-2 configuration assessed against MCSB baseline and apps without private endpoint, VNet integration, or HTTPS-only enforcement identified.
- Azure Policy compliance evaluated for: "App Service apps should only be accessible over HTTPS", "App Service apps should use the latest TLS version".
- Gap findings documented with remediation scope and affected App Service plan and site instances noted.

---

**[SEC-2] Secure Cloud Native Services: Cache for Redis**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Cache for Redis network isolation — non-SSL port 6379 status, TLS minimum version, public network access, and private endpoint or VNet injection configuration — so that NS-2 gaps exposing Redis data over unencrypted or unrestricted public channels are identified. Key Azure Policy built-ins applicable: "Azure Cache for Redis should disable public network access", "Azure Cache for Redis should use private link".

**Acceptance Criteria:**
- Cache for Redis NS-2 configuration assessed against MCSB baseline and instances with public access enabled or non-SSL port active identified.
- Azure Policy compliance evaluated for: "Azure Cache for Redis should disable public network access", "Azure Cache for Redis should use private link".
- Gap findings documented with remediation scope and affected Redis instance and tier configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Cognitive Search**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Cognitive Search network posture — private endpoint, public network access, IP firewall rules, and API key vs managed identity authentication — so that NS-2 gaps where search service data is accessible over public endpoints or via unauthenticated connections are documented. Key Azure Policy built-ins applicable: "Azure Cognitive Search services should disable public network access", "Azure Cognitive Search service should use private link".

**Acceptance Criteria:**
- Cognitive Search NS-2 configuration assessed against MCSB baseline and services with public network access or API key authentication identified.
- Azure Policy compliance evaluated for: "Azure Cognitive Search services should disable public network access", "Azure Cognitive Search service should use private link".
- Gap findings documented with remediation scope and affected Search service instances noted.

---

**[SEC-2] Secure Cloud Native Services: Communication Services**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Communication Services access configuration — managed identity authentication, API access scoping, data residency, and diagnostic log routing — so that NS-2 gaps in authentication controls and network access for this service are identified. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure Communication Services-specific policy built-ins in MCSB v2 preview — assessment relies on Defender for Cloud recommendations and manual configuration audit.

**Acceptance Criteria:**
- Communication Services NS-2 configuration assessed against MCSB baseline and instances lacking managed identity authentication or diagnostic logging identified.
- Azure Policy coverage for Communication Services controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected Communication Services resource instances noted.

---

**[SEC-2] Secure Cloud Native Services: Communications Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Communications Gateway network security — SIP signaling TLS configuration, admin plane access restrictions, and carrier network BGP peering authentication — so that NS-2 gaps in SIP transport security and management plane exposure are identified. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure Communications Gateway-specific policy built-ins in MCSB v2 preview — assessment relies on SIP and BGP configuration manual review.

**Acceptance Criteria:**
- Communications Gateway NS-2 configuration assessed against MCSB baseline and SIP instances without TLS enforcement or restricted admin access identified.
- Azure Policy coverage for Communications Gateway controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected Communications Gateway deployment instances noted.

---

**[SEC-2] Secure Cloud Native Services: Container Apps**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Container Apps environment network isolation — VNet integration, internal-only ingress configuration, private DNS zone linkage, and environment-level isolation — so that NS-2 gaps where container workloads are reachable via public FQDN without restriction are identified. Key Azure Policy built-ins applicable: ⚠️ "Container Apps environments should use network injection" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Container Apps NS-2 configuration assessed against MCSB baseline and environments without VNet injection or internal ingress configuration identified.
- Azure Policy compliance evaluated for network isolation controls applicable to Container Apps environments.
- Gap findings documented with remediation scope and affected Container Apps environment and app instances noted.

---

**[SEC-2] Secure Cloud Native Services: Data Factory**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Data Factory network controls — managed private endpoints for linked services, self-hosted IR VNet placement, and public network access on the ADF authoring surface — so that NS-2 gaps where pipeline data movement traverses public endpoints are identified. Key Azure Policy built-ins applicable: "Azure Data Factory should use private link", ⚠️ "Azure Data Factory linked services should use Key Vault for storing secrets" (security-adjacent control).

**Acceptance Criteria:**
- Data Factory NS-2 configuration assessed against MCSB baseline and factories with public network access or unmanaged linked service connectivity identified.
- Azure Policy compliance evaluated for: "Azure Data Factory should use private link" and applicable linked service network controls.
- Gap findings documented with remediation scope and affected Data Factory and Integration Runtime instances noted.

---

**[SEC-2] Secure Cloud Native Services: Database Migration Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Database Migration Service deployment posture — VNet integration mode, source and target connectivity routing, and private endpoint configuration — so that NS-2 gaps where migration traffic traverses public internet paths are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure Database Migration Service should use private endpoint" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Database Migration Service NS-2 configuration assessed against MCSB baseline and DMS instances without VNet integration or private endpoint identified.
- Azure Policy compliance evaluated for private connectivity controls applicable to Database Migration Service.
- Gap findings documented with remediation scope and affected DMS project and migration instances noted.

---

**[SEC-2] Secure Cloud Native Services: Databricks**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Databricks network isolation — VNet injection, no-public-IP mode on cluster nodes, NSG rule compliance, and Secure Cluster Connectivity configuration — so that NS-2 gaps where Databricks workspace or compute nodes are accessible over public networks are identified. Key Azure Policy built-ins applicable: "Azure Databricks Workspaces should use private link", "Azure Databricks Clusters should disable public IP".

**Acceptance Criteria:**
- Databricks NS-2 configuration assessed against MCSB baseline and workspaces without VNet injection, no-public-IP mode, or Secure Cluster Connectivity identified.
- Azure Policy compliance evaluated for: "Azure Databricks Workspaces should use private link", "Azure Databricks Clusters should disable public IP".
- Gap findings documented with remediation scope and affected Databricks workspace and cluster instances noted.

---

**[SEC-2] Secure Cloud Native Services: Digital Twins**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Digital Twins network controls — private endpoint, public network access, API authentication method, and event routing connectivity — so that NS-2 gaps in data plane access and event delivery network isolation are documented. Key Azure Policy built-ins applicable: ⚠️ "Azure Digital Twins should use private link" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Digital Twins NS-2 configuration assessed against MCSB baseline and instances with public data plane access or missing private endpoint identified.
- Azure Policy compliance evaluated for private link and public network access controls applicable to Digital Twins.
- Gap findings documented with remediation scope and affected Digital Twins instance and endpoint route configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Event Grid**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Event Grid network posture — private endpoint on topics and domains, public network access, managed identity for event delivery, and dead-letter storage connectivity — so that NS-2 gaps in event routing network isolation are identified. Key Azure Policy built-ins applicable: "Azure Event Grid topics should use private link", "Azure Event Grid domains should use private link".

**Acceptance Criteria:**
- Event Grid NS-2 configuration assessed against MCSB baseline and topics or domains with public network access or missing private endpoints identified.
- Azure Policy compliance evaluated for: "Azure Event Grid topics should use private link", "Azure Event Grid domains should use private link".
- Gap findings documented with remediation scope and affected Event Grid topic and domain instances noted.

---

**[SEC-2] Secure Cloud Native Services: Event Hubs**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Event Hubs namespace network controls — private endpoint, public network access, SAS key usage by applications, IP firewall, and TLS minimum version — so that NS-2 gaps in messaging layer network isolation and authentication exposure are documented. Key Azure Policy built-ins applicable: "Event Hub Namespaces should use private link", ⚠️ "Azure Event Hubs namespaces should disable public network access" (training data — verify exact display name).

**Acceptance Criteria:**
- Event Hubs NS-2 configuration assessed against MCSB baseline and namespaces with public access, missing private endpoints, or SAS-only authentication identified.
- Azure Policy compliance evaluated for: "Event Hub Namespaces should use private link" and applicable public network access controls.
- Gap findings documented with remediation scope and affected Event Hub namespace instances noted.

---

**[SEC-2] Secure Cloud Native Services: File Sync**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure File Sync network configuration — Storage Sync Service private endpoint, underlying storage account firewall rules, and registered server authentication — so that NS-2 gaps where sync traffic traverses public network paths are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure File Sync should use private link" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- File Sync NS-2 configuration assessed against MCSB baseline and Storage Sync Services lacking private endpoint or with storage firewall bypasses identified.
- Azure Policy compliance evaluated for private link controls applicable to File Sync and associated storage accounts.
- Gap findings documented with remediation scope and affected Storage Sync Service and registered server instances noted.

---

**[SEC-2] Secure Cloud Native Services: Functions**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Functions network controls — VNet integration for outbound routing, private endpoints for trigger storage, HTTPS-only enforcement, and managed identity for bindings — so that NS-2 gaps where function workloads egress or are triggered over public network paths are identified. Key Azure Policy built-ins applicable: "Function apps should only be accessible over HTTPS", "Function apps should use the latest TLS version".

**Acceptance Criteria:**
- Functions NS-2 configuration assessed against MCSB baseline and function apps without VNet integration, HTTPS-only enforcement, or managed identity bindings identified.
- Azure Policy compliance evaluated for: "Function apps should only be accessible over HTTPS", "Function apps should use the latest TLS version".
- Gap findings documented with remediation scope and affected Function App and hosting plan instances noted.

---

**[SEC-2] Secure Cloud Native Services: HPC Cache**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure HPC Cache network isolation — VNet deployment, subnet NSG rules for client access restriction, and storage target connectivity routing — so that NS-2 gaps where cache data movement or client access traverses unauthorized network paths are identified. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure HPC Cache-specific policy built-ins in MCSB v2 preview — assessment relies on VNet placement and NSG manual audit.

**Acceptance Criteria:**
- HPC Cache NS-2 configuration assessed against MCSB baseline and cache instances deployed outside dedicated VNet subnets or with unrestricted NSG rules identified.
- Azure Policy coverage for HPC Cache controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected HPC Cache instance and storage target configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Logic Apps**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Logic Apps Standard network controls — VNet integration, private endpoint for triggers, IP restriction on callback URLs, and managed identity for connector authentication — so that NS-2 gaps where workflow triggers or connector traffic traverse public network paths are identified. Key Azure Policy built-ins applicable: ⚠️ "Logic Apps Integration Service Environment should be isolated on a virtual network" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Logic Apps NS-2 configuration assessed against MCSB baseline and Standard apps without VNet integration or ISE apps with public exposure identified.
- Azure Policy compliance evaluated for VNet isolation controls applicable to Logic Apps Standard and ISE deployments.
- Gap findings documented with remediation scope and affected Logic App workflow and connector instances noted.

---

**[SEC-2] Secure Cloud Native Services: Machine Learning Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Machine Learning workspace network isolation — private endpoint, public network access, compute node public IP configuration, and associated resource private endpoint coverage — so that NS-2 gaps in ML environment isolation are identified across the workspace and its dependent services. Key Azure Policy built-ins applicable: "Azure Machine Learning Workspaces should use private link", ⚠️ "Azure Machine Learning workspace should disable public network access" (training data — verify exact display name).

**Acceptance Criteria:**
- Machine Learning NS-2 configuration assessed against MCSB baseline and workspaces with public network access, missing private endpoints, or compute nodes with public IPs identified.
- Azure Policy compliance evaluated for: "Azure Machine Learning Workspaces should use private link" and applicable public network access controls.
- Gap findings documented with remediation scope and affected ML workspace and compute cluster instances noted.

---

**[SEC-2] Secure Cloud Native Services: Managed Lustre**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Managed Lustre network isolation — VNet deployment, client subnet NSG rules for Lustre port 988, and storage backend connectivity routing — so that NS-2 gaps in file system network access control are identified. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure Managed Lustre-specific policy built-ins in MCSB v2 preview — assessment relies on VNet placement, NSG port 988 rules, and storage connectivity manual audit.

**Acceptance Criteria:**
- Managed Lustre NS-2 configuration assessed against MCSB baseline and file system instances without dedicated VNet subnets or with unrestricted Lustre port access identified.
- Azure Policy coverage for Managed Lustre controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected Managed Lustre cluster and client subnet configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Notification Hubs**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Notification Hubs namespace access controls — IP firewall configuration, SAS key usage by backend applications, and push notification provider TLS configuration — so that NS-2 gaps in management plane access restriction and authentication are identified for this service. Key Azure Policy built-ins applicable: ⚠️ No confirmed Notification Hubs-specific policy built-ins in MCSB v2 preview — assessment relies on namespace IP rules and SAS authentication manual review.

**Acceptance Criteria:**
- Notification Hubs NS-2 configuration assessed against MCSB baseline and namespaces without IP firewall restriction or relying on SAS-only authentication identified.
- Azure Policy coverage for Notification Hubs controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected Notification Hub namespace and backend application configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Remote Rendering**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Remote Rendering access configuration — Entra ID token authentication for session creation, service principal scoping, and TLS enforcement for rendering streaming — so that NS-2 gaps where rendering sessions are accessible without proper identity or transport security controls are documented. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure Remote Rendering-specific policy built-ins in MCSB v2 preview — assessment relies on Entra ID authentication and TLS configuration manual audit.

**Acceptance Criteria:**
- Remote Rendering NS-2 configuration assessed against MCSB baseline and session creation flows without Entra ID token authentication or TLS enforcement identified.
- Azure Policy coverage for Remote Rendering controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected Remote Rendering account and session instances noted.

---

**[SEC-2] Secure Cloud Native Services: Service Bus**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Service Bus namespace network controls — private endpoint, public network access, SAS key authentication by applications, and TLS minimum version — so that NS-2 gaps in messaging network isolation and local authentication exposure are identified. Key Azure Policy built-ins applicable: "Service Bus Namespaces should use private link", ⚠️ "Azure Service Bus namespaces should disable public network access" (training data — verify exact display name).

**Acceptance Criteria:**
- Service Bus NS-2 configuration assessed against MCSB baseline and namespaces with public access, missing private endpoints, or SAS-only authentication identified.
- Azure Policy compliance evaluated for: "Service Bus Namespaces should use private link" and applicable public network access controls.
- Gap findings documented with remediation scope and affected Service Bus namespace and queue/topic instances noted.

---

**[SEC-2] Secure Cloud Native Services: SignalR Service**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure SignalR Service network posture — private endpoint, public network access, upstream webhook authentication, and diagnostic log configuration — so that NS-2 gaps in real-time messaging service network isolation and upstream security are documented. Key Azure Policy built-ins applicable: ⚠️ "Azure SignalR Service should use private link" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- SignalR Service NS-2 configuration assessed against MCSB baseline and instances with public network access or missing private endpoints identified.
- Azure Policy compliance evaluated for private link and public network access controls applicable to SignalR Service.
- Gap findings documented with remediation scope and affected SignalR Service instance and upstream webhook configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Spring Apps**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Spring Apps network isolation — VNet injection, public test endpoint status, outbound UDR through Azure Firewall, and app-to-app communication routing — so that NS-2 gaps where Spring Apps workloads are reachable over public networks or uncontrolled egress paths are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure Spring Cloud should use network injection" (training data — verify exact display name; service renamed to Azure Spring Apps in current portal).

**Acceptance Criteria:**
- Spring Apps NS-2 configuration assessed against MCSB baseline and service instances without VNet injection or with public test endpoints active identified.
- Azure Policy compliance evaluated for VNet injection and network isolation controls applicable to Spring Apps.
- Gap findings documented with remediation scope and affected Spring Apps service instance and app configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Web PubSub**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Web PubSub network controls — private endpoint, public network access, upstream event handler authentication, and diagnostic logging — so that NS-2 gaps in WebSocket service network isolation and upstream webhook security are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure Web PubSub Service should use private link" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Web PubSub NS-2 configuration assessed against MCSB baseline and instances with public network access or missing private endpoints identified.
- Azure Policy compliance evaluated for private link and public network access controls applicable to Web PubSub.
- Gap findings documented with remediation scope and affected Web PubSub service instance and upstream handler configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Batch**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Batch network isolation — pool node public IP configuration, Batch account private endpoint, pool managed identity for storage access, and diagnostic log coverage — so that NS-2 gaps in compute workload network isolation are identified. Key Azure Policy built-ins applicable: "Azure Batch accounts should disable public network access", ⚠️ "Azure Batch pools should have disk encryption enabled" (security-adjacent — verify NS-2-specific built-ins against current policy list).

**Acceptance Criteria:**
- Batch NS-2 configuration assessed against MCSB baseline and accounts with public network access or pools with public IP nodes identified.
- Azure Policy compliance evaluated for: "Azure Batch accounts should disable public network access" and applicable pool network isolation controls.
- Gap findings documented with remediation scope and affected Batch account and pool configurations noted.

---

**[SEC-2] Secure Cloud Native Services: Cognitive Services**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Cognitive Services network controls — private endpoint or VNet service endpoint coverage, public network access, and local API key authentication usage — so that NS-2 gaps where AI service endpoints are accessible over unrestricted public networks are identified. Key Azure Policy built-ins applicable: "Cognitive Services accounts should restrict network access", "Cognitive Services accounts should use private link".

**Acceptance Criteria:**
- Cognitive Services NS-2 configuration assessed against MCSB baseline and accounts with unrestricted public network access or local key authentication identified.
- Azure Policy compliance evaluated for: "Cognitive Services accounts should restrict network access", "Cognitive Services accounts should use private link".
- Gap findings documented with remediation scope and affected Cognitive Services account and resource instances noted.

---

**[SEC-2] Secure Cloud Native Services: Content Delivery Network**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Content Delivery Network configuration — HTTPS-only delivery rules, custom domain TLS certificate management, WAF policy association, and origin access control — so that NS-2 gaps in CDN delivery security and direct origin bypass exposure are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure CDN profiles should use HTTPS only" (training data — verify exact display name; CDN Classic vs Azure Front Door Standard/Premium distinctions may affect applicable policy IDs).

**Acceptance Criteria:**
- Content Delivery Network NS-2 configuration assessed against MCSB baseline and CDN profiles without HTTPS-only delivery rules or WAF policy association identified.
- Azure Policy compliance evaluated for HTTPS enforcement and WAF association controls applicable to CDN profiles and endpoints.
- Gap findings documented with remediation scope and affected CDN profile and origin configurations noted.

---

### 3 Deploy Firewall at Edge of Enterprise Network [3 combined]

**[SEC-3] Deploy Firewall at Edge of Enterprise Network: Firewall**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Firewall Premium configuration — IDPS mode, Threat Intelligence setting, Firewall Policy hierarchy, and diagnostic log routing to Log Analytics — so that NS-3 gaps where hub firewall instances deviate from centralized inspection and detection requirements are identified. Key Azure Policy built-ins applicable: "Azure Firewall Standard - Classic Rules should enable Threat Intelligence", "Azure Firewall Standard should be upgraded to Premium for next generation protection".

**Acceptance Criteria:**
- Azure Firewall NS-3 configuration assessed against MCSB baseline and hub firewall instances without Premium SKU, IDPS mode, or Threat Intelligence alert mode identified.
- Azure Policy compliance evaluated for: "Azure Firewall Standard - Classic Rules should enable Threat Intelligence", "Azure Firewall Standard should be upgraded to Premium for next generation protection".
- Gap findings documented with remediation scope and affected Firewall and Firewall Policy instances noted.

---

**[SEC-3] Deploy Firewall at Edge of Enterprise Network: Firewall Manager**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Firewall Manager policy and hub configuration — parent policy structure, route intent coverage for spoke traffic, DDoS Standard plan association, and policy change alerting — so that NS-3 gaps in centralized firewall policy governance and hub traffic inspection are documented. Key Azure Policy built-ins applicable: "Virtual Hubs should be protected with Azure Firewall".

**Acceptance Criteria:**
- Firewall Manager NS-3 configuration assessed against MCSB baseline and Virtual WAN hubs without secured-hub configuration or route intent policy coverage identified.
- Azure Policy compliance evaluated for: "Virtual Hubs should be protected with Azure Firewall".
- Gap findings documented with remediation scope and affected Firewall Manager policy and hub instances noted.

---

**[SEC-3] Deploy Firewall at Edge of Enterprise Network: Stack Edge**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Stack Edge security configuration — local firewall rules, VPN authentication method, firmware version currency, and device credential management — so that NS-3 gaps in edge appliance network boundary protection are identified. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure Stack Edge-specific policy built-ins in MCSB v2 preview — assessment relies on Defender for IoT recommendations and device-level configuration audit.

**Acceptance Criteria:**
- Stack Edge NS-3 configuration assessed against MCSB baseline and devices with outdated firmware, default credentials, or misconfigured local firewall rules identified.
- Azure Policy coverage for Stack Edge controls evaluated; gaps in automated compliance detection via Defender for IoT noted.
- Gap findings documented with remediation scope and affected Stack Edge device and network configuration instances noted.

---

### 4 Deploy Intrusion Detection/Prevention Systems [pure v2]

**[SEC-4] Deploy Intrusion Detection/Prevention Systems**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess IDPS deployment across all Azure Firewall Premium hub instances — mode configuration, Sentinel alert integration, and quarterly tuning cadence documentation — so that NS-4 gaps in intrusion detection and prevention coverage across the hub firewall estate are identified. Key Azure Policy built-ins applicable: "Azure Firewall Standard - Classic Rules should enable Threat Intelligence", "Azure Firewall Standard should be upgraded to Premium for next generation protection".

**Acceptance Criteria:**
- IDPS NS-4 configuration assessed across all hub Firewall Premium instances and deviations from MCSB IDPS mode and Sentinel integration requirements identified.
- Azure Policy compliance evaluated for: "Azure Firewall Standard - Classic Rules should enable Threat Intelligence", "Azure Firewall Standard should be upgraded to Premium for next generation protection".
- Gap findings documented with remediation scope and affected Firewall instance and IDPS policy configurations noted.

---

### 5 Deploy DDoS Protection [2 combined]

**[SEC-5] Deploy DDoS Protection: DDoS Protection**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure DDoS Protection Standard plan coverage — VNet association completeness, diagnostic log routing, and metric alert configuration for attack detection events — so that NS-5 gaps where VNets hosting public IP resources lack volumetric attack protection are identified. Key Azure Policy built-ins applicable: "Virtual networks should be protected by Azure DDoS Protection".

**Acceptance Criteria:**
- DDoS Protection NS-5 configuration assessed against MCSB baseline and VNets hosting public IP resources without DDoS Standard plan association identified.
- Azure Policy compliance evaluated for: "Virtual networks should be protected by Azure DDoS Protection".
- Gap findings documented with remediation scope and affected VNet and DDoS Protection plan coverage instances noted.

---

**[SEC-5] Deploy DDoS Protection: Public IP**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Public IP resource posture — Standard SKU compliance, DDoS Standard plan coverage via parent VNet, unused PIP identification, and diagnostic log enablement — so that NS-5 gaps in public IP hygiene and DDoS protection coverage are documented. Key Azure Policy built-ins applicable: "Public IP addresses should have resource logs enabled for Azure DDoS Protection", "Virtual networks should be protected by Azure DDoS Protection".

**Acceptance Criteria:**
- Public IP NS-5 configuration assessed against MCSB baseline and PIPs without Standard SKU, diagnostic logs, or DDoS coverage via parent VNet identified.
- Azure Policy compliance evaluated for: "Public IP addresses should have resource logs enabled for Azure DDoS Protection", "Virtual networks should be protected by Azure DDoS Protection".
- Gap findings documented with remediation scope and affected Public IP and parent VNet instances noted.

---

### 6 Deploy Web Application Firewall [3 combined]

**[SEC-6] Deploy Web Application Firewall: Application Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Application Gateway WAF configuration — policy mode, OWASP CRS version, SSL policy TLS minimum version, and WAF diagnostic log routing to Sentinel — so that NS-6 gaps where web application traffic is not inspected in Prevention mode or uses outdated rulesets are identified. Key Azure Policy built-ins applicable: "Web Application Firewall (WAF) should be enabled for Application Gateway", "Web Application Firewall (WAF) should use the specified mode for Application Gateway".

**Acceptance Criteria:**
- Application Gateway NS-6 configuration assessed against MCSB baseline and gateways without WAF enabled, in Detection mode, or using outdated OWASP CRS versions identified.
- Azure Policy compliance evaluated for: "Web Application Firewall (WAF) should be enabled for Application Gateway", "Web Application Firewall (WAF) should use the specified mode for Application Gateway".
- Gap findings documented with remediation scope and affected Application Gateway and WAF policy instances noted.

---

**[SEC-6] Deploy Web Application Firewall: Front Door**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Front Door WAF and access control configuration — WAF policy mode, managed ruleset version, origin access restriction, and diagnostic log forwarding to Sentinel — so that NS-6 gaps where CDN-fronted workloads lack Prevention mode WAF or are susceptible to direct origin bypass are identified. Key Azure Policy built-ins applicable: "Azure Web Application Firewall should be enabled for Azure Front Door entry-points", "Web Application Firewall (WAF) should use the specified mode for Azure Front Door Service".

**Acceptance Criteria:**
- Front Door NS-6 configuration assessed against MCSB baseline and profiles without WAF policy, in Detection mode, or with unprotected direct origin access identified.
- Azure Policy compliance evaluated for: "Azure Web Application Firewall should be enabled for Azure Front Door entry-points", "Web Application Firewall (WAF) should use the specified mode for Azure Front Door Service".
- Gap findings documented with remediation scope and affected Front Door profile and origin group configurations noted.

---

**[SEC-6] Deploy Web Application Firewall: Web Application Firewall**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess standalone WAF policy configuration — resource association status, exclusion list scope, custom rule coverage, and disabled rule documentation — so that NS-6 gaps where WAF policies are unattached or have overly broad exclusions that reduce detection effectiveness are identified. Key Azure Policy built-ins applicable: "Web Application Firewall (WAF) should be enabled for Application Gateway", "Azure Web Application Firewall should be enabled for Azure Front Door entry-points".

**Acceptance Criteria:**
- WAF policy NS-6 configuration assessed against MCSB baseline and standalone policies without resource association or with undocumented broad exclusions identified.
- Azure Policy compliance evaluated for: "Web Application Firewall (WAF) should be enabled for Application Gateway", "Azure Web Application Firewall should be enabled for Azure Front Door entry-points".
- Gap findings documented with remediation scope and affected WAF policy and associated gateway or Front Door instances noted.

---

### 7 Simplify Network Security Configuration [1 combined]

**[SEC-7] Simplify Network Security Configuration: Network Watcher**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Network Watcher configuration — NSG flow log version and Traffic Analytics enablement across all regions, Connection Monitor probe coverage, and Azure Policy assignment for flow log compliance — so that NS-7 gaps in network traffic visibility and east-west monitoring are identified. Key Azure Policy built-ins applicable: "Flow logs should be configured for every network security group", "Network Watcher flow logs should have traffic analytics enabled".

**Acceptance Criteria:**
- Network Watcher NS-7 configuration assessed against MCSB baseline and regions with missing flow logs, Traffic Analytics disabled, or absent Connection Monitor coverage identified.
- Azure Policy compliance evaluated for: "Flow logs should be configured for every network security group", "Network Watcher flow logs should have traffic analytics enabled".
- Gap findings documented with remediation scope and affected Network Watcher and NSG flow log instances noted.

---

### 8 Detect and Disable Insecure Services and Protocols [pure v2]

**[SEC-8] Detect and Disable Insecure Services and Protocols**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess insecure protocol exposure across Azure services in scope — TLS 1.0/1.1 acceptance, FTP/FTPS settings, SSL enforcement on database services, and Defender for Cloud insecure protocol recommendations — so that NS-8 gaps where deprecated protocols remain active are enumerated and scoped for targeted remediation. Key Azure Policy built-ins applicable: ⚠️ "App Service apps should require 'latest' TLS version" (training data), ⚠️ "Enforce SSL connection should be enabled for MySQL database servers" (training data — NS-8 spans multiple resource types with per-service TLS policies; verify applicable built-in IDs against current MCSB v2 preview list).

**Acceptance Criteria:**
- Insecure protocol NS-8 exposure assessed across in-scope Azure services and resources accepting TLS 1.0/1.1, FTP, or non-SSL database connections identified.
- Azure Policy compliance evaluated for per-service TLS minimum version and SSL enforcement built-ins applicable to NS-8 scope.
- Gap findings documented with remediation scope and affected service instances and protocol configurations noted.

---

### 9 Connect On-Premises or Cloud Network Privately [6 combined]

**[SEC-9] Connect On-Premises or Cloud Network Privately: VPN Gateway**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess VPN Gateway configuration — IKEv2 protocol usage on site-to-site connections, Basic SKU compliance, point-to-site Entra ID authentication, and diagnostic log coverage — so that NS-9 gaps in encrypted private connectivity configuration are identified. Key Azure Policy built-ins applicable: "Azure VPN gateways should not use 'basic' SKU", "VPN gateways should use only Azure Active Directory (Azure AD) authentication for point-to-site users".

**Acceptance Criteria:**
- VPN Gateway NS-9 configuration assessed against MCSB baseline and gateways on Basic SKU, using IKEv1, or with P2S configured without Entra ID authentication identified.
- Azure Policy compliance evaluated for: "Azure VPN gateways should not use 'basic' SKU", "VPN gateways should use only Azure Active Directory (Azure AD) authentication for point-to-site users".
- Gap findings documented with remediation scope and affected VPN Gateway and connection instances noted.

---

**[SEC-9] Connect On-Premises or Cloud Network Privately: Private Link**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Private Link deployment — service endpoint vs private endpoint gap analysis, DNS zone group linkage completeness, cross-tenant connection approval workflow, and subnet network policy configuration — so that NS-9 gaps where private connectivity is absent or DNS resolution falls back to public IP are identified. Key Azure Policy built-ins applicable: ⚠️ "Private endpoint connections on Blob Storage should be enabled" (resource-type-scoped example — Private Link itself has no single built-in; per-service private endpoint policies apply individually).

**Acceptance Criteria:**
- Private Link NS-9 configuration assessed against MCSB baseline and services relying on service endpoints rather than private endpoints, or missing DNS zone group linkage, identified.
- Azure Policy compliance evaluated for per-service private endpoint built-ins applicable to the in-scope resource list.
- Gap findings documented with remediation scope and affected Private Endpoint and DNS zone group configurations noted.

---

**[SEC-9] Connect On-Premises or Cloud Network Privately: Bastion**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Bastion deployment — Premium SKU tier, shareable link configuration, session recording setup, and RBAC access scoping — so that NS-9 gaps where VM management paths lack Entra ID authentication enforcement, session audit capability, or minimum-privilege access control are documented. Key Azure Policy built-ins applicable: ⚠️ "Azure Bastion should be enabled" (training data — verify exact display name and scope against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Bastion NS-9 configuration assessed against MCSB baseline and subscriptions or VNets where direct RDP/SSH to VMs is permitted without Bastion identified.
- Azure Policy compliance evaluated for Bastion deployment and SKU controls applicable across the in-scope subscription estate.
- Gap findings documented with remediation scope and affected VNet and VM management path configurations noted.

---

**[SEC-9] Connect On-Premises or Cloud Network Privately: Virtual Desktop**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Virtual Desktop network configuration — host pool and workspace private endpoint, Conditional Access MFA coverage for AVD sign-in, and RDP Shortpath scope restriction to managed networks — so that NS-9 gaps in secure private desktop access configuration are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure Virtual Desktop host pools should use private endpoints" (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Virtual Desktop NS-9 configuration assessed against MCSB baseline and host pools without private endpoints, missing MFA Conditional Access, or with unmanaged-network RDP Shortpath enabled identified.
- Azure Policy compliance evaluated for private endpoint and network isolation controls applicable to Virtual Desktop host pools and workspaces.
- Gap findings documented with remediation scope and affected host pool and workspace configurations noted.

---

**[SEC-9] Connect On-Premises or Cloud Network Privately: Nutanix on Azure**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Nutanix Cloud Clusters on Azure network security — dedicated VNet isolation, Prism Central management plane access restrictions, Azure Firewall egress control, and Nutanix security hardening configuration — so that NS-9 gaps in bare-metal cluster network boundary protection are identified. Key Azure Policy built-ins applicable: ⚠️ No confirmed Nutanix on Azure-specific policy built-ins in MCSB v2 preview — assessment relies on VNet isolation and Azure Firewall egress configuration manual audit.

**Acceptance Criteria:**
- Nutanix on Azure NS-9 configuration assessed against MCSB baseline and clusters without dedicated VNet isolation or with unrestricted Prism Central management plane access identified.
- Azure Policy coverage for Nutanix on Azure controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected Nutanix cluster and management network configurations noted.

---

**[SEC-9] Connect On-Premises or Cloud Network Privately: VMware Solution**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure VMware Solution connectivity and microsegmentation — ExpressRoute-only management access, NSX-T distributed firewall coverage for VM workloads, T0/T1 gateway north-south rule configuration, and default credential rotation — so that NS-9 gaps in private cloud network isolation are documented. Key Azure Policy built-ins applicable: ⚠️ No confirmed Azure VMware Solution-specific NS-9 policy built-ins in MCSB v2 preview — assessment relies on ExpressRoute connectivity and NSX-T distributed firewall configuration manual audit.

**Acceptance Criteria:**
- VMware Solution NS-9 configuration assessed against MCSB baseline and private clouds with management access outside ExpressRoute or NSX-T distributed firewall gaps identified.
- Azure Policy coverage for Azure VMware Solution controls evaluated; gaps in automated compliance detection noted.
- Gap findings documented with remediation scope and affected private cloud and NSX-T gateway rule configurations noted.

---

### 10 Ensure Domain Name System (DNS) Security [1 combined]

**[SEC-10] Ensure Domain Name System (DNS) Security: DNS**
Parent: [SEC-NS] Network Security — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure DNS security configuration — Private DNS zone coverage and naming accuracy for all private endpoint types, DNS zone group linkage completeness, DNS Private Resolver hybrid forwarding, and Defender for DNS enablement — so that NS-10 gaps where private endpoint DNS resolution returns public IPs or hybrid DNS routes through unmonitored forwarder VMs are identified. Key Azure Policy built-ins applicable: ⚠️ "Azure DNS zones should use private DNS" (training data — DNS NS-10 built-ins are typically scoped per private endpoint resource type, not DNS service itself; verify applicable IDs against current MCSB v2 preview list).

**Acceptance Criteria:**
- DNS NS-10 configuration assessed against MCSB baseline and private endpoints with missing Private DNS zone group linkage or returning public IP on resolution identified.
- Azure Policy compliance evaluated for per-resource-type Private DNS zone group built-ins applicable to the in-scope private endpoint estate.
- Gap findings documented with remediation scope and affected DNS zone, zone group, and Private Resolver configurations noted.
