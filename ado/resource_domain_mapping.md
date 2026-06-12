# Resource → Domain Mapping

Core artifact: maps all 118 MCSB v3 Azure resources to MCSB v2 security domains.
Primary domain = Feature parent for user story.
Secondary domains = noted for context; user story lives under Primary only.

---

## Mapping Table (118 Resources)

| # | Azure Resource | Primary Domain | Code | Secondary Domain(s) | Mapping Rationale |
|---|---|---|---|---|---|
| 1 | API Management | Identity Management | IM | NS, DP | Core function = API auth/authz; network policy and TLS secondary |
| 2 | App Service | Network Security | NS | IM, DP | VNet integration, private endpoint, network access primary; managed identity and TLS secondary |
| 3 | Application Gateway | Network Security | NS | — | Pure network: L7 load balancer, WAF, TLS termination |
| 4 | Automation | Privileged Access | PA | IM, DS | Privileged runbook execution; managed identity for auth, automation scripts security |
| 5 | Active Directory Domain Services | Identity Management | IM | PA | Identity and auth provider; privileged roles in AD secondary |
| 6 | Advisor | Posture & Vulnerability Mgmt | PV | GS | Security recommendations and posture guidance; governance insights secondary |
| 7 | Analysis Services | Data Protection | DP | IM | Model and data encryption primary; auth controls secondary |
| 8 | App Configuration | Data Protection | DP | IM | Sensitive config/feature flag storage; access control secondary |
| 9 | Arc-enabled Kubernetes | Endpoint Security | ES | PV, NS | Container endpoint security on any infra; patching and network policy secondary |
| 10 | Arc-enabled Servers | Endpoint Security | ES | PV | Endpoint protection for non-Azure servers; patch management secondary |
| 11 | Bastion | Network Security | NS | — | Secure RDP/SSH jump host with no public IP exposure |
| 12 | Bot Service | Identity Management | IM | NS | Bot identity and auth primary; network access secondary |
| 13 | Cache for Redis | Network Security | NS | DP | Private endpoint and network access primary; encryption at rest secondary |
| 14 | Center for SAP Solutions | Data Protection | DP | PV, NS | SAP data protection primary; SAP posture and network secondary |
| 15 | Cognitive Search | Network Security | NS | DP, IM | Private endpoint and network access primary; encryption and API key → managed identity secondary |
| 16 | Communication Services | Network Security | NS | DP | Network security for comms channels (TLS for calls/chat); data encryption secondary |
| 17 | Communications Gateway | Network Security | NS | — | SIP/media protocol network security for operator connectivity |
| 18 | Container Apps | Network Security | NS | IM, PV | Network isolation (VNET, Dapr); managed identity and container posture secondary |
| 19 | Cosmos DB | Data Protection | DP | NS, IM | Encryption/CMK primary; private endpoint, RBAC-based auth secondary |
| 20 | Cosmos DB for PostgreSQL | Data Protection | DP | NS | TDE and encryption primary; network/firewall secondary |
| 21 | Data Box | Data Protection | DP | AM | Physical data transfer encryption; physical asset tracking and lifecycle secondary |
| 22 | Data Explorer | Data Protection | DP | NS, IM | Data encryption and column-level security; network and auth secondary |
| 23 | Data Manager for Energy | Data Protection | DP | NS, IM | OSDU data platform encryption; network and auth secondary |
| 24 | Data Share | Data Protection | DP | AM | Data sharing security and access control; data governance and lineage secondary |
| 25 | Database for MariaDB | Data Protection | DP | NS, LT | TDE and encryption at rest primary; private endpoint, audit logging secondary |
| 26 | Database for MySQL Flexible Server | Data Protection | DP | NS, LT | TDE and encryption primary; network access, audit logging secondary |
| 27 | Database for PostgreSQL Flexible Server | Data Protection | DP | NS, LT | TDE and encryption primary; network access, audit logging secondary |
| 28 | Database Migration Service | Network Security | NS | DP | Secure migration connectivity (private endpoint, VNet); data in transit secondary |
| 29 | Databricks | Network Security | NS | DP, IM | VNet injection and private endpoint primary; cluster encryption and auth secondary |
| 30 | DDoS Protection | Network Security | NS | — | DDoS Standard plan — pure network protection |
| 31 | Dedicated HSM | Data Protection | DP | — | HSM-backed key management — pure DP, no secondary |
| 32 | DevTest Labs | Asset Management | AM | DS | Lab resource lifecycle governance; dev environment security secondary |
| 33 | Digital Twins | Network Security | NS | IM, DP | Private endpoint and network access primary; auth and data secondary |
| 34 | DNS | Network Security | NS | — | DNS security: Azure DNS, private resolver, DNSSEC, DNS logging |
| 35 | File Sync | Network Security | NS | DP | Sync endpoint network security primary; data encryption in transit secondary |
| 36 | Firewall | Network Security | NS | — | Azure Firewall — pure network perimeter control |
| 37 | Firewall Manager | Network Security | NS | GS | Centralized firewall policy management; governance of firewall rules secondary |
| 38 | Front Door | Network Security | NS | — | Global CDN, WAF, HTTPS enforcement, DDoS protection |
| 39 | HPC Cache | Network Security | NS | DP | Network isolation for HPC cache access primary; data encryption secondary |
| 40 | Information Protection | Data Protection | DP | AM | MIP/AIP data classification labels and protection primary; asset classification secondary |
| 41 | Kubernetes Service (AKS) | Endpoint Security | ES | NS, PV, IM | Container and pod security primary; network policies, vulnerability scanning, Azure AD auth secondary |
| 42 | Kubernetes Service on Azure Stack HCI | Endpoint Security | ES | NS, PV | Container endpoint security on HCI; network policies and patching secondary |
| 43 | Lighthouse | Privileged Access | PA | GS | Delegated privileged access for MSP/partner scenarios; governance of delegated access secondary |
| 44 | Load Balancer | Network Security | NS | — | Network load distribution and health probing |
| 45 | Managed Applications | Governance & Strategy | GS | AM | Governance of marketplace managed application policies; resource lifecycle secondary |
| 46 | Managed Lustre | Network Security | NS | DP | Network isolation for HPC parallel filesystem; data encryption secondary |
| 47 | Migrate | Asset Management | AM | PV | Asset discovery and inventory baseline; security posture assessment secondary |
| 48 | Monitor | Logging & Threat Detection | LT | — | Azure Monitor: metrics, logs, alerts, diagnostics — pure LT |
| 49 | NAT Gateway | Network Security | NS | — | Outbound network address translation control |
| 50 | NetApp Files | Data Protection | DP | NS, BR | Enterprise storage encryption (NFS/SMB); network access and backup secondary |
| 51 | Open Datasets | Asset Management | AM | DP | Public dataset governance and classification; data sensitivity secondary |
| 52 | OpenAI | Data Protection | DP | NS, IM | Data privacy and content filtering primary; private endpoint and RBAC secondary |
| 53 | Policy | Governance & Strategy | GS | AM | Compliance policy governance; resource policy enforcement secondary |
| 54 | Private Link | Network Security | NS | — | Private connectivity to PaaS services — pure NS |
| 55 | Public IP | Network Security | NS | — | Public exposure management and IP protection |
| 56 | Purview | Data Protection | DP | AM, GS | Data classification and privacy primary; data catalog, lineage, and governance secondary |
| 57 | Red Hat OpenShift (ARO) | Endpoint Security | ES | NS, PV | Container and pod security; private cluster and vulnerability management secondary |
| 58 | Remote Rendering | Network Security | NS | IM | 3D streaming network security primary; service identity secondary |
| 59 | Resource Graph | Asset Management | AM | — | Resource inventory query service — pure AM |
| 60 | Resource Manager | Asset Management | AM | GS | Resource lifecycle, locks, RBAC; governance, policy, and management groups secondary |
| 61 | SignalR Service | Network Security | NS | IM | WebSocket network security and access control primary; auth secondary |
| 62 | Spatial Anchors | Identity Management | IM | NS | Device and service identity/auth primary (mixed reality); network secondary |
| 63 | Sphere | Endpoint Security | ES | NS | IoT microcontroller endpoint security primary; network secondary |
| 64 | Spring Apps | Network Security | NS | IM, DS | Network isolation for microservices; managed identity and application security secondary |
| 65 | SQL | Data Protection | DP | NS, LT, IM | TDE/CMK/Always Encrypted primary; private endpoint, SQL Audit, Azure AD auth secondary |
| 66 | Stack Edge | Network Security | NS | ES, DP | Edge device network security primary; device endpoint and edge data encryption secondary |
| 67 | Stream Analytics | Data Protection | DP | NS, IM | Streaming data encryption primary; network and managed identity secondary |
| 68 | Synapse Analytics | Data Protection | DP | NS, IM, LT | Encryption of analytics data primary; managed VNet, auth, audit logging secondary |
| 69 | Virtual Desktop | Network Security | NS | IM, ES, PA | RDP/network access security primary; identity, session host endpoint, privileged admin secondary |
| 70 | VMware Solution | Network Security | NS | ES, PV | Network extension and segment security primary; VMware endpoint and patching secondary |
| 71 | Web Application Firewall | Network Security | NS | — | OWASP WAF rule enforcement — pure NS |
| 72 | Web PubSub | Network Security | NS | IM | WebSocket network security primary; auth secondary |
| 73 | Backup | Backup & Recovery | BR | — | Azure Backup policies, encryption, retention, vaults — pure BR |
| 74 | Batch | Network Security | NS | DP, IM | No-public-IP job isolation primary; job data encryption and managed identity secondary |
| 75 | Cloud Shell | Privileged Access | PA | IM | Privileged shell access tool; user identity secondary |
| 76 | Cognitive Services | Network Security | NS | DP, IM | Private endpoint/network access primary; data and API key → managed identity secondary |
| 77 | Container Instances | Endpoint Security | ES | NS, PV | Container security in ACI primary; VNet integration and image vulnerability secondary |
| 78 | Container Registry | Endpoint Security | ES | DS, NS | Container image scanning and signing primary; supply chain and private endpoint secondary |
| 79 | Content Delivery Network | Network Security | NS | — | CDN HTTPS enforcement, geo-restriction, edge TLS |
| 80 | Cost Management | Governance & Strategy | GS | AM | Financial governance and budget controls; resource efficiency tracking secondary |
| 81 | Customer Lockbox | Privileged Access | PA | — | Microsoft support privileged access approval — pure PA |
| 82 | Data Factory | Network Security | NS | DP, IM | Private endpoints for data movement primary; data encryption in transit, managed identity secondary |
| 83 | Data Lake Analytics | Data Protection | DP | NS, IM | Big data encryption primary; network and auth secondary |
| 84 | Event Grid | Network Security | NS | IM, DP | Private endpoint primary; auth and data in transit secondary |
| 85 | Event Hubs | Network Security | NS | DP, IM | Private endpoint primary; message encryption and auth secondary |
| 86 | Functions | Network Security | NS | IM, DS | Private endpoint/VNet integration primary; managed identity and serverless security secondary |
| 87 | Intelligent Recommendations | Data Protection | DP | IM | Data privacy for recommendation model training data; auth secondary |
| 88 | IoT Central | Endpoint Security | ES | NS, IM | IoT device security and enrollment primary; network and device auth secondary |
| 89 | IoT Hub | Endpoint Security | ES | NS, IM, DP | IoT device endpoint security primary; network, device auth, telemetry data secondary |
| 90 | Key Vault | Data Protection | DP | — | Secrets, keys, certificates management — pure DP |
| 91 | Key Vault Managed HSM | Data Protection | DP | — | FIPS 140-2 Level 3 HSM-backed key management — pure DP |
| 92 | Logic Apps | Network Security | NS | IM, DS | Private endpoint and connector network security primary; managed identity, workflow security secondary |
| 93 | Machine Learning Service | Network Security | NS | DP, IM, DS | Private workspace and network isolation primary; model data security, auth, MLSecOps secondary |
| 94 | Media Services | Data Protection | DP | NS, IM | Content encryption and DRM primary; network and auth secondary |
| 95 | Attestation | Identity Management | IM | PV | Hardware identity attestation and trusted execution environments; trusted hardware posture secondary |
| 96 | Managed Instance for Apache Cassandra | Data Protection | DP | NS | Cassandra data encryption primary; VNet injection and network secondary |
| 97 | Peering Service | Network Security | NS | — | BGP peering security and route filtering |
| 98 | Defender for Cloud | Posture & Vulnerability Mgmt | PV | LT | Secure Score and posture recommendations primary; threat detection secondary |
| 99 | Defender for IoT | Endpoint Security | ES | LT | IoT/OT device endpoint security primary; threat detection and alerting secondary |
| 100 | Sentinel | Logging & Threat Detection | LT | IR | SIEM, analytics rules, threat hunting primary; incident management and playbooks secondary |
| 101 | Network Watcher | Network Security | NS | LT | Network monitoring, flow logs, packet capture primary; network diagnostic logging secondary |
| 102 | Notification Hubs | Network Security | NS | IM | Push notification network security primary; auth secondary |
| 103 | Nutanix on Azure | Network Security | NS | ES, PV | Nutanix network integration security primary; hypervisor endpoint and posture secondary |
| 104 | Resource Mover | Asset Management | AM | NS | Asset migration and lifecycle management primary; network dependency review secondary |
| 105 | Service Bus | Network Security | NS | DP, IM | Private endpoint and network access primary; message encryption and auth secondary |
| 106 | Site Recovery | Backup & Recovery | BR | — | Disaster recovery replication, failover, and test DR — pure BR |
| 107 | SQL IaaS | Data Protection | DP | NS, LT, PV | TDE and SQL Server encryption primary; network access, SQL audit, OS patching secondary |
| 108 | Storage | Data Protection | DP | NS, LT, IM | Encryption at rest (CMK) primary; network firewall, access logging, RBAC/SAS secondary |
| 109 | Traffic Manager | Network Security | NS | — | DNS-based traffic routing security |
| 110 | Trusted Hardware Identity Management | Identity Management | IM | PV | Hardware root of trust and attestation certificates; trusted hardware posture secondary |
| 111 | Universal Print | Identity Management | IM | GS | Printer access control and authentication; governance of print resources secondary |
| 112 | Virtual Machine Scale Sets | Endpoint Security | ES | NS, PV, DP | Endpoint protection at scale primary; NSG, OS patching, disk encryption secondary |
| 113 | Virtual Machines (Linux) | Endpoint Security | ES | NS, PV, DP | Defender for Endpoint, antimalware primary; NSG, patch mgmt, disk encryption secondary |
| 114 | Virtual Machines (Windows) | Endpoint Security | ES | NS, PV, DP | Defender for Endpoint/EDR primary; NSG, Windows Update, BitLocker secondary |
| 115 | Virtual Network | Network Security | NS | — | VNet design, NSGs, subnet segmentation, VNet peering |
| 116 | Virtual Network NAT | Network Security | NS | — | Outbound NAT connectivity control |
| 117 | Virtual WAN | Network Security | NS | — | Hub-spoke topology, secure hub, Azure Firewall integration |
| 118 | VPN Gateway | Network Security | NS | DP | Site-to-site/P2S VPN security primary; IKE/IPsec encryption in transit secondary |

---

## Domain Summary

| Domain | Code | Primary Count | Azure Resources (Primary) |
|---|---|---|---|
| Network Security | NS | 50 | App Service, Application Gateway, Bastion, Cache for Redis, Cognitive Search, Communication Services, Communications Gateway, Container Apps, Data Factory, Database Migration Service, Databricks, DDoS Protection, Digital Twins, DNS, Event Grid, Event Hubs, File Sync, Firewall, Firewall Manager, Front Door, Functions, HPC Cache, Load Balancer, Logic Apps, Machine Learning Service, Managed Lustre, NAT Gateway, Network Watcher, Notification Hubs, Nutanix on Azure, Peering Service, Private Link, Public IP, Remote Rendering, Service Bus, SignalR Service, Spring Apps, Stack Edge, Traffic Manager, Virtual Desktop, Virtual Network, Virtual Network NAT, Virtual WAN, VMware Solution, VPN Gateway, Web Application Firewall, Web PubSub, Batch, Cognitive Services, Content Delivery Network |
| Data Protection | DP | 28 | Analysis Services, App Configuration, Center for SAP Solutions, Cosmos DB, Cosmos DB for PostgreSQL, Data Box, Data Explorer, Data Manager for Energy, Data Share, Database for MariaDB, Database for MySQL Flexible Server, Database for PostgreSQL Flexible Server, Dedicated HSM, Information Protection, Intelligent Recommendations, Key Vault, Key Vault Managed HSM, Managed Instance for Apache Cassandra, Media Services, NetApp Files, OpenAI, Purview, SQL, SQL IaaS, Storage, Stream Analytics, Synapse Analytics, Data Lake Analytics |
| Endpoint Security | ES | 14 | Arc-enabled Kubernetes, Arc-enabled Servers, Container Instances, Container Registry, Defender for IoT, IoT Central, IoT Hub, Kubernetes Service (AKS), Kubernetes Service on Azure Stack HCI, Red Hat OpenShift (ARO), Sphere, Virtual Machine Scale Sets, Virtual Machines (Linux), Virtual Machines (Windows) |
| Identity Management | IM | 7 | API Management, Active Directory Domain Services, Attestation, Bot Service, Spatial Anchors, Trusted Hardware Identity Management, Universal Print |
| Asset Management | AM | 6 | DevTest Labs, Migrate, Open Datasets, Resource Graph, Resource Manager, Resource Mover |
| Governance & Strategy | GS | 3 | Cost Management, Managed Applications, Policy |
| Privileged Access | PA | 4 | Automation, Cloud Shell, Customer Lockbox, Lighthouse |
| Posture & Vuln. Mgmt | PV | 2 | Advisor, Defender for Cloud |
| Logging & Threat Detection | LT | 2 | Monitor, Sentinel |
| Backup & Recovery | BR | 2 | Backup, Site Recovery |
| DevOps Security | DS | 0 | (DS controls are cross-cutting — no v3 resources map primarily to DS) |
| Incident Response | IR | 0 | (IR controls are process-level — no v3 resources map primarily to IR) |
| **TOTAL** | | **118** | |
