# CyberProbe — Official References & Industry Resources

A curated collection of official documentation, industry frameworks, research references, and authoritative sources that support, educate, and extend CyberProbe's security investigation capabilities.

> **Last updated:** 2026-04-14

---

## Table of Contents

1. [Microsoft Security Platform](#1-microsoft-security-platform)
2. [Microsoft Sentinel & Data Lake](#2-microsoft-sentinel--data-lake)
3. [Microsoft Defender XDR](#3-microsoft-defender-xdr)
4. [Microsoft Entra ID (Identity)](#4-microsoft-entra-id-identity)
5. [Microsoft Security APIs](#5-microsoft-security-apis)
6. [AI Attacks, Threats & Adversarial Techniques](#6-ai-attacks-threats--adversarial-techniques)
7. [AI & LLM Security Frameworks](#7-ai--llm-security-frameworks)
8. [MITRE Frameworks](#8-mitre-frameworks)
9. [OWASP Standards](#9-owasp-standards)
10. [NIST Cybersecurity](#10-nist-cybersecurity)
11. [Threat Intelligence Services](#11-threat-intelligence-services)
12. [KQL & Query Language](#12-kql--query-language)
13. [AI Agents, MCP & Copilot](#13-ai-agents-mcp--copilot)
14. [AI Governance & Agent 365](#14-ai-governance--agent-365)
15. [Industry Frameworks & Benchmarks](#15-industry-frameworks--benchmarks)
16. [Security Research & Blogs](#16-security-research--blogs)
17. [Open-Source Projects & Community](#17-open-source-projects--community)
18. [Training & Certification](#18-training--certification)

---

## 1. Microsoft Security Platform

Core platform documentation for the security stack CyberProbe integrates with.

| Resource | URL | Description |
|----------|-----|-------------|
| Microsoft Sentinel Documentation | https://learn.microsoft.com/azure/sentinel/ | SIEM platform — analytics, workbooks, playbooks, hunting |
| Microsoft Defender XDR Documentation | https://learn.microsoft.com/defender-xdr/ | Unified threat protection, Advanced Hunting, incidents |
| Microsoft Defender for Endpoint | https://learn.microsoft.com/defender-endpoint/ | Endpoint detection and response (EDR) |
| Microsoft Defender for Office 365 | https://learn.microsoft.com/defender-office-365/ | Email and collaboration security |
| Microsoft Defender for Cloud | https://learn.microsoft.com/azure/defender-for-cloud/ | Cloud-native application protection (CNAPP) |
| Microsoft Defender for Cloud Apps | https://learn.microsoft.com/defender-cloud-apps/ | SaaS security, shadow IT, app governance |
| Microsoft Defender for Identity | https://learn.microsoft.com/defender-for-identity/ | On-premises AD threat detection |
| Microsoft Security Exposure Management | https://learn.microsoft.com/security-exposure-management/ | Attack surface, choke points, exposure scoring |
| Microsoft Security Copilot | https://learn.microsoft.com/security-copilot/ | AI-powered security assistant |
| Security Copilot Agent Guide | https://learn.microsoft.com/copilot/security/agents-overview | Building custom Security Copilot agents |
| Defender Portal | https://security.microsoft.com | Unified security portal |

---

## 2. Microsoft Sentinel & Data Lake

Data ingestion, querying, and the new programmatic KQL API for the Sentinel data lake.

| Resource | URL | Description |
|----------|-----|-------------|
| Microsoft Sentinel Data Lake Overview | https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-overview | Architecture and capabilities |
| Run KQL Queries on Data Lake via API | https://learn.microsoft.com/azure/sentinel/datalake/kql-queries-api | Native REST API for programmatic KQL execution |
| Data Lake KQL Queries (Portal) | https://learn.microsoft.com/azure/sentinel/datalake/kql-queries | Interactive query execution |
| Data Lake Service Limits | https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-service-limits | Query size, timeout, rate limits |
| Data Lake Onboarding | https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-onboarding | Workspace setup and configuration |
| Connect Sentinel to Defender XDR | https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal | Portal integration, region support |
| Sentinel Region Support | https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal#region-support | Supported regions for unified experience |
| Entity Investigation (UEBA) | https://learn.microsoft.com/azure/sentinel/investigate-with-ueba | Entity behavior analytics and graph investigation |
| **Blog**: Running KQL on Data Lake using API | https://techcommunity.microsoft.com/blog/MicrosoftSentinelBlog/running-kql-queries-on-microsoft-sentinel-data-lake-using-api/4503128 | Walkthrough with Python and Logic Apps examples |

---

## 3. Microsoft Defender XDR

Advanced Hunting tables, incident management, and entity investigation.

| Resource | URL | Description |
|----------|-----|-------------|
| Advanced Hunting Schema Tables | https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables | Complete table schema reference |
| Advanced Hunting Quotas & Limits | https://learn.microsoft.com/defender-xdr/advanced-hunting-limits | 45 req/min, 30-day retention, 100K rows |
| Investigate Incidents | https://learn.microsoft.com/defender-xdr/investigate-incidents | Incident response workflow |
| Blast Radius Analysis | https://learn.microsoft.com/defender-xdr/investigate-incidents#blast-radius-analysis | Entity impact analysis |
| Investigate Users | https://learn.microsoft.com/defender-xdr/investigate-users | User entity investigation |
| GQL (Graph Query Language) | https://learn.microsoft.com/defender-xdr/advanced-hunting-graph | Pattern-matching queries for graph traversal |
| Native Defender XDR API (retiring Feb 2027) | https://learn.microsoft.com/defender-xdr/api-overview | Legacy API surface — migrate to Graph |

---

## 4. Microsoft Entra ID (Identity)

Identity protection, authentication, conditional access, and risk detection.

| Resource | URL | Description |
|----------|-----|-------------|
| Entra ID Documentation | https://learn.microsoft.com/entra/identity/ | Identity and access management |
| Conditional Access Overview | https://learn.microsoft.com/entra/identity/conditional-access/overview | Policy framework for access control |
| Identity Protection Overview | https://learn.microsoft.com/entra/id-protection/overview-identity-protection | Risk-based identity protection |
| Temporary Access Pass (TAP) | https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass | Passwordless onboarding |
| Manage OAuth Consent Requests | https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests | App consent governance |
| Token Protection (Conditional Access) | https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection | Token binding and AiTM/token theft defense |
| Create Service Principal | https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal | Service principal for API automation |
| MSAL Overview | https://learn.microsoft.com/entra/identity-platform/msal-overview | Microsoft Authentication Library |
| Phishing-Resistant MFA | https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths | FIDO2, certificate-based auth |
| **Entra Agent ID Overview** | https://learn.microsoft.com/entra/agent-id/what-is-microsoft-entra-agent-id | Identity & security framework for AI agents (Preview) |
| Entra Agent Identity Platform | https://learn.microsoft.com/entra/agent-id/ | Agent identity management, blueprints, OAuth protocols, governance |
| Entra SDK for Agent ID | https://learn.microsoft.com/entra/agent-id/microsoft-entra-sdk-for-agent-identities | Containerized SDK — token acquisition, validation, downstream API calls for 3rd-party agents |
| Agent OAuth Protocols | https://learn.microsoft.com/entra/agent-id/agent-oauth-protocols | OAuth 2.0 flows for agents: OBO, autonomous, agent-user-account |
| Agent Identity Blueprints | https://learn.microsoft.com/entra/agent-id/agent-blueprint | Reusable templates for agent identities with preconfigured permissions & policies |
| Conditional Access for Agents | https://learn.microsoft.com/entra/identity/conditional-access/agent-id | Extending CA policies to agent identities |
| Identity Protection for Agents | https://learn.microsoft.com/entra/id-protection/concept-risky-agents | Risk detection for agent identities |

---

## 5. Microsoft Security APIs

REST API endpoints used for programmatic access and MCP fallback scenarios.

| API Surface | Endpoint | Description |
|-------------|----------|-------------|
| Microsoft Graph Security API | `https://graph.microsoft.com/v1.0/security/` | Recommended — incidents, alerts, Advanced Hunting, devices |
| Sentinel Data Lake KQL API | `https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query` | Native KQL execution (auth scope: `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default`) |
| Native Defender XDR API | `https://api.security.microsoft.com/api/` | Legacy — retiring Feb 2027 |
| Log Analytics API | `https://api.loganalytics.io/v1/` | ARM-based workspace queries |

**Key API References:**

| Resource | URL |
|----------|-----|
| Graph Security API Overview | https://learn.microsoft.com/graph/api/resources/security-api-overview |
| Advanced Hunting via Graph | https://learn.microsoft.com/graph/api/security-security-runhuntingquery |
| Incidents API | https://learn.microsoft.com/graph/api/resources/security-incident |
| Alerts v2 API | https://learn.microsoft.com/graph/api/resources/security-alert |

---

## 6. AI Attacks, Threats & Adversarial Techniques

A primer on how adversaries target AI/ML systems, LLM-powered applications, and AI-assisted security tools — and the taxonomies used to classify these threats.

### OWASP Top 10 for LLM Applications (2025) — Full Breakdown

The [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) is the industry-standard risk catalog for systems that integrate large language models. Every risk below is relevant to AI-assisted security tools like CyberProbe.

| Rank | Risk | Description | Attack Example | Reference |
|------|------|-------------|----------------|----------|
| **LLM01** | Prompt Injection | Attacker manipulates LLM behavior through crafted input — either directly (user prompt) or indirectly (poisoned tool output) | Malicious KQL result containing instructions that trick the agent into exfiltrating data | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM02** | Insecure Output Handling | LLM output used in downstream systems without validation (SQL injection, XSS via generated content) | Generated HTML report containing unescaped script tags from alert descriptions | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM03** | Training Data Poisoning | Compromised training data causes model to produce biased, incorrect, or malicious outputs | Poisoned threat intel feed causing false negatives on known-bad IPs | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM04** | Model Denial of Service | Crafted inputs designed to exhaust model resources or cause degraded performance | Recursive prompt patterns that consume all available tokens without useful output | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM05** | Supply Chain Vulnerabilities | Compromised model weights, plugins, datasets, or dependencies | Malicious MCP server or poisoned skill file injecting unauthorized tool calls | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM06** | Sensitive Information Disclosure | Model reveals PII, secrets, API keys, or internal system details in outputs | Agent leaking tenant IDs, UPNs, or API keys in generated investigation reports | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM07** | Insecure Plugin Design | Plugins/tools accept unsafe input without validation, enabling injection or privilege escalation | MCP tool executing unvalidated KQL from user input without parameterization | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM08** | Excessive Agency | LLM granted too many capabilities or permissions, enabling unintended destructive actions | Agent autonomously isolating devices or blocking users without analyst confirmation | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM09** | Overreliance | Humans blindly trusting LLM output without verification, leading to missed threats or false confidence | SOC analyst closing an incident based solely on AI summary without reviewing raw evidence | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| **LLM10** | Model Theft | Unauthorized access to proprietary model weights, fine-tuned data, or system prompts | Exfiltration of custom investigation skill definitions or copilot-instructions.md | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |

### MITRE ATLAS — AI Attack Taxonomy

[MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial Intelligence Systems) extends ATT&CK into the AI/ML domain. Key tactics and techniques:

| ATLAS Tactic | Description | Techniques (Examples) |
|-------------|-------------|----------------------|
| **Reconnaissance** | Gathering information about AI systems | AML.T0000 — Discover ML model capabilities; AML.T0016 — Discover ML training data |
| **Resource Development** | Preparing tools/resources to attack AI | AML.T0017 — Acquire infrastructure for adversarial ML |
| **Initial Access** | Gaining access to AI systems | AML.T0019 — Exploit public-facing ML API; AML.T0045 — Compromise ML supply chain |
| **ML Attack Staging** | Preparing adversarial inputs | AML.T0043 — Craft adversarial data; AML.T0040 — ML model inference API access |
| **Execution** | Running adversarial techniques | AML.T0044 — Full ML model access; AML.T0025 — Prompt injection |
| **Persistence** | Maintaining access to AI systems | AML.T0020 — Poison training data; AML.T0018 — Backdoor ML model |
| **Evasion** | Avoiding AI detection | AML.T0015 — Evade ML model; AML.T0046 — Input manipulation |
| **Exfiltration** | Extracting data from AI systems | AML.T0024 — Extract ML model; AML.T0035 — Extract training data |
| **Impact** | Degrading AI system performance | AML.T0029 — Denial of ML service; AML.T0034 — Trigger model failure |

> **ATLAS Case Studies:** https://atlas.mitre.org/studies — Real-world examples of AI attacks including ChatGPT prompt injection, adversarial perturbation of malware classifiers, and model extraction via API.

### AI Attack Patterns Relevant to Security Operations

Attack patterns that specifically target AI-assisted security investigation workflows:

| Attack Pattern | Description | SOC Impact | Mitigation |
|---------------|-------------|------------|------------|
| **Indirect Prompt Injection** | Adversary plants instructions in data sources (alert descriptions, email subjects, hostname fields) that are ingested by the AI agent | Agent may skip investigating an entity, generate misleading report, or execute unintended actions | Input sanitization, prompt injection detection in tool outputs, evidence-based analysis rules |
| **Tool Poisoning** | Compromised MCP server returns manipulated data designed to alter agent behavior | False investigation conclusions, missed threats, fabricated evidence | Tool output validation, cross-referencing multiple sources, human-in-the-loop for critical decisions |
| **Adversarial Evasion** | Attacker crafts activity patterns designed to fall below AI detection thresholds | SOC AI tools fail to flag genuinely malicious behavior | Ensemble detection (combine AI + rule-based), threshold tuning, continuous model evaluation |
| **Data Poisoning via Feedback Loops** | Attacker contaminates training/fine-tuning data through manipulated incident classifications | Model learns incorrect patterns, future investigations degrade in quality | Audit classification decisions, protected validation sets, anomaly detection on feedback data |
| **Model Extraction** | Attacker queries the AI system systematically to reverse-engineer its detection logic | Adversary learns to evade specific detection rules or investigation patterns | Rate limiting, query pattern monitoring, model watermarking |
| **Copilot Prompt Exfiltration** | Attacker attempts to extract system instructions, skill definitions, or custom rules | Reveals investigation methodology, tool access patterns, and defensive blind spots | Instruction-level guardrails, output filtering, prompt leak detection |
| **Hallucination Exploitation** | Attacker relies on known AI tendency to fabricate plausible-sounding data | Analyst acts on non-existent evidence, false IOCs contaminate threat intel feeds | Evidence-based analysis (CyberProbe's global rule), mandatory source citation, human verification |

### Real-World AI Security Incidents & Research

| Incident / Research | Year | Description | Reference |
|-------------------|------|-------------|----------|
| ChatGPT Indirect Prompt Injection | 2023 | Researchers demonstrated data exfiltration via invisible instructions in web content | https://arxiv.org/abs/2302.12173 |
| Microsoft Tay Bot Manipulation | 2016 | Twitter chatbot poisoned via coordinated adversarial input | https://blogs.microsoft.com/blog/2016/03/25/learning-tays-introduction/ |
| Adversarial Patches in Object Detection | 2018 | Physical-world adversarial examples fooling ML classifiers | https://arxiv.org/abs/1712.09665 |
| GPT-4 System Prompt Extraction | 2023 | Techniques to extract hidden system instructions from deployed models | https://arxiv.org/abs/2311.16119 |
| Sleeper Agents in LLMs | 2024 | Anthropic research on backdoor behaviors surviving safety training | https://arxiv.org/abs/2401.05566 |
| AI-Generated Phishing at Scale | 2023 | Research showing LLMs can generate highly effective spear-phishing emails | https://arxiv.org/abs/2305.06972 |
| VirusTotal AI-Crafted Malware Analysis | 2024 | AI-generated polymorphic malware evading traditional signature detection | https://blog.virustotal.com/ |
| NIST AI Red-Teaming Guidelines | 2025 | Guidance for adversarial testing of AI systems | https://doi.org/10.6028/NIST.AI.600-1 |

### Defensive Strategies for AI-Powered Security Tools

| Strategy | Description | CyberProbe Implementation |
|----------|-------------|---------------------------|
| **Evidence-Based Analysis** | Never fabricate findings — base all conclusions on retrieved data | Global rule: mandatory source citation, explicit absence confirmation |
| **Human-in-the-Loop** | Require analyst confirmation for destructive or high-impact actions | Confirmation prompts for device isolation, user blocking, incident updates |
| **Input Validation** | Sanitize and validate all inputs to AI tools | MCP tool safety filters, Copilot instruction guardrails |
| **Output Verification** | Cross-reference AI outputs against multiple data sources | Multi-source enrichment (AbuseIPDB + IPInfo + Shodan + VPNapi) |
| **Least Privilege** | Limit AI agent permissions to minimum required | Read-only default queries, scoped MCP tool permissions |
| **Audit Trail** | Log all AI actions and decisions for accountability | Investigation JSON files with full methodology, query-level evidence |
| **Supply Chain Security** | Verify integrity of models, plugins, and MCP servers | MCP health checks, skill file version control, dependency pinning |
| **Prompt Injection Detection** | Monitor for injection attempts in tool outputs | Security requirements in Copilot instructions, alert on anomalous patterns |
| **Continuous Evaluation** | Regularly test AI tool accuracy and detection coverage | CTI-REALM benchmarks, periodic red-team exercises |

---

## 7. AI & LLM Security Frameworks

Frameworks for securing AI systems and evaluating AI-driven security tools.

| Resource | URL | Description |
|----------|-----|-------------|
| MITRE ATLAS (Adversarial Threat Landscape for AI Systems) | https://atlas.mitre.org/ | Tactics and techniques targeting AI/ML systems |
| OWASP Top 10 for LLM Applications (2025) | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | Top risks for LLM-powered applications |
| NIST AI Risk Management Framework (AI RMF) | https://www.nist.gov/itl/ai-risk-management-framework | AI risk management guidance |
| NIST AI 600-1: Generative AI Profile | https://doi.org/10.6028/NIST.AI.600-1 | Companion to AI RMF for generative AI |
| Microsoft Responsible AI Principles | https://www.microsoft.com/ai/principles-and-approach | Fairness, reliability, safety, privacy, inclusiveness, transparency, accountability |
| EU AI Act | https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai | European regulatory framework for AI |
| CTI-REALM (Microsoft) | https://www.microsoft.com/en-us/security/blog/ | Open-source benchmark for AI-driven detection rule generation (Microsoft Security Blog) |
| Project Glasswing (Anthropic) | https://www.anthropic.com/glasswing | Hardware-level security for AI systems (12-company coalition) |
| AI-SPM (AI Security Posture Management) | https://learn.microsoft.com/azure/defender-for-cloud/ai-security-posture | Defender for Cloud AI security posture |
| Google SAIF (Secure AI Framework) | https://safety.google/cybersecurity-advancements/saif/ | Google's framework for securing AI |
| CISA AI Security Guidelines | https://www.cisa.gov/ai | US government AI security guidance |

---

## 8. MITRE Frameworks

The MITRE ecosystem of threat modeling, defense, and adversary frameworks.

| Framework | URL | Description |
|-----------|-----|-------------|
| **MITRE ATT&CK** | https://attack.mitre.org/ | Adversary tactics, techniques, and procedures (TTPs) |
| ATT&CK Enterprise Matrix | https://attack.mitre.org/matrices/enterprise/ | Full enterprise technique matrix |
| ATT&CK for Cloud | https://attack.mitre.org/matrices/enterprise/cloud/ | Cloud-specific attack techniques |
| **MITRE ATLAS** | https://atlas.mitre.org/ | Adversarial techniques targeting AI/ML systems |
| ATLAS Case Studies | https://atlas.mitre.org/studies | Real-world AI attack case studies |
| **MITRE D3FEND** | https://d3fend.mitre.org/ | Defensive technique knowledge base |
| **MITRE CALDERA** | https://caldera.mitre.org/ | Adversary emulation platform |
| **MITRE Engage** | https://engage.mitre.org/ | Adversary engagement framework (deception, denial) |
| ATT&CK Navigator | https://mitre-attack.github.io/attack-navigator/ | Visual technique coverage mapping |

### Key ATT&CK Techniques Referenced in CyberProbe

| Technique ID | Name | Investigation Context |
|-------------|------|----------------------|
| T1078 | Valid Accounts | Compromised credential detection |
| T1078.004 | Cloud Accounts | Cloud identity abuse |
| T1110.003 | Password Spraying | Brute-force authentication attacks |
| T1098 | Account Manipulation | Privilege escalation detection |
| T1021.001 | Remote Desktop Protocol | Lateral movement analysis |
| T1557 | Adversary-in-the-Middle | AiTM phishing / token theft |
| T1539 | Steal Web Session Cookie | Session hijacking detection |
| T1550.001 | Application Access Token | Token replay attacks |
| TA0008 | Lateral Movement | Cross-device attack propagation |
| TA0006 | Credential Access | Credential harvesting techniques |

---

## 9. OWASP Standards

Web application and AI security best practices.

| Resource | URL | Description |
|----------|-----|-------------|
| OWASP Top 10 (2025) | https://owasp.org/www-project-top-ten/ | Web application security risks |
| OWASP Top 10 for LLM Applications (2025) | https://owasp.org/www-project-top-10-for-large-language-model-applications/ | AI/LLM-specific risks (prompt injection, data leakage, etc.) |
| OWASP API Security Top 10 | https://owasp.org/API-Security/ | REST/GraphQL API security risks |
| OWASP Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ | Security testing methodology |
| OWASP Cheat Sheet Series | https://cheatsheetseries.owasp.org/ | Practical secure coding guidance |

### OWASP LLM Top 10 — Relevance to CyberProbe

| Risk | OWASP LLM ID | CyberProbe Mitigation |
|------|-------------|----------------------|
| Prompt Injection | LLM01 | Input validation in MCP tool calls, Copilot instruction guardrails |
| Sensitive Information Disclosure | LLM06 | PII-free query library, config.json gitignored |
| Excessive Agency | LLM08 | Confirmation prompts for destructive actions, read-only default queries |
| Overreliance | LLM09 | Evidence-based analysis rule — never fabricate findings |

---

## 10. NIST Cybersecurity

US National Institute of Standards and Technology cybersecurity frameworks.

| Resource | URL | Description |
|----------|-----|-------------|
| NIST Cybersecurity Framework (CSF) 2.0 | https://www.nist.gov/cyberframework | Identify, Protect, Detect, Respond, Recover, Govern |
| NIST SP 800-53 Rev. 5 | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final | Security and privacy controls catalog |
| NIST SP 800-61 Rev. 3 | https://csrc.nist.gov/pubs/sp/800/61/r3/final | Incident handling guide |
| NIST SP 800-86 | https://csrc.nist.gov/pubs/sp/800/86/final | Guide to integrating forensic techniques |
| NIST SP 800-150 | https://csrc.nist.gov/publications/detail/sp/800-150/final | Guide to cyber threat information sharing |
| NIST AI RMF (AI 100-1) | https://www.nist.gov/itl/ai-risk-management-framework | AI risk management framework |
| NIST AI 600-1 | https://doi.org/10.6028/NIST.AI.600-1 | Generative AI profile |
| NIST SP 800-207 | https://csrc.nist.gov/publications/detail/sp/800-207/final | Zero Trust Architecture |

---

## 11. Threat Intelligence Services

External enrichment APIs and threat intelligence platforms integrated or referenced.

### Integrated in CyberProbe

| Service | URL | Integration | Free Tier |
|---------|-----|-------------|-----------|
| AbuseIPDB | https://www.abuseipdb.com/api | IP abuse confidence scoring | 1,000 checks/day |
| IPInfo.io | https://ipinfo.io/ | IP geolocation, ASN, VPN detection | 50K req/month |
| VPNapi.io | https://vpnapi.io/ | VPN/proxy/Tor/relay detection | 1K req/day |
| Shodan | https://www.shodan.io/ | Open ports, CVEs, services (+ InternetDB free) | InternetDB: unlimited |
| VirusTotal | https://www.virustotal.com/ | File hash, domain, URL analysis | 500 lookups/day |
| GreyNoise | https://www.greynoise.io/ | Internet background noise classification | Community: 50/day |

### Recommended (Free, No Key Required)

| Service | URL | Value | Integration Status |
|---------|-----|-------|-------------------|
| ThreatFox (abuse.ch) | https://threatfox-api.abuse.ch/ | C2 servers, malware families, IOC sharing | Planned |
| MalwareBazaar (abuse.ch) | https://bazaar.abuse.ch/api/ | Malware sample database | Planned |
| URLhaus (abuse.ch) | https://urlhaus-api.abuse.ch/ | Malicious URL database | Planned |
| PhishTank | https://phishtank.org/ | Community phishing URL verification | Planned |

### Recommended (Free Tier Available)

| Service | URL | Value |
|---------|-----|-------|
| AlienVault OTX | https://otx.alienvault.com/ | 80M+ IOCs, MITRE ATT&CK mapping, community pulse |
| Hybrid Analysis | https://www.hybrid-analysis.com/ | Sandbox detonation, behavioral analysis |
| URLScan.io | https://urlscan.io/ | Website scanning, screenshot, DOM analysis |
| Censys | https://censys.io/ | Internet-wide scan data, certificate transparency |
| MaxMind GeoIP2 | https://www.maxmind.com/ | GeoIP databases, ASN data |

### Microsoft Native Threat Intelligence

| Service | URL | Description |
|---------|-----|-------------|
| Defender Threat Intelligence (MDTI) | https://learn.microsoft.com/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti | IP/domain reputation, threat articles, CVE intel |
| Microsoft Threat Intelligence Blog | https://www.microsoft.com/security/blog/topic/threat-intelligence/ | Threat actor tracking, campaign analysis |

---

## 12. KQL & Query Language

Kusto Query Language references for Sentinel and Advanced Hunting.

| Resource | URL | Description |
|----------|-----|-------------|
| KQL Quick Reference | https://learn.microsoft.com/azure/data-explorer/kql-quick-reference | Operator and function cheat sheet |
| KQL Overview | https://learn.microsoft.com/azure/data-explorer/kusto/query/ | Complete language specification |
| Advanced Hunting Query Best Practices | https://learn.microsoft.com/defender-xdr/advanced-hunting-best-practices | Performance optimization tips |
| KQL (ASIM) Parsers | https://learn.microsoft.com/azure/sentinel/normalization-parsers-overview | Advanced Security Information Model |
| Sentinel Analytics Rules Templates | https://learn.microsoft.com/azure/sentinel/detect-threats-built-in | Built-in detection templates |
| GQL (Graph Query Language) | https://learn.microsoft.com/defender-xdr/advanced-hunting-graph | Entity graph traversal syntax |

### Community KQL Resources

| Resource | URL | Description |
|----------|-----|-------------|
| Microsoft 365 Defender Hunting Queries | https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries | Official KQL hunting queries from Microsoft |
| Azure Sentinel Community (GitHub) | https://github.com/Azure/Azure-Sentinel | Community detections, workbooks, playbooks |
| KQL Cafe | https://www.kqlcafe.com/ | Community KQL learning and examples |
| Must Learn KQL | https://github.com/rod-trent/MustLearnKQL | Rod Trent's KQL learning series |
| KQL Search | https://www.kqlsearch.com/ | Search engine for KQL examples |

---

## 13. AI Agents, MCP & Copilot

Model Context Protocol, GitHub Copilot extensibility, and AI agent standards.

| Resource | URL | Description |
|----------|-----|-------------|
| Model Context Protocol (MCP) Specification | https://modelcontextprotocol.io/ | Open standard for AI tool integration |
| MCP GitHub Repository | https://github.com/modelcontextprotocol | Protocol source, SDKs, examples |
| **Microsoft MCP Servers Catalog** | https://github.com/microsoft/mcp | Official Microsoft MCP servers — Azure, Sentinel, Foundry, M365, Fabric, Playwright, and more |
| VS Code Agent Skills | https://code.visualstudio.com/docs/copilot/customization/agent-skills | Agent skill definition standard |
| VS Code Copilot Customization | https://code.visualstudio.com/docs/copilot/copilot-customization | Custom instructions, prompt files |
| Agent Skills Standard | https://agentskills.io | Cross-platform agent skill interchange format |
| GitHub Copilot Documentation | https://docs.github.com/copilot | GitHub Copilot features and APIs |
| Azure MCP Server | https://github.com/microsoft/mcp#azure | Azure resource management via MCP |

### CyberProbe MCP Servers (Configured)

| MCP Server | Purpose |
|------------|---------|
| Sentinel Data Lake (Data Exploration) | KQL query execution, table discovery |
| Sentinel Triage | Incidents, alerts, Advanced Hunting, entity investigation |
| Defender Response | Device isolation, AV scans, forensic packages |
| Sentinel Graph | Blast radius, attack paths, entity relationships |
| Security Copilot Agent Creation | YAML-based agent deployment |
| Microsoft Learn | Documentation search and fetch |
| GitHub Copilot | Repository context and code intelligence |
| Azure | Resource management, Log Analytics fallback |

---

## 14. AI Governance & Agent 365

Governance frameworks, controls, and platforms for managing AI agents at enterprise scale — including Microsoft's Agent 365 platform for deploying and governing MCP-based agents across Microsoft 365.

### Microsoft Agent 365 Platform

| Resource | URL | Description |
|----------|-----|-------------|
| **Agent 365 MCP Platform (GitHub)** | https://github.com/bap-microsoft/MCP-Platform | Official repository — MCP server implementations for M365 services (Calendar, Mail, Teams, Word, SharePoint, Admin Center, Copilot Chat, User) |
| Agent 365 Service Endpoint | `https://agent365.svc.cloud.microsoft/agents/tenants/{tenant_id}/servers/` | Remote MCP server base URL — tenant-scoped agent deployment |
| Microsoft 365 Agents Toolkit | https://github.com/OfficeDev/microsoft-365-agents-toolkit/ | Build, test, and deploy agents for Teams and M365 Copilot |
| Microsoft 365 Agents SDK | https://learn.microsoft.com/microsoft-365-copilot/extensibility/ | SDK and extensibility for building custom agents on M365 |
| Microsoft 365 Copilot Extensibility | https://learn.microsoft.com/microsoft-365-copilot/extensibility/ | Extending Copilot with declarative agents, plugins, connectors |
| Copilot Studio | https://learn.microsoft.com/microsoft-copilot-studio/ | Low-code agent builder with enterprise governance controls |

### Microsoft Entra Agent ID (Identity for Agents)

| Resource | URL | Description |
|----------|-----|-------------|
| **Entra Agent ID Overview** | https://learn.microsoft.com/entra/agent-id/what-is-microsoft-entra-agent-id | Identity & security framework extending Entra to AI agents (Preview) |
| Entra Agent Identity Platform | https://learn.microsoft.com/entra/agent-id/ | Hub for agent identity management, blueprints, OAuth, security, governance |
| Entra SDK for Agent ID | https://learn.microsoft.com/entra/agent-id/microsoft-entra-sdk-for-agent-identities | Containerized SDK for 3rd-party agent auth — token acquisition, validation, downstream API calls |
| Agent OAuth Protocols | https://learn.microsoft.com/entra/agent-id/agent-oauth-protocols | OBO, autonomous app, agent-user-account OAuth 2.0 flows; FIC-based token exchange |
| Agent Identity Blueprints | https://learn.microsoft.com/entra/agent-id/agent-blueprint | Reusable templates — parent-child identity model with preconfigured permissions |
| Python SDK for Agent ID | https://learn.microsoft.com/entra/msidweb/agent-id-sdk/scenarios/using-from-python | Python integration guide |
| TypeScript SDK for Agent ID | https://learn.microsoft.com/entra/msidweb/agent-id-sdk/scenarios/using-from-typescript | TypeScript integration guide |
| Agent ID SDK Installation | https://learn.microsoft.com/entra/msidweb/agent-id-sdk/installation | SDK setup and containerized deployment |
| Security for AI (Entra integration) | https://learn.microsoft.com/security/security-for-ai/ | How Entra Agent ID integrates with Security for AI |
| Sign-in & Audit Logs for Agents | https://learn.microsoft.com/entra/agent-id/sign-in-audit-logs-agents | Agent authentication and activity logging |

### Agent 365 MCP Servers (Available)

| MCP Server | Repository Path | Endpoint Suffix | Description |
|------------|----------------|-----------------|-------------|
| Calendar Tools | `mcp_CalendarTools` | `/servers/mcp_CalendarTools` | Create, update, delete events; manage invites; check availability |
| Mail Tools | `mcp_MailTools` | `/servers/mcp_MailTools` | Create, send, reply, search emails via Graph Mail APIs |
| Teams Server | `mcp_TeamsServer` | `/servers/mcp_TeamsServer` | Manage chats, channels, users, messages |
| Word Server | `mcp_WordServer` | `/servers/mcp_WordServer` | Read, create, and collaborate on Word documents |
| M365 Copilot | `mcp_M365Copilot` | `/servers/mcp_M365Copilot` | Search across M365 content (docs, emails, sites, chats) |
| User / Me Server | `mcp_MeServer` | `/servers/mcp_MeServer` | User details, manager, team, org chart via Graph |
| Admin Tools | `mcp_AdminTools` | `/servers/mcp_AdminTools` | Microsoft Admin Center operations |
| OneDrive & SharePoint | `mcp_ODSPRemoteServer` | `/servers/mcp_ODSPRemoteServer` | File management across OneDrive and SharePoint |
| SharePoint Lists | `mcp_SharePointListsTools` | `/servers/mcp_SharePointListsTools` | Site management, document libraries, lists |

### AI Governance Principles & Frameworks

| Resource | URL | Description |
|----------|-----|-------------|
| **Microsoft Responsible AI Standard v2** | https://www.microsoft.com/ai/principles-and-approach | Fairness, reliability, safety, privacy, inclusiveness, transparency, accountability |
| Microsoft Responsible AI Impact Assessment | https://learn.microsoft.com/azure/machine-learning/concept-responsible-ai | Assessment guide for AI deployments |
| EU AI Act | https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai | European regulatory framework — risk-based AI classification |
| NIST AI RMF (AI 100-1) | https://www.nist.gov/itl/ai-risk-management-framework | US framework for AI risk management |
| ISO/IEC 42001:2023 | https://www.iso.org/standard/81230.html | AI management system standard — first international AI governance ISO |
| OECD AI Principles | https://oecd.ai/en/ai-principles | International principles for trustworthy AI |
| IEEE 7000 Series | https://ethicsinaction.ieee.org/ | Ethical design standards for autonomous and intelligent systems |
| Singapore AI Governance Framework | https://www.pdpc.gov.sg/help-and-resources/2020/01/model-ai-governance-framework | Model framework for responsible AI deployment |

### AI Agent Governance Controls

Key governance considerations when deploying AI agents in enterprise security operations:

| Control Area | Description | Implementation Guidance |
|-------------|-------------|------------------------|
| **Identity & Access** | Agents must authenticate with managed identities; enforce least-privilege RBAC | **Entra Agent ID** blueprints, Entra SDK for Agent ID, scoped Graph API permissions, tenant-bound Agent 365 endpoints |
| **Data Residency** | Agent-processed data must comply with organizational data sovereignty | Agent 365 tenant-scoped endpoints, Sentinel workspace region alignment |
| **Audit & Logging** | All agent actions must be logged for compliance and forensics | Investigation JSON files, MCP tool call logging, Azure Monitor integration |
| **Human-in-the-Loop** | Destructive or high-impact actions require analyst confirmation | CyberProbe confirmation prompts for device isolation, user blocking, incident updates |
| **Content Safety** | Agent outputs must be screened for harmful, biased, or fabricated content | Evidence-based analysis rule, prompt injection detection, output validation |
| **Supply Chain** | MCP servers, skills, and dependencies must be verified and version-controlled | MCP health checks, skill file integrity via Git, dependency pinning |
| **Model Transparency** | Organizations must document which models power their agents and their limitations | Methodology section in reports, model version tracking |
| **Continuous Monitoring** | Agent accuracy and behavior must be evaluated regularly | CTI-REALM benchmarks, red-team exercises, drift detection |

---

## 15. Industry Frameworks & Benchmarks

Standards and benchmarks used for security posture assessment and compliance.

| Framework | URL | Description |
|-----------|-----|-------------|
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks | Configuration hardening standards |
| CIS Controls v8 | https://www.cisecurity.org/controls | Prioritized security safeguards |
| ISO/IEC 27001:2022 | https://www.iso.org/standard/27001 | Information security management system |
| ISO/IEC 27035 | https://www.iso.org/standard/78973.html | Incident management standard |
| SOC 2 (AICPA) | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | Service organization controls for security |
| CISA Known Exploited Vulnerabilities | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | KEV catalog — actively exploited CVEs |
| CISA Cybersecurity Advisories | https://www.cisa.gov/news-events/cybersecurity-advisories | Threat advisories and bulletins |
| CVSS (Common Vulnerability Scoring System) | https://www.first.org/cvss/ | Vulnerability severity scoring |
| EPSS (Exploit Prediction Scoring System) | https://www.first.org/epss/ | Probability of exploit in the wild |

### Microsoft-Specific Benchmarks

| Benchmark | URL | Description |
|-----------|-----|-------------|
| Microsoft Cloud Security Benchmark (MCSB) | https://learn.microsoft.com/security/benchmark/azure/ | Azure security best practices |
| Secure Score (Defender) | https://learn.microsoft.com/defender-xdr/microsoft-secure-score | Organization security posture metric |
| Exposure Score | https://learn.microsoft.com/security-exposure-management/microsoft-security-exposure-management | Attack surface exposure metric |

---

## 16. Security Research & Blogs

Research, blog posts, and community resources relevant to CyberProbe investigations.

### Microsoft Security Research

| Resource | URL | Description |
|----------|-----|-------------|
| **Microsoft Security Blog (Official)** | https://www.microsoft.com/en-us/security/blog/ | Official Microsoft security blog — threat intelligence, product updates, research, advisories |
| Microsoft Threat Intelligence Blog | https://www.microsoft.com/security/blog/topic/threat-intelligence/ | Threat actor tracking (Midnight Blizzard, Volt Typhoon, etc.) |
| Microsoft Incident Response Blog | https://www.microsoft.com/security/blog/topic/incident-response/ | IR case studies and methodologies |
| CTI-REALM (Detection Rule Benchmark) | https://www.microsoft.com/en-us/security/blog/ | Open-source benchmark for AI-generated detection rules (Microsoft Security Blog) |

### Industry Research

| Resource | URL | Description |
|----------|-----|-------------|
| **Blog**: Defeating AiTM Phishing Attacks | https://techcommunity.microsoft.com/blog/microsoft-entra-blog/defeating-adversary-in-the-middle-phishing-attacks/1751777 | Token theft defense with Conditional Access |
| **Research**: JumpSec TokenSmith | https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/ | Device compliance bypass via token manipulation |
| SANS Reading Room | https://www.sans.org/reading-room/ | Security research papers and whitepapers |
| SANS Incident Handler's Handbook | https://www.sans.org/white-papers/33901/ | IR methodology reference |
| Mandiant Threat Research | https://www.mandiant.com/resources/blog | APT tracking, IR case studies |
| CrowdStrike Blog | https://www.crowdstrike.com/blog/ | Threat intelligence and adversary tracking |
| Unit 42 (Palo Alto Networks) | https://unit42.paloaltonetworks.com/ | Threat research and analysis |

### AI Security Research

| Resource | URL | Description |
|----------|-----|-------------|
| Anthropic Research | https://www.anthropic.com/research | AI safety and alignment research |
| Project Glasswing | https://www.anthropic.com/glasswing | Hardware-level confidential computing for AI |
| OpenAI Security | https://openai.com/security | AI model security and red-teaming |
| Google Project Zero | https://googleprojectzero.blogspot.com/ | Zero-day vulnerability research |
| Microsoft AI Red Team | https://www.microsoft.com/en-us/security/blog/topic/ai-and-machine-learning/ | AI security testing methodologies |

---

## 17. Open-Source Projects & Community

GitHub repositories and open-source tools referenced or recommended.

| Repository | URL | Description |
|------------|-----|-------------|
| Azure Sentinel (Community) | https://github.com/Azure/Azure-Sentinel | Detections, workbooks, playbooks, hunting queries |
| Microsoft 365 Defender Hunting Queries | https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries | Official hunting query library |
| stefanpems/ai-powered-soc | https://github.com/stefanpems/ai-powered-soc | SOC metrics MCP server (adapted for CyberProbe soc-metrics queries) |
| Must Learn KQL | https://github.com/rod-trent/MustLearnKQL | KQL learning series by Rod Trent |
| Awesome Copilot | https://github.com/github/awesome-copilot | Community Copilot extensions and skills |
| Azure CLI | https://github.com/Azure/azure-cli | Azure command-line interface |
| MCP Protocol | https://github.com/modelcontextprotocol | Model Context Protocol SDKs |

---

## 18. Training & Certification

Learning paths and certifications relevant to CyberProbe's technology stack.

### Microsoft Security Certifications

| Certification | URL | Focus Area |
|--------------|-----|------------|
| SC-200: Security Operations Analyst | https://learn.microsoft.com/certifications/security-operations-analyst/ | Sentinel, Defender XDR, KQL, incident response |
| SC-100: Cybersecurity Architect | https://learn.microsoft.com/certifications/cybersecurity-architect-expert/ | Security architecture, Zero Trust |
| SC-300: Identity and Access Administrator | https://learn.microsoft.com/certifications/identity-and-access-administrator/ | Entra ID, Conditional Access, identity protection |
| AZ-500: Azure Security Engineer | https://learn.microsoft.com/certifications/azure-security-engineer/ | Azure security controls, Defender for Cloud |
| AI-102: AI Engineer | https://learn.microsoft.com/certifications/azure-ai-engineer/ | Azure AI services, responsible AI |

### Free Learning Paths

| Resource | URL | Description |
|----------|-----|-------------|
| SC-200 Learning Path | https://learn.microsoft.com/training/paths/sc-200-mitigate-threats-using-microsoft-365-defender/ | Sentinel + Defender XDR hands-on labs |
| KQL Learning Path | https://learn.microsoft.com/training/paths/sc-200-utilize-kql-for-azure-sentinel/ | KQL from basics to advanced |
| Microsoft Security Virtual Training Days | https://www.microsoft.com/en-us/trainingdays/security | Free live training events |
| Ninja Training: Microsoft Sentinel | https://techcommunity.microsoft.com/blog/microsoftsentinelblog/become-a-microsoft-sentinel-ninja-the-complete-level-400-training/1246310 | Level 400 training |
| Ninja Training: Defender XDR | https://techcommunity.microsoft.com/blog/microsoftdefenderxdrblog/become-a-microsoft-365-defender-ninja/1789376 | Level 400 training |

### Industry Certifications

| Certification | Organization | Focus Area |
|--------------|-------------|------------|
| GIAC Security Operations (GCDA, GSOM) | SANS | SOC operations, detection engineering |
| Certified SOC Analyst (CSA) | EC-Council | SOC Level 1-2 operations |
| CompTIA CySA+ | CompTIA | Cybersecurity analyst fundamentals |
| OSCP | OffSec | Penetration testing (offensive context for defenders) |

---

## Contributing References

To add a reference to this document:

1. Verify the source is **official** (vendor documentation, standards body, peer-reviewed research, or authoritative blog)
2. Include the **full URL** (not shortened links)
3. Add a **brief description** of relevance to security investigation
4. Place it in the appropriate **section** above
5. Ensure no PII (real workspace names, UPNs, tenant IDs) is included in examples
