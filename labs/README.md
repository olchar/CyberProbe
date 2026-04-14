# CyberProbe Labs & Workshops

Welcome to the CyberProbe hands-on learning environment! This lab series is designed to help you master security investigations using Microsoft Defender XDR, Sentinel, and MCP automation.

## 🎯 Learning Path Overview

### **100-Series: Fundamentals** (Start Here!)
Learn the core concepts, setup, and basic investigation workflows.

| Lab | Title | Duration | Prerequisites |
|-----|-------|----------|---------------|
| [101](./101-getting-started/) | **Getting Started with CyberProbe** | 30 min | None |
| [102](./102-basic-investigations/) | **Basic Security Investigations** | 45 min | Lab 101 |
| [103](./103-advanced-auth-analysis/) | **Advanced Authentication Analysis** | 60 min | Lab 102 |
| [104](./104-threat-hunting/) | **Threat Hunting Fundamentals** | 60 min | Lab 102 |
| [105](./105-incident-response/) | **Incident Response Workflow** | 45 min | Lab 102 |
| [106](./106-automation-mcp/) | **MCP Automation & AI Integration** | 60 min | Lab 101, 102 |

### **200-Series: Real-World Scenarios** (Apply Your Skills!)
Investigate realistic security incidents using playbooks from the Investigation Guide.

| Lab | Title | Duration | Use Case Reference |
|-----|-------|----------|-------------------|
| [201](./201-phishing-investigation/) | **Phishing Campaign Investigation** | 90 min | Playbook 2 |
| [202](./202-compromised-identity/) | **Compromised Identity Response** | 90 min | Playbook 4 |
| [203](./203-insider-threat/) | **Insider Threat Detection** | 90 min | Playbook 3 |
| [204](./204-dlp-exfiltration/) | **Data Exfiltration via DLP Violations** | 90 min | Query 10 |

---

## 🚀 Quick Start

### Option 1: Quick Demo (15-30 minutes)
**New to CyberProbe?** Start here for a fast overview!
- See [**DEMO_GUIDE.md**](./DEMO_GUIDE.md) for step-by-step demonstration scenarios
- Includes beginner-friendly explanations and ready-to-run queries
- Perfect for evaluating the platform or showing to stakeholders

### Option 2: Self-Paced Learning
1. Start with **Lab 101** to set up your environment
2. Progress through **Labs 102-106** to build core skills
3. Practice with **Labs 201-204** using realistic scenarios
4. Review the [Investigation Guide](../Investigation-Guide.md) for advanced techniques

### Option 3: Workshop Format (Instructor-Led)
- **Half-Day Workshop**: Labs 101, 102, 201
- **Full-Day Workshop**: Labs 101-105, choice of 201 or 202
- **Advanced Workshop**: Labs 103, 106, 202, 203

---

## 📋 Prerequisites

### Required Access
- ✅ Microsoft Defender XDR (E5 Security)
- ✅ Microsoft Sentinel workspace
- ✅ Azure AD admin or Security Reader role (minimum)
- ✅ VS Code with GitHub Copilot extension

### Required Software
- ✅ Python 3.9+ with virtual environment
- ✅ PowerShell 7.x
- ✅ Git for version control

### Recommended Knowledge
- Basic KQL (Kusto Query Language) syntax
- Understanding of Azure AD authentication
- Familiarity with security incident concepts

---

## 🎓 Learning Objectives

By completing this lab series, you will be able to:

**Fundamentals (100-Series)**
- ✅ Set up and configure CyberProbe in your environment
- ✅ Execute basic security investigations using KQL queries
- ✅ Trace authentication chains using SessionId forensics
- ✅ Hunt for threats across Defender XDR data sources
- ✅ Follow structured incident response workflows
- ✅ Automate investigations using MCP servers and AI

**Real-World Scenarios (200-Series)**
- ✅ Investigate phishing campaigns from email to post-compromise activity
- ✅ Analyze compromised identities with geographic anomalies
- ✅ Detect insider threats through behavioral analysis
- ✅ Track data exfiltration via DLP policy violations

**New Capabilities (2026)**
- ✅ Use the `exposure-management` skill for CTEM metrics and CNAPP posture
- ✅ Visualize exposure graphs, vulnerability dashboards, and compliance posture inline with MCP Apps
- ✅ Execute active response actions with the `defender-response` skill (isolate devices, disable accounts)
- ✅ Extract, enrich, and manage IOCs across investigations with `ioc-management`
- ✅ Analyze incident trends, detect campaigns, and calculate SOC KPIs with `incident-correlation-analytics`
- ✅ Perform endpoint forensics with `endpoint-device-investigation` (process trees, lateral movement, CVEs)
- ✅ Generate and validate custom KQL queries with `kql-query-builder` (331+ table schemas)
- ✅ Convert Sigma rules and Splunk SPL to Sentinel analytics rules with `detection-engineering`

---

## 📁 Lab Structure

Each lab contains:

```
lab-folder/
├── README.md           # Lab guide with objectives and steps
├── scenario.md         # Detailed scenario background (200-series)
├── queries/            # Pre-built KQL queries for the lab
├── solutions/          # Sample solutions and answers
└── resources/          # Additional reference materials
```

---

## 🛠️ Lab Environment Setup

### Initial Setup (Before Lab 101)

1. **Clone CyberProbe Repository**
   ```bash
   git clone https://github.com/yourusername/CyberProbe.git
   cd CyberProbe
   ```

2. **Create Python Virtual Environment**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. **Configure API Keys** (if using threat intelligence)
   ```bash
   cp enrichment/config.json.template enrichment/config.json
   # Edit config.json with your API keys
   ```

4. **Verify MCP Server Access**
   - Ensure Sentinel MCP server is configured in VS Code
   - Test connection with `mcp_data_explorat_list_sentinel_workspaces`

---

## 📊 Sample Data

For environments without access to production Defender XDR data, we provide:

- **[Sample KQL Query Results](./sample-data/)** - Sanitized investigation data
- **[Mock Incident Data](./sample-data/incidents/)** - Realistic incident JSON files
- **[Test User Profiles](./sample-data/users/)** - Fictional user accounts for practice

> **Note**: Sample data is for training purposes only. Always use production data in real investigations.

---

## 🎯 Skill Checkpoints

Track your progress with these milestones:

### ☑️ Beginner (Labs 101-102)
- [ ] Execute a basic user investigation
- [ ] Query sign-in logs by application and location
- [ ] Identify security incidents involving a user
- [ ] Generate an investigation report

### ☑️ Intermediate (Labs 103-105)
- [ ] Trace authentication chains using SessionId
- [ ] Hunt for lateral movement patterns
- [ ] Respond to a phishing incident
- [ ] Analyze IP threat intelligence

### ☑️ Advanced (Lab 106, 200-Series)
- [ ] Automate investigations using MCP + AI
- [ ] Investigate a multi-stage attack scenario
- [ ] Detect insider threat behavioral patterns
- [ ] Track data exfiltration across multiple data sources

---

## 💡 Tips for Success

**For Analysts:**
- 📖 Keep the [Investigation Guide](../Investigation-Guide.md) open as reference
- 🔍 Start with sample queries (Section 8) before writing custom KQL
- ⏱️ Time yourself to build investigation efficiency
- 📝 Document your findings in the investigation report template

**For AI-Assisted Investigations:**
- 🤖 Follow the automated workflow in Quick Start Guide (Investigation Guide)
- ✅ Always verify JSON investigation files exist before re-querying
- 🔗 Use SessionId tracing for authentication anomalies (Section 9)
- 📊 Leverage IP enrichment data from investigation JSON files

---

## 🤝 Contributing

Have an idea for a new lab scenario? Want to improve existing content?

1. Fork the repository
2. Create a new lab in the appropriate series (100 or 200)
3. Follow the lab template structure
4. Submit a pull request with your changes

---

## 📚 Additional Resources

- [Investigation Guide](../Investigation-Guide.md) - Complete reference manual
- [Agent Skills](../.github/skills/) - 12 VS Code Copilot automation skills
- [Enrichment Scripts](../enrichment/) - Threat intelligence integration (AbuseIPDB, IPInfo, VPNapi, Shodan, VirusTotal)
- [Report Templates](../reports/) - Investigation report examples
- [MCP Apps](../mcp-apps/) - Interactive inline visualizations (exposure graph, vuln dashboard, compliance posture)
- [Query Library](../queries/) - 40+ verified KQL queries organized by domain (identity, endpoint, email, network, cloud, SOC metrics)
- [XDR Tables & APIs](../docs/XDR_TABLES_AND_APIS.md) - Complete table schemas, API endpoints, and fallback patterns
- [Exposure Management Guide](../docs/EXPOSURE_MANAGEMENT.md) - CTEM framework and scoring methodologies

---

## 🆘 Support

**Questions or Issues?**
- 📧 Review the [Troubleshooting Guide](../Investigation-Guide.md#16-troubleshooting-guide)
- 💬 Check the FAQ in each lab's README
- 🐛 Report bugs via GitHub Issues

---

## 📜 License

This lab content is provided as-is for educational purposes. Ensure you have proper authorization before running queries against production environments.

---

**Ready to get started?** Begin with [Lab 101: Getting Started with CyberProbe](./101-getting-started/) →
