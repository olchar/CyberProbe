# CyberProbe Labs - Visual Learning Path

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CyberProbe Learning Journey                         │
└─────────────────────────────────────────────────────────────────────────────┘

START HERE ▼

┌─────────────────────────────────────────────────────────────────────────────┐
│                         📚 100-SERIES: FUNDAMENTALS                          │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌───────────────────┐
    │   Lab 101 (30m)   │  Getting Started
    │   ✓ Environment   │  • MCP setup
    │   ✓ First Query   │  • Navigation
    │   ✓ First Report  │  • Basics
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │   Lab 102 (45m)   │  Basic Investigations
    │   ✓ User Queries  │  • Sign-ins
    │   ✓ Anomalies     │  • Incidents
    │   ✓ JSON Export   │  • Reporting
    └─────────┬─────────┘
              │
      ┌───────┴────────┬────────────────┐
      │                │                │
      ▼                ▼                ▼
┌───────────┐    ┌───────────┐    ┌───────────┐
│Lab 103    │    │Lab 104    │    │Lab 105    │
│(60m)      │    │(60m)      │    │(45m)      │
│           │    │           │    │           │
│SessionId  │    │Threat     │    │Incident   │
│Tracing    │    │Hunting    │    │Response   │
│           │    │           │    │           │
│✓ Auth     │    │✓ Lateral  │    │✓ Triage   │
│  Chains   │    │  Movement │    │✓ Playbook │
│✓ IP       │    │✓ Malware  │    │✓ Timeline │
│  Enrichmt │    │✓ Beaconing│    │✓ Remediate│
└─────┬─────┘    └─────┬─────┘    └─────┬─────┘
      │                │                │
      └────────────────┴────────────────┘
                       │
                       ▼
              ┌───────────────┐
              │  Lab 106 (60m)│  MCP Automation
              │               │
              │  ✓ AI Agent   │  • Copilot Skills
              │  ✓ Automated  │  • Workflows
              │  ✓ Parallel   │  • Performance
              └───────┬───────┘
                      │
                      │
        ┌─────────────┴─────────────┐
        │   CHECKPOINT: Fundamentals │
        │   Ready for Real-World?    │
        └─────────────┬─────────────┘
                      │
                      ▼

┌─────────────────────────────────────────────────────────────────────────────┐
│                    🔥 200-SERIES: REAL-WORLD SCENARIOS                       │
└─────────────────────────────────────────────────────────────────────────────┘

Choose your investigation path:

    ┌─────────────────────┐       ┌─────────────────────┐
    │   Lab 201 (90m)     │       │   Lab 202 (90m)     │
    │   🎣 PHISHING       │       │   🔓 COMPROMISED    │
    │                     │       │      IDENTITY       │
    │  Incident #41398    │       │                     │
    │  3 Compromised      │       │  SessionId Deep     │
    │  Data Exfiltration  │       │  Geographic Anomaly │
    │                     │       │  Token Theft        │
    │  ✓ Email Analysis   │       │  ✓ SessionId Trace  │
    │  ✓ Click Tracking   │       │  ✓ MFA Bypass       │
    │  ✓ Post-Compromise  │       │  ✓ IP Enrichment    │
    │  ✓ DLP Violations   │       │  ✓ Risk Assessment  │
    └─────────────────────┘       └─────────────────────┘

    ┌─────────────────────┐       ┌─────────────────────┐
    │   Lab 203 (90m)     │       │   Lab 204 (90m)     │
    │   👤 INSIDER        │       │   📤 DLP            │
    │      THREAT         │       │      EXFILTRATION   │
    │                     │       │                     │
    │  Behavioral Analysis│       │  Multi-Stage Attack │
    │  Data Access        │       │  SharePoint → Cloud │
    │  After-Hours        │       │  Policy Violations  │
    │                     │       │                     │
    │  ✓ Baseline         │       │  ✓ File Tracking    │
    │  ✓ Anomalies        │       │  ✓ DLP Queries      │
    │  ✓ Exfiltration     │       │  ✓ External Sharing │
    │  ✓ HR Correlation   │       │  ✓ MITRE Mapping    │
    └─────────────────────┘       └─────────────────────┘

                      │
                      ▼
        ┌─────────────────────────────┐
        │   🎓 CERTIFICATION READY!   │
        │                             │
        │   You can now:              │
        │   ✅ Investigate any        │
        │      incident type          │
        │   ✅ Use SessionId tracing  │
        │   ✅ Automate with AI       │
        │   ✅ Generate reports       │
        │   ✅ Make recommendations   │
        └─────────────────────────────┘

```

---

## 📊 Learning Path Decision Tree

```
                    ┌─────────────────┐
                    │  What's your    │
                    │  experience?    │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                                 │
            ▼                                 ▼
    ┌───────────────┐                ┌───────────────┐
    │ New to SOC/   │                │ Experienced   │
    │ Defender XDR? │                │ Analyst?      │
    └───────┬───────┘                └───────┬───────┘
            │                                 │
            │ Start Lab 101                   │ Start Lab 103
            │                                 │ (Skip basics)
            ▼                                 ▼
    ┌───────────────┐                ┌───────────────┐
    │ Complete      │                │ Complete      │
    │ 101-106       │                │ 103-106       │
    │ in order      │                │ + 1 scenario  │
    └───────┬───────┘                └───────┬───────┘
            │                                 │
            └────────────────┬────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Choose scenario │
                    │ based on        │
                    │ incident type   │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┬─────────────┐
            │                │                │             │
            ▼                ▼                ▼             ▼
    ┌───────────┐    ┌───────────┐   ┌───────────┐  ┌──────────┐
    │ Phishing? │    │ Geographic│   │ Data Loss?│  │ Insider? │
    │ Lab 201   │    │ Anomaly?  │   │ Lab 204   │  │ Lab 203  │
    └───────────┘    │ Lab 202   │   └───────────┘  └──────────┘
                     └───────────┘

```

---

## 🎯 Lab Objectives Matrix

| Lab | KQL | MCP | SessionId | Enrichment | Reporting | Automation |
|-----|-----|-----|-----------|------------|-----------|------------|
| 101 | ⭐   | ⭐⭐⭐ | -         | -          | ⭐        | -          |
| 102 | ⭐⭐  | ⭐⭐⭐ | -         | ⭐         | ⭐⭐       | ⭐         |
| 103 | ⭐⭐⭐ | ⭐⭐  | ⭐⭐⭐      | ⭐⭐⭐       | ⭐⭐       | ⭐         |
| 104 | ⭐⭐⭐ | ⭐⭐  | ⭐        | ⭐⭐        | ⭐        | -          |
| 105 | ⭐⭐  | ⭐⭐⭐ | ⭐        | ⭐         | ⭐⭐⭐      | ⭐         |
| 106 | ⭐   | ⭐⭐⭐ | ⭐        | ⭐⭐        | ⭐⭐⭐      | ⭐⭐⭐       |
| 201 | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐      | ⭐⭐⭐       | ⭐⭐⭐      | ⭐⭐        |
| 202 | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐      | ⭐⭐⭐       | ⭐⭐⭐      | ⭐⭐        |
| 203 | ⭐⭐⭐ | ⭐⭐  | ⭐⭐       | ⭐⭐        | ⭐⭐⭐      | ⭐         |
| 204 | ⭐⭐⭐ | ⭐⭐⭐ | ⭐        | ⭐         | ⭐⭐⭐      | ⭐         |

⭐ = Basic Coverage | ⭐⭐ = Intermediate | ⭐⭐⭐ = Advanced

---

## 📅 Recommended Training Schedules

### 🏃 Fast Track (1 Day)
**For: Experienced analysts new to CyberProbe**
- Morning: Labs 101, 103, 106 (2.5 hours)
- Afternoon: Lab 201 (Phishing Investigation)
- **Total**: 4 hours hands-on

### 🚶 Standard Track (2 Days)
**For: SOC analysts transitioning to Defender XDR**
- Day 1 Morning: Labs 101-102 (1.25 hours)
- Day 1 Afternoon: Labs 103-104 (2 hours)
- Day 2 Morning: Labs 105-106 (1.75 hours)
- Day 2 Afternoon: Lab 201 or 202 (1.5 hours)
- **Total**: 6.5 hours

### 📚 Complete Track (1 Week)
**For: New SOC analysts or comprehensive training**
- Day 1: Labs 101-102 + Investigation Guide review
- Day 2: Labs 103-104
- Day 3: Labs 105-106
- Day 4: Labs 201-202 (scenarios)
- Day 5: Labs 203-204 + custom scenario practice
- **Total**: ~15 hours + self-study

---

## 🏆 Certification Path (Future)

```
Beginner Labs (101-106)
         ↓
[Basic Assessment]  ✓ Pass: CyberProbe Analyst Certified
         ↓
Advanced Labs (201-204)
         ↓
[Advanced Assessment]  ✓ Pass: CyberProbe Investigator Certified
         ↓
Custom Scenario Challenge
         ↓
[Expert Assessment]  ✓ Pass: CyberProbe Expert Certified
```

*(Certification program in development)*

---

## 🎨 Lab Features

Each lab includes:
- ✅ **Scenario Background** - Realistic incident context
- ✅ **Step-by-Step Guide** - Detailed instructions with screenshots
- ✅ **Pre-built KQL Queries** - Production-ready queries you can copy
- ✅ **Solutions & Answers** - Hidden hints to verify your work
- ✅ **Sample Data** - Sanitized investigation results for practice
- ✅ **Checkpoints** - Validate progress before moving forward
- ✅ **Pro Tips** - Best practices from Investigation Guide

---

**Ready to start learning?** → [Begin with Lab 101: Getting Started](../101-getting-started/)
