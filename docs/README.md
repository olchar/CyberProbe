# Documentation Directory

This directory contains comprehensive documentation for the CyberProbe threat intelligence platform.

## Contents

### User Documentation

| File | Description |
|------|-------------|
| [SETUP_GUIDE.md](SETUP_GUIDE.md) | Complete setup guide: prerequisites, Azure auth, API keys, MCP servers, verification tests |
| [USER_GUIDE.md](USER_GUIDE.md) | Complete user guide for SOC analysts |
| [USER_GUIDE.html](USER_GUIDE.html) | HTML version of user guide |

### Technical Documentation

| File | Description |
|------|-------------|
| [AGENT_SKILLS.md](AGENT_SKILLS.md) | 12 VS Code Copilot agent skills for AI-assisted security investigations |
| [EXPOSURE_MANAGEMENT.md](EXPOSURE_MANAGEMENT.md) | Exposure management, CTEM, and CNAPP reference |
| [XDR_TABLES_AND_APIS.md](XDR_TABLES_AND_APIS.md) | XDR table schemas, APIs, and fallback patterns |
| [MERGE_SUMMARY.md](MERGE_SUMMARY.md) | Project merge and integration summary |

## Quick Links

- **Getting Started:** [SETUP_GUIDE.md](SETUP_GUIDE.md) (new user onboarding)
- **Project Overview:** [../README.md](../README.md)
- **AI Agent Routing:** [../.github/copilot-instructions.md](../.github/copilot-instructions.md) (auto-loaded by Copilot)
- **Investigation Guide:** [../Investigation-Guide.md](../Investigation-Guide.md) (human reference)
- **Lab Exercises:** [../labs/README.md](../labs/README.md)
- **Query Library:** [../queries/README.md](../queries/README.md)
- **MCP Apps:** [../mcp-apps/README.md](../mcp-apps/README.md)
- **Security Copilot:** [../security-copilot/](../security-copilot/)

## Documentation Structure

```
docs/
├── SETUP_GUIDE.md          # End-to-end setup & configuration
├── USER_GUIDE.md           # Primary user documentation
├── USER_GUIDE.html         # User guide (HTML format)
├── AGENT_SKILLS.md         # Security Copilot agent reference
├── EXPOSURE_MANAGEMENT.md  # CTEM & CNAPP reference
├── XDR_TABLES_AND_APIS.md  # XDR table schemas & APIs
└── MERGE_SUMMARY.md        # Technical integration notes
```

## Target Audience

- **New Users:** SETUP_GUIDE.md
- **SOC Analysts:** USER_GUIDE.md, AGENT_SKILLS.md
- **Security Engineers:** All documentation
- **Administrators:** MERGE_SUMMARY.md

## Related Documentation

- [Enrichment Configuration](../enrichment/CONFIG.md)
- [Lab Exercises](../labs/README.md)
- [Query Deployment](../queries/DEPLOYMENT_GUIDE.md)
- [MCP Apps (Inline Visualizations)](../mcp-apps/README.md)
- [Security Copilot Quickstart](../security-copilot/SECURITY_COPILOT_QUICKSTART.md)

---

**Last Updated:** April 13, 2026  
**Maintained by:** CyberProbe Security Team
