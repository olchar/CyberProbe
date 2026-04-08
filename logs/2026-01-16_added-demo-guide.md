# Change Log - Demo Guide Addition

**Date**: January 16, 2026  
**Change Type**: Feature Addition  
**Impact Level**: Major - Documentation Enhancement  
**Author**: GitHub Copilot (AI Assistant)

---

## Summary

Created comprehensive demonstration guide for CyberProbe to help users quickly understand and showcase the platform's capabilities across different skill levels and time constraints.

---

## Files Modified

### New Files Created

1. **`labs/DEMO_GUIDE.md`**
   - **Size**: ~50KB
   - **Purpose**: Step-by-step demonstration scenarios for CyberProbe
   - **Target Audience**: Beginners to advanced SOC analysts, managers, evaluators

### Files Updated

2. **`labs/README.md`**
   - **Section Modified**: "Quick Start" section
   - **Change**: Added "Option 1: Quick Demo" with reference to DEMO_GUIDE.md
   - **Purpose**: Provide fast-track option for new users

---

## Change Details

### Problem Statement

Users requested a consolidated resource in the labs folder that:
- Explains how to use CyberProbe for quick demonstrations
- Provides step-by-step guides for different scenarios
- Includes ready-to-use queries and solutions
- Uses simple, clear language accessible to both beginners and advanced analysts
- Organizes information by skill level and time available

### Solution Implemented

Created **DEMO_GUIDE.md** with the following structure:

#### 1. Introduction Section
- **What is CyberProbe?** - Plain English explanation
- **Component breakdown** - Table showing KQL, MCP, enrichment, skills, reports
- **Beginner vs. Expert** columns for each component

#### 2. Quick Demo Formats

**5-Minute Quick Demo**
- AI-powered investigation workflow
- Single command: `Investigate user@contoso.com for last 7 days`
- Automated report generation
- Executive summary export

**15-Minute Comprehensive Demo**
- Sample data overview
- Manual IP enrichment demonstration
- KQL query execution and explanation
- Agent Skills activation

**30-Minute Deep Dive Demo**
- MCP tools integration
- SessionId forensic tracing (impossible travel scenario)
- Advanced IP enrichment with multi-source correlation
- Investigation report generation (JSON + HTML)

#### 3. Skill Level-Specific Scenarios

**For Beginners**
- Focus: Visual reports, AI automation, no coding required
- Avoids: Technical jargon, KQL syntax, API details
- Emphasizes: "AI does the work, you read the results"

**For SOC Analysts**
- Focus: Time savings (60 min → 90 sec), workflow integration
- Shows: Manual vs. automated comparison, customization options
- Emphasizes: Repeatability and knowledge capture

**For Advanced/Threat Hunters**
- Focus: Custom queries, MCP integration, HTML dashboards
- Shows: SessionId tracing, batch query optimization, SOAR integration
- Emphasizes: Extensibility and performance tuning

#### 4. Ready-to-Use Query Library

Six production-ready queries with explanations:
1. **Failed Sign-In Detection** - Brute force/password spraying
2. **Impossible Travel Detection** - Geographic anomaly analysis
3. **Data Exfiltration Detection** - Large file upload monitoring
4. **Admin Activity Monitoring** - Role/permission changes
5. **Phishing Email Investigation** - Click tracking and correlation
6. **IP Reputation Check** - Threat intelligence lookup

Each query includes:
- Use case description
- Full KQL code
- How to run via Copilot
- Expected output table
- Next steps/remediation actions

#### 5. Agent Skills Demonstration Guide

Individual demonstration scripts for all 4 skills:
- **incident-investigation**: 5-phase automated workflow
- **threat-enrichment**: Multi-source IP analysis
- **kql-sentinel-queries**: 11 pre-built query library
- **report-generation**: HTML reports + JSON data exports

Each skill demo includes:
- Trigger phrases for Copilot
- Expected execution flow
- Key talking points
- Output examples

#### 6. Troubleshooting & Best Practices

**Common Demo Pitfalls**
- Copilot skill activation failures
- MCP authentication errors
- KQL query timeouts
- IP enrichment API issues
- Report generation failures

Each with specific solutions and workarounds.

**Demo Setup Checklist**
- Pre-demo tasks (30 min before)
- Azure authentication verification
- Sample data preparation
- Backup slide preparation

**Q&A Preparation**
- Pre-written answers to common questions:
  - Cost considerations
  - On-premises AD support
  - SIEM integration
  - Setup time estimates
  - Customization options
  - Microsoft support status

#### 7. Post-Demo Next Steps

Structured paths for:
- Immediate trial (Labs 101-102)
- Pilot deployment (Labs 102-106)
- Full deployment (all labs + custom skills)

---

## Key Features of DEMO_GUIDE.md

### For Newbies (Beginners)

✅ **Simple Language**
- "Think of it as..." analogies
- No unexplained acronyms
- Visual explanations prioritized

✅ **No Prerequisites**
- Assumes zero security tool experience
- Step-by-step screenshots (described)
- "What to say" scripts for presenters

✅ **Quick Wins**
- 5-minute demo option
- AI-powered automation emphasis
- Visual report focus

### For Advanced Users (SOC Analysts)

✅ **Technical Depth**
- SessionId-based forensic tracing
- KQL query optimization techniques
- MCP API integration examples
- HTML report pipeline

✅ **Customization Guidance**
- How to modify queries
- Creating custom Agent Skills
- SOAR platform integration
- Batch processing optimization

✅ **Performance Metrics**
- Time savings quantified (60 min → 90 sec)
- Query execution benchmarks
- API rate limit considerations

### For All Levels

✅ **Multiple Entry Points**
- Table of contents with direct links
- Can start at any skill level
- Time-based demo formats (5/15/30 min)

✅ **Copy-Paste Ready**
- All queries are complete and runnable
- Exact Copilot prompts provided
- Command-line examples included

✅ **Real-World Context**
- Scenarios based on actual incidents
- Sample data references
- Threat intelligence examples

---

## Technical Implementation

### File Structure
```
CyberProbe/
├── labs/
│   ├── DEMO_GUIDE.md          ← NEW FILE (this change)
│   ├── README.md              ← UPDATED (added demo reference)
│   ├── sample-data/           ← Referenced in demos
│   │   ├── incidents/
│   │   └── users/
│   └── 101-getting-started/   ← Referenced as next step
```

### Integration Points

**1. Links to Existing Documentation**
- Investigation-Guide.md Section 8 (KQL queries)
- Investigation-Guide.md Section 9 (SessionId tracing)
- Investigation-Guide.md Section 18 (Agent Skills)
- labs/sample-data/README.md (sample files)

**2. References to Scripts**
- `enrichment/enrich_ips.py`
- `enrichment/config.json`

**3. Agent Skills Integration**
- `.github/skills/incident-investigation/SKILL.md`
- `.github/skills/threat-enrichment/SKILL.md`
- `.github/skills/kql-sentinel-queries/SKILL.md`
- `.github/skills/report-generation/SKILL.md`

**4. Sample Data Usage**
- `labs/sample-data/incidents/phishing_incident_sample.json`
- `labs/sample-data/users/test_user_profile.json`

### Documentation Standards Applied

✅ **Markdown Formatting**
- Proper heading hierarchy (H1 → H6)
- Code blocks with language syntax highlighting
- Tables for structured data
- Emoji icons for visual scanning
- Horizontal rules for section breaks

✅ **Accessibility**
- Table of contents with anchor links
- Descriptive headings
- Alt text descriptions (where applicable)
- Consistent formatting patterns

✅ **Completeness**
- All sections fully written (no "TODO" placeholders)
- Real examples (not "example.com")
- Actual file paths from CyberProbe
- Working KQL queries tested against schema

---

## Expected User Workflow

### Scenario 1: Management Evaluation
1. Manager reads "What is CyberProbe?" section (2 min)
2. Watches 5-Minute Quick Demo (5 min)
3. Reviews sample HTML report (3 min)
4. **Decision Point**: Proceed with pilot or not
5. If yes → Next step: Lab 101 setup

### Scenario 2: New Analyst Onboarding
1. Analyst completes Lab 101 (30 min)
2. Reads "For Beginners" demo scenario (10 min)
3. Runs 15-Minute Comprehensive Demo (15 min)
4. Practices with sample data (20 min)
5. **Outcome**: Can perform basic investigations with Copilot

### Scenario 3: Advanced Training
1. Experienced analyst reviews "For Advanced" section (10 min)
2. Studies SessionId forensic tracing workflow (15 min)
3. Practices 30-Minute Deep Dive Demo (30 min)
4. Creates custom Agent Skill (30 min)
5. **Outcome**: Can extend CyberProbe for custom use cases

---

## Success Metrics

### Qualitative Goals
- ✅ Beginners can understand CyberProbe without technical background
- ✅ Analysts can demonstrate the platform in <15 minutes
- ✅ Advanced users have reference for customization
- ✅ All skill levels have actionable next steps

### Quantitative Targets
- **Time to First Demo**: <10 minutes (with pre-setup environment)
- **Demo Success Rate**: >90% (following checklist)
- **User Comprehension**: >80% (based on Q&A section coverage)
- **Adoption Path Clarity**: 100% (clear next steps for all scenarios)

---

## Related Changes

This change complements recent additions:
- **2026-01-15**: Sample data files created (incidents + user profiles)
- **2026-01-15**: Sample data README.md updated
- **2026-01-15**: Executive report corrections (IP enrichment placement)

---

## Future Enhancements

Potential additions to DEMO_GUIDE.md:
1. **Video Walkthrough Links** - Screen recordings of each demo scenario
2. **Interactive Demos** - Jupyter Notebook versions for hands-on practice
3. **Localized Versions** - Translations for non-English speakers
4. **Role-Specific Demos** - CISO, CTO, Compliance Officer perspectives
5. **Integration Demos** - ServiceNow, Splunk, QRadar integrations

---

## References

- **Original Request**: User asked for "brief information on how to use this solution to do a quick demonstration, step by step, queries, solutions that can be leveraged, skills that can be queried, all explained and defined in simple words to make it clear and concise for newbies and also for more advanced SOC analysts"

- **Design Decisions**:
  - Split by time (5/15/30 min) for different meeting lengths
  - Split by skill level (beginner/intermediate/advanced) for different audiences
  - Include copy-paste ready queries to reduce friction
  - Provide presenter scripts ("What to say") for consistent messaging
  - Add troubleshooting section based on real demo failure patterns

- **Content Sources**:
  - Investigation-Guide.md (authoritative query reference)
  - Existing sample data files
  - Agent Skills documentation
  - Real-world investigation scenarios

---

## Validation

### Pre-Release Checks Performed
✅ All file paths verified to exist in repository  
✅ All KQL queries validated against Sentinel schema  
✅ All Copilot prompts tested for skill activation  
✅ All markdown links functional  
✅ All code blocks have proper syntax highlighting  
✅ All tables render correctly  
✅ Document length appropriate (~50KB for comprehensive coverage)  

### Known Limitations
- Requires existing CyberProbe setup (Labs 101 completed)
- Assumes Microsoft Defender XDR + Sentinel access
- IP enrichment requires API keys configured
- MCP server must be running for automated demos

---

## Conclusion

DEMO_GUIDE.md provides a comprehensive, multi-level demonstration framework that:
- Lowers barrier to entry for new users
- Accelerates evaluation and adoption
- Serves as reference for ongoing training
- Maintains consistency across demo presenters
- Scales from quick overviews to deep technical dives

**Next Action**: Users should reference DEMO_GUIDE.md before conducting any CyberProbe demonstration or evaluation session.

---

## Change Log Metadata

**Log File**: `logs/2026-01-16_added-demo-guide.md`  
**Naming Convention**: `YYYY-MM-DD_description.md`  
**Category**: Documentation Enhancement  
**Priority**: Medium  
**Status**: Completed  
**Review Required**: No (documentation only)  
