# CyberProbe Workshop Facilitator Guide

**For Instructors Leading CyberProbe Training Sessions**

---

## 📋 Workshop Planning

### Pre-Workshop Checklist (1 Week Before)

**Environment Setup**:
- [ ] Verify all participants have Defender XDR access
- [ ] Confirm Sentinel workspace access and workspace ID
- [ ] Test MCP server connectivity from VS Code
- [ ] Ensure Python 3.9+ installed on all machines
- [ ] Share `requirements.txt` for pip install
- [ ] Distribute API keys (AbuseIPDB, IPInfo) if using enrichment

**Materials Preparation**:
- [ ] Clone CyberProbe repository to shared location
- [ ] Prepare sample data files (if production access unavailable)
- [ ] Test all lab exercises end-to-end
- [ ] Print Quick Reference guides (optional)
- [ ] Set up screen sharing/projection

**Communication**:
- [ ] Send pre-work email (Lab 101 setup instructions)
- [ ] Share calendar invite with lab links
- [ ] Provide Investigation Guide PDF or link
- [ ] Set expectations: hands-on, bring questions

---

## 🎓 Workshop Formats

### Format 1: Half-Day Intro (4 hours)

**Audience**: Analysts new to CyberProbe, basic Defender XDR knowledge

**Schedule**:
```
09:00-09:15  Welcome & Introductions
09:15-09:45  Lab 101: Getting Started (guided)
09:45-10:30  Lab 102: Basic Investigations (paired exercise)
10:30-10:45  Break ☕
10:45-12:00  Lab 201: Phishing Investigation (group scenario)
12:00-12:30  Debrief: Questions, Next Steps, Resources
```

**Learning Outcomes**:
- Setup complete environment
- Run first automated investigation
- Understand real-world phishing scenario
- Know where to find resources

---

### Format 2: Full-Day Deep Dive (8 hours)

**Audience**: SOC analysts adopting CyberProbe, intermediate skills

**Schedule**:
```
09:00-09:15  Welcome & Workshop Overview
09:15-09:45  Lab 101: Getting Started
09:45-10:30  Lab 102: Basic Investigations
10:30-10:45  Break ☕
10:45-11:45  Lab 103: Advanced Auth Analysis
11:45-12:45  Lunch 🍕
12:45-13:30  Lab 104: Threat Hunting
13:30-14:15  Lab 105: Incident Response
14:15-14:30  Break ☕
14:30-15:30  Lab 106: MCP Automation
15:30-17:00  Lab 201 OR 202: Real-World Scenario
17:00-17:30  Wrap-up & Certification Discussion
```

**Learning Outcomes**:
- Complete fundamentals (100-series)
- Master SessionId tracing
- Practice threat hunting
- Execute full automated workflow
- Apply skills to realistic scenario

---

### Format 3: Advanced Workshop (2 Days)

**Audience**: Experienced analysts, team leads, security architects

**Day 1: Fundamentals & Core Skills**
```
09:00-09:15  Workshop Kickoff
09:15-10:00  Labs 101-102 (Self-Paced Review)
10:00-11:00  Lab 103: SessionId Tracing (Deep Dive)
11:00-11:15  Break
11:15-12:15  Lab 104: Threat Hunting (Hands-On)
12:15-13:15  Lunch
13:15-14:00  Lab 105: Incident Response Playbooks
14:00-15:00  Lab 106: Automation & AI Integration
15:00-15:15  Break
15:15-17:00  Custom Query Development Workshop
17:00-17:30  Day 1 Wrap-up
```

**Day 2: Real-World Scenarios & Mastery**
```
09:00-09:15  Day 2 Kickoff & Recap
09:15-10:45  Lab 201: Phishing Investigation (Full Walkthrough)
10:45-11:00  Break
11:00-12:30  Lab 202: Compromised Identity (Group Exercise)
12:30-13:30  Lunch
13:30-15:00  Lab 203 OR 204: Choose Your Scenario
15:00-15:15  Break
15:15-16:30  Bring Your Own Incident (BYOI) Session
16:30-17:30  Certification Exam (Optional)
17:30-18:00  Graduation & Next Steps
```

**Learning Outcomes**:
- Full mastery of all investigation techniques
- Custom query development skills
- Apply to real organizational incidents
- Certification-ready (if offered)

---

## 👥 Facilitation Tips

### Before Each Lab

**Set Context** (3 minutes):
- Explain why this skill matters
- Reference Investigation Guide section
- Show real-world example
- Set success criteria

**Example Script** (Lab 103):
> "In Lab 103, we're learning SessionId tracing - the gold standard for authentication forensics. When Identity Protection flags an impossible travel alert, you need to determine if it's a compromised account or a false positive. SessionId lets you trace the ENTIRE authentication chain to find the exact moment of initial login. This is covered in Section 9 of the Investigation Guide. By the end, you'll be able to definitively say 'this user was compromised' or 'this was legitimate travel.'"

### During Each Lab

**Monitor Progress**:
- Walk around (or monitor screen shares in virtual)
- Check for common blockers (date range errors, MCP connection issues)
- Encourage paired programming (2 analysts per machine)
- Celebrate wins ("Great! You found the SessionId!")

**Use Checkpoints**:
- Pause at each "Checkpoint" in lab guides
- Ask: "Who got X result?" (show of hands)
- Troubleshoot as group if <80% pass checkpoint
- Don't move forward until most participants ready

**Time Management**:
- Labs have target durations, but be flexible
- If behind: Skip optional exercises, focus on core concepts
- If ahead: Add challenges ("Now try finding IPs for this other user")
- Always preserve time for debrief

### After Each Lab

**Debrief** (5 minutes):
- Ask: "What was the key takeaway?"
- Clarify common mistakes
- Link to next lab: "In Lab 104, we'll use these queries for threat hunting"
- Take questions

### Common Mistakes to Watch For

**Lab 101**:
- ❌ Forgetting to add +2 days to date range
- ❌ Not activating Python virtual environment
- ✅ Fix: Show date calculator clearly, demo `.venv\Scripts\Activate.ps1`

**Lab 102**:
- ❌ Skipping User ID retrieval (Phase 1)
- ❌ Not checking if JSON already exists
- ✅ Fix: Emphasize workflow rules from Investigation Guide

**Lab 103**:
- ❌ Using wrong SessionId (picking random one vs suspicious IP's)
- ❌ Interpreting last event as initial auth (should be first!)
- ✅ Fix: Draw timeline on whiteboard showing first = auth, rest = tokens

**Lab 201**:
- ❌ Not tracking which user is which (violetm vs u3498 vs u11317)
- ❌ Skipping post-compromise analysis (stopping at click tracking)
- ✅ Fix: Create participant table: User | Click Time | First Suspicious IP

**Lab 106 (Microsoft Learn)**: 🆕
- ❌ Not understanding when to use docs_search vs code_sample_search
- ❌ Forgetting to specify language parameter for code samples
- ✅ Fix: Demo both tools side-by-side, emphasize language filtering

---

## 🎯 Engagement Strategies

### Interactive Techniques

**Think-Pair-Share**:
1. Pose question: "What does impossible travel mean?"
2. Give 1 min to think individually
3. Pair up, discuss 2 mins
4. Share with group

**Live Polling**:
- Use Slido or Teams polls
- "Which severity would you assign this incident? High/Medium/Low"
- Discuss why answers differ

**Hot Seat Rotation**:
- Rotate who's "driving" the screen share
- Each person executes one query, explains to group
- Builds confidence in speaking technical language

**Capture The Flag (CTF) Style**:
- Hide "flags" in lab data (e.g., "Find the attacker's email address")
- First person to find it explains how
- Gamifies learning

### Handling Questions

**Tactical Questions** ("How do I fix this error?"):
- Check error message against Investigation Guide Troubleshooting
- Demo fix on screen
- Have them retry

**Strategic Questions** ("Why SessionId vs just looking at IPs?"):
- Refer to Investigation Guide explanation
- Show example where IP-only would fail (token theft scenario)
- Connect to real incident

**Out-of-Scope Questions** ("Can this work with Splunk?"):
- Acknowledge question value
- Parking lot for offline discussion
- Stay focused on current lab

---

## 📊 Assessment & Certification

### Continuous Assessment (During Workshop)

**Lab Checkpoints**:
- Each lab has validation checklist
- Participants self-assess (honor system)
- Instructor spot-checks 3-5 participants per lab

**Hands-On Demos**:
- Lab 106: Participant demonstrates automated investigation
- Lab 201: Participant explains SessionId tracing for violetm

### Final Assessment (Optional)

**Format**: 60-minute scenario-based exam
**Passing**: 70% (28/40 points)

**Example Exam Structure**:
1. **Incident Analysis** (15 points)
   - Given: Incident JSON export
   - Task: Identify compromised user, trace auth chain, list IOCs
   
2. **Query Writing** (10 points)
   - Write KQL query to find all sign-ins from IP range
   - Write query to detect inbox rule creation

3. **Risk Assessment** (10 points)
   - Given: IP enrichment data
   - Task: Calculate risk score, justify rating (High/Med/Low)

4. **Remediation Plan** (5 points)
   - Multiple choice: Best remediation for phishing scenario
   - Short answer: List 3 immediate actions for DLP violation

**Grading Rubric**: Provided in separate assessment document

### Certification Levels

**Level 1: CyberProbe Analyst**
- Completed Labs 101-106
- Passed basic assessment (60%)
- Can run automated investigations

**Level 2: CyberProbe Investigator**
- Completed Labs 201-204
- Passed advanced assessment (70%)
- Can execute playbooks independently

**Level 3: CyberProbe Expert** (Future)
- Completed custom scenario challenge
- Created 3 custom queries for organization
- Mentored 2 analysts through Level 1

---

## 📚 Facilitator Resources

### Presentation Slides (Create These)

**Slide Deck 1: Workshop Intro** (10 slides)
1. Welcome & Agenda
2. Learning Objectives
3. CyberProbe Architecture Overview
4. Lab Structure (100 vs 200 series)
5. Investigation Guide Navigation
6. Success Metrics
7. Support Resources
8. Ground Rules (cameras on, ask questions, etc.)

**Slide Deck 2: SessionId Tracing Deep Dive** (15 slides)
- Use for Lab 103 introduction
- Visual diagram of SessionId chain
- Real vs fake compromise examples
- Step-by-step forensic workflow

### Demo Videos (Record These)

1. **Lab 101 Walkthrough** (10 min)
2. **SessionId Tracing Example** (15 min)
3. **Full Phishing Investigation** (30 min)
4. **Automation with Copilot** (20 min)

### Additional Materials

**Participant Workbook**:
- Checklist for each lab
- Note-taking space
- Quick reference cards

**Instructor Notes**:
- Talking points for each slide
- Anticipated questions & answers
- Time stamps for pacing

**Sample Data Package**:
- Sanitized investigation JSONs
- Sample IP enrichment results
- Mock incident reports

---

## 🐛 Troubleshooting Guide for Instructors

### Issue: MCP Server Not Connecting

**Symptoms**: `mcp_data_explorat_list_sentinel_workspaces` fails

**Quick Fixes**:
1. Check Azure AD authentication (re-login in VS Code)
2. Verify Sentinel workspace ID in config
3. Check participant has Security Reader role
4. Fallback: Use sample data from `labs/sample-data/`

### Issue: Date Range Returns No Results

**Symptoms**: Query executes but returns 0 rows

**Quick Fixes**:
1. Verify current date context (should be provided in lab)
2. Check +2 day rule applied correctly
3. Try broader range (14 days instead of 7)
4. Switch to sample data if production quiet

### Issue: Python Script Fails

**Symptoms**: `generate_report_from_json.py` crashes

**Quick Fixes**:
1. Check virtual environment activated
2. Verify all dependencies installed (`pip list`)
3. Check JSON format (valid syntax)
4. Fallback: Use pre-generated HTML report

### Issue: Participant Stuck, Blocking Progress

**Solutions**:
- Assign buddy to help while you continue with group
- Skip to next exercise, come back during break
- If widespread issue: Pause, demo solution, have all retry

---

## 💬 Sample Facilitation Scripts

### Opening Script (Full-Day Workshop)

> "Good morning everyone! Welcome to CyberProbe Deep Dive training. Over the next 8 hours, you're going to transform from CyberProbe beginner to confident investigator. We'll start with environment setup, progress through fundamental skills like SessionId tracing and threat hunting, and finish by investigating a realistic phishing campaign that compromised 3 users and exfiltrated 184 MB of financial data.
> 
> This is a hands-on workshop - you'll spend 90% of your time actually running queries and generating reports. I'm here to guide, troubleshoot, and answer questions, but the best learning happens when you're typing the KQL yourself.
> 
> Three ground rules: (1) Ask questions anytime - if you're confused, others probably are too. (2) Help each other - pair programming is encouraged. (3) Stay present - close email, focus on labs.
> 
> By end of day, you'll have completed your first full investigation and be ready to use CyberProbe in your SOC tomorrow. Let's get started with Lab 101..."

### Transition Script (Between Labs)

> "Great work on Lab 102! You just ran your first automated investigation. Key takeaway: Always check if JSON exists before re-querying - saves time and API costs.
> 
> In Lab 103, we're leveling up to SessionId tracing. This is the skill that separates good analysts from great ones. When you see an impossible travel alert, SessionId lets you say definitively whether it's a real compromise or just a VPN. We'll trace a complete authentication chain, identify the moment of initial login, and make a high-confidence risk assessment. This technique comes directly from Section 9 of the Investigation Guide.
> 
> Everyone ready? Let's dive in..."

### Microsoft Learn Integration Teaching Points 🆕

**When introducing Lab 106, Exercise 8:**

> "One of the biggest challenges in incident response is finding the RIGHT remediation procedures. You've all been there - Googling 'how to revoke OAuth app Azure AD', getting a mix of blog posts, Stack Overflow answers, and outdated Microsoft docs using deprecated cmdlets.
> 
> With the Microsoft Learn MCP Server, we're changing that workflow entirely. Instead of manually searching, you'll ask Copilot for remediation guidance and get official Microsoft documentation in seconds - always current, always authoritative, always production-ready.
> 
> Let me show you the difference..."

**Demo Script:**

1. **Show the old way** (2 minutes):
   - Open browser, Google "revoke OAuth application Azure AD"
   - Show mixed results: blogs, forums, old docs
   - Find Microsoft doc, but it references deprecated AzureAD module
   - "This is what we've all been doing - it works, but it's slow and error-prone"

2. **Show the new way** (2 minutes):
   - Open Copilot Chat in VS Code
   - Ask: "Show me PowerShell code to revoke malicious OAuth applications"
   - Watch as Copilot:
     - Searches Microsoft Learn automatically
     - Returns official Microsoft.Graph cmdlets
     - Includes documentation URLs for citation
   - "Same result in 10 seconds instead of 10 minutes, and guaranteed to be current"

3. **Explain the benefits** (1 minute):
   - ✅ **Speed**: 30-90x faster than manual research
   - ✅ **Accuracy**: Official Microsoft docs, not community interpretations
   - ✅ **Compliance**: Citable sources for audit reports
   - ✅ **Currency**: Always reflects latest security features
   - "This is especially valuable during active incidents - you can't afford to waste 15 minutes researching while an attacker is in your environment"

4. **Show integration** (2 minutes):
   - "During automated investigations, Copilot can automatically lookup remediation guidance"
   - "When it detects TOR IPs, it searches for Conditional Access blocking procedures"
   - "When it finds OAuth attacks, it retrieves official revocation playbooks"
   - "The generated reports include Microsoft Learn URLs - perfect for compliance documentation"

**Common Questions to Anticipate:**

**Q: "Does this require special API keys?"**
A: "No! Microsoft Learn is publicly accessible. The MCP Server is already configured in VS Code Copilot - no setup needed."

**Q: "What if I need docs for non-Microsoft products?"**
A: "This is specifically for Microsoft security products - Defender, Entra ID, Sentinel, Microsoft 365. For third-party tools, you'll still use traditional research methods."

**Q: "Can I trust the code samples to work in production?"**
A: "These come directly from Microsoft Learn documentation - they're production-tested by Microsoft. However, always test in a non-production environment first, especially for destructive operations like revoking access."

**Q: "What's the difference between docs_search and code_sample_search?"**
A: "Great question! 
- `docs_search`: Returns procedures, step-by-step guides, conceptual documentation
- `code_sample_search`: Returns executable code (PowerShell, KQL, Python) with language filtering
- Use docs_search first to understand WHAT to do, then code_sample_search to get the HOW (actual commands)"

### Wrap-Up Script

> "Congratulations on completing [X] labs today! Let's recap what you've mastered:
> - ✅ Environment setup and MCP queries
> - ✅ Automated investigation workflow (5 phases)
> - ✅ SessionId forensic tracing
> - ✅ [Other labs completed]
> 
> You now have all the skills to investigate real incidents in your environment. Your next steps:
> 1. Bookmark the Investigation Guide - it's your encyclopedia
> 2. Join the [Slack/Teams channel] for ongoing support
> 3. Complete remaining 200-series labs at your own pace
> 4. Apply this to a real incident in your SOC this week
> 
> I'll email you the completion certificates and access to advanced materials. Thank you for your engagement today - your questions made this better for everyone. Now go forth and investigate!"

---

## 📈 Workshop Success Metrics

Track these to improve future sessions:

- **Completion Rate**: % who finish all planned labs
- **Checkpoint Pass Rate**: % who pass each validation checkpoint
- **Post-Workshop Survey**: Satisfaction (1-5), confidence (1-5), likelihood to recommend
- **Time to First Investigation**: Days until participants use CyberProbe on real incident
- **Query Reuse Rate**: % of sample queries used in production within 30 days

**Target Metrics**:
- Completion: >85%
- Checkpoint Pass: >80%
- Satisfaction: >4.2/5
- Time to First Investigation: <7 days

---

**Good luck with your workshop! 🎓**

For questions about facilitation, contact the CyberProbe training team.
