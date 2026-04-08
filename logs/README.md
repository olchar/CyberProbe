# CyberProbe Change Logs

This directory contains detailed change logs documenting modifications, enhancements, and updates to the CyberProbe solution.

---

## Purpose

The logs folder serves as a historical record of:
- **Feature additions** - New capabilities, tools, or documentation
- **Bug fixes** - Corrections to existing functionality
- **Configuration changes** - Updates to settings, API keys, or integrations
- **Documentation updates** - Improvements to guides, READMEs, or examples
- **Performance optimizations** - Query improvements, caching, batch processing
- **Security enhancements** - Authentication updates, permission changes

---

## Naming Convention

All log files follow this naming pattern:

```
YYYY-MM-DD_brief-description.md
```

**Examples**:
- `2026-01-16_added-demo-guide.md`
- `2026-01-15_fixed-ip-enrichment-bug.md`
- `2026-01-14_optimized-kql-queries.md`
- `2026-01-13_updated-mcp-authentication.md`

**Rules**:
- Date format: ISO 8601 (YYYY-MM-DD)
- Description: Lowercase with hyphens (kebab-case)
- Max length: 50 characters total
- File extension: Always `.md` (Markdown)

---

## Log Entry Template

Each log file should contain:

```markdown
# Change Log - [Brief Title]

**Date**: [YYYY-MM-DD]  
**Change Type**: [Feature Addition|Bug Fix|Configuration|Documentation|Performance|Security]  
**Impact Level**: [Critical|Major|Minor|Trivial]  
**Author**: [Name or GitHub Handle]

---

## Summary

[1-2 paragraph overview of what was changed and why]

---

## Files Modified

### New Files Created
1. **`path/to/file.ext`**
   - Purpose: [What this file does]
   - Size: [Approximate size]

### Files Updated
2. **`path/to/existing.ext`**
   - Section Modified: [Which part]
   - Change: [What changed]

### Files Deleted
3. **`path/to/obsolete.ext`**
   - Reason: [Why removed]

---

## Change Details

[Detailed explanation of the changes, including:]
- Problem statement
- Solution implemented
- Technical decisions made
- Code examples (if applicable)
- Configuration changes (if applicable)

---

## Testing Performed

[List of tests run to validate changes:]
- [ ] Unit tests passed
- [ ] Integration tests passed
- [ ] Manual testing completed
- [ ] Documentation reviewed

---

## Impact Assessment

**Breaking Changes**: [Yes/No - if yes, explain]  
**Backward Compatibility**: [Yes/No]  
**Migration Required**: [Yes/No - if yes, provide steps]  

---

## Related Issues

- GitHub Issue #[number]: [Description]
- Related PR #[number]: [Description]

---

## Next Steps

[Follow-up actions or future enhancements]

---

## References

- [Links to related documentation]
- [External resources consulted]
```

---

## How to Use This Folder

### Creating a New Log Entry

1. **Determine the date**: Use today's date in YYYY-MM-DD format
2. **Write a brief description**: Summarize the change in 2-5 words
3. **Create the file**: `logs/YYYY-MM-DD_description.md`
4. **Use the template**: Copy from "Log Entry Template" above
5. **Fill in all sections**: Provide complete details
6. **Commit with message**: `git commit -m "Log: [Brief description]"`

### Finding a Specific Change

**By Date**:
```bash
ls logs/2026-01-*
```

**By Description**:
```bash
ls logs/*demo-guide*
```

**By Change Type** (requires grep):
```bash
grep -l "Change Type: Feature Addition" logs/*.md
```

### Viewing Recent Changes

List the 10 most recent log files:
```bash
ls -lt logs/*.md | head -10
```

---

## Maintenance

### Log Retention Policy

- **Keep all logs**: No automatic deletion
- **Archive annually**: Create `archive/YYYY/` folders for logs older than 1 year
- **Review quarterly**: Identify patterns, common issues, or improvement areas

### Log Quality Standards

✅ **Good Log Entry**:
- Complete summary explaining what and why
- All affected files listed with context
- Testing evidence included
- Clear impact assessment
- Actionable next steps

❌ **Poor Log Entry**:
- Vague summary ("Fixed stuff")
- Missing file paths
- No explanation of changes
- No testing details
- No impact analysis

---

## Current Logs

### 2026-01-16
- **[added-demo-guide.md](./2026-01-16_added-demo-guide.md)** - Comprehensive demonstration guide for all skill levels

### 2026-01-15
- (Previous logs to be added retrospectively if needed)

---

## Statistics

**Total Logs**: 1  
**Last Updated**: 2026-01-16  
**Most Common Change Type**: Documentation (100%)  
**Average Log Size**: ~15KB  

---

## Contributing

When making changes to CyberProbe:

1. **Always create a log entry** for non-trivial changes
2. **Use the naming convention** strictly
3. **Fill out the template** completely
4. **Link related issues/PRs** if applicable
5. **Commit the log** with your code changes

**Example workflow**:
```bash
# Make your changes
git add enrichment/new_feature.py

# Create the log
cp logs/README.md logs/2026-01-16_new-feature.md
# Edit the log file...

# Commit together
git add logs/2026-01-16_new-feature.md
git commit -m "Add new feature + log entry"
```

---

## Questions?

- See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines
- Check existing logs for examples
- Open an issue if you're unsure about logging requirements

---

**Last Updated**: January 16, 2026  
**Maintained By**: CyberProbe Contributors  
