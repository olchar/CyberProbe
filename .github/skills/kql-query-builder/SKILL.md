# KQL Query Builder & Sentinel Analytic Rules Generator

## Purpose

This skill enables AI-assisted creation, validation, and optimization of KQL (Kusto Query Language) queries for security investigations and automated generation of Microsoft Sentinel Analytic Rules. It leverages the KQL Search MCP server to provide schema-validated queries, GitHub community examples, and ASIM normalization support.

**CRITICAL: Table Usage Rules**
- ✅ **ONLY use tables from Microsoft Sentinel Data Lake** (SigninLogs, AuditLogs, SecurityAlert, etc.)
- ✅ **Reference Investigation-Guide.md Section 8** for complete list of available tables
- ❌ **NEVER use Advanced Hunting tables** (IdentityLogonEvents, IdentityDirectoryEvents, DeviceEvents)
- ❌ **NEVER assume table existence** - always validate against Investigation Guide first

**Primary Use Cases:**
1. Generate validated KQL queries for Sentinel Data Lake investigations
2. Create custom Sentinel Analytic Rules with proper MITRE ATT&CK mapping
3. Validate existing queries against Sentinel table schemas
4. Convert natural language investigation requirements into production-ready KQL
5. Build ASIM-normalized queries for multi-source correlation
6. Search GitHub for community detection patterns and hunting queries

**Sentinel Data Lake Tables (Use ONLY These):**
- SigninLogs - Azure AD/Entra ID sign-in events
- AuditLogs - Azure AD/Entra ID audit logs
- SecurityAlert - Microsoft Defender alerts, Sentinel alerts
- SecurityIncident - Sentinel incidents
- CommonSecurityLog - CEF/Syslog data from firewalls, proxies
- OfficeActivity - Microsoft 365 audit logs
- AADRiskDetections - Identity Protection risk detections
- AADUserRiskEvents - User risk events
- AADServicePrincipalRiskEvents - Service principal risks
- ThreatIntelligenceIndicator - Threat intelligence IOCs

**See Investigation-Guide.md Section 8 for complete table documentation and examples.**

---

## When to Use This Skill

Use this skill when:
- ✅ User asks to "create a KQL query" or "generate a query for..."
- ✅ User requests a Sentinel Analytic Rule for specific threat scenarios
- ✅ User needs to validate or optimize existing KQL queries
- ✅ User wants to search for community detection rules or hunting queries
- ✅ Investigating security incidents and need custom queries for Sentinel Data Lake
- ✅ Building ASIM parsers or normalized security event queries
- ✅ Need to discover which Sentinel tables contain specific data

**MANDATORY WORKFLOW:**
1. **Before generating ANY query** - Check Investigation-Guide.md Section 8 for table availability
2. **Validate table names** - Only use tables documented in Investigation Guide
3. **Generate query** - Use Sentinel Data Lake table names (SigninLogs, not IdentityLogonEvents)
4. **Test query** - Verify syntax with Sentinel MCP server execution

Do NOT use this skill when:
- ❌ User is asking general questions about KQL syntax (use documentation search instead)
- ❌ Executing queries (use Sentinel MCP server tools for execution)
- ❌ User wants pre-built queries only (use sample queries from Investigation Guide Section 8)

---

## Available KQL Search MCP Tools

### Schema Intelligence & Query Generation (13 tools)

**Core Query Generation:**
1. **generate_kql_query** - Generate fully validated KQL from natural language
   - Parameters: `description` (required), `table_name` (optional), `time_range` (optional), `columns` (optional), `filters` (optional), `limit` (optional)
   - Returns: Validated query with schema verification, Microsoft Learn docs, explanations
   - Use when: Creating new queries from scratch

2. **validate_kql_query** - Validate existing KQL for correctness
   - Parameters: `query` (required)
   - Returns: Validation status, errors, warnings, fix suggestions
   - Use when: Checking query syntax before execution or optimization

3. **generate_query_template** - Get ready-to-use query templates
   - Parameters: `table_name` (required), `include_comments` (optional, default: true)
   - Returns: Template with common filters, time ranges, column selections
   - Use when: Need starting point for specific table

4. **generate_query_from_natural_language** - Create complete query from description
   - Parameters: `query` (required - natural language description)
   - Returns: Complete KQL with appropriate table, filters, aggregations
   - Use when: User describes what data they need in plain English

**Schema Discovery:**
5. **get_table_schema** - Get complete schema for specific table
   - Parameters: `table_name` (required)
   - Returns: All columns with types, descriptions, join suggestions, examples
   - Use when: Need to understand table structure before query creation

6. **search_tables** - Find tables using natural language
   - Parameters: `query` (required), `max_results` (optional, default: 10)
   - Returns: Ranked tables with relevance scores, descriptions, common columns
   - Use when: User asks "where can I find [type of data]?"

7. **list_table_categories** - Browse 57 table categories
   - Returns: Complete category list (Authentication & Identity, Security & Threats, Email & Collaboration, etc.)
   - Use when: User wants to explore available data sources

8. **get_tables_by_category** - Get all tables in category
   - Parameters: `category` (required)
   - Returns: Tables in category with descriptions
   - Use when: Browsing specific data domain

9. **find_column** - Find which tables contain specific column
   - Parameters: `column_name` (required)
   - Returns: All tables with that column, data types
   - Use when: Looking for specific field across multiple tables

10. **get_schema_statistics** - View schema coverage stats
    - Returns: Total tables, categories, product coverage
    - Use when: Understanding available data scope

**Documentation & Examples:**
11. **get_query_documentation** - Get Microsoft Learn docs for table/query
    - Parameters: `query` (optional), `table_name` (optional)
    - Returns: Table reference, operator docs, KQL reference links
    - Use when: Need official Microsoft documentation

12. **check_microsoft_docs_mcp** - Get Microsoft Docs MCP installation info
    - Returns: Installation guide, benefits, configuration examples
    - Use when: User needs enhanced documentation access

13. **search_github_examples_fallback** - Search GitHub for unvalidated examples
    - Parameters: `table_name` (required), `description` (optional)
    - Returns: GitHub examples with warnings
    - Use when: Table not in schema index (custom tables)

### GitHub Community Query Search (8 tools)

**Universal Search:**
14. **search_kql_queries** - Search ALL GitHub for KQL queries
    - Parameters: `query` (required), `max_results` (optional, default: 5, max: 50), `include_context` (optional, default: true), `sort_by` (optional: 'relevance'/'stars'/'updated')
    - Returns: KQL queries with syntax highlighting, repo info, descriptions, context, source links
    - Use when: Looking for community detection rules, hunting queries, or examples

15. **get_kql_from_file** - Extract queries from specific GitHub file
    - Parameters: `owner` (required), `repo` (required), `path` (required), `include_context` (optional, default: true)
    - Returns: All queries in file with descriptions, context, metadata
    - Use when: Found specific file in search results, need full content

16. **search_kql_repositories** - Find repos containing KQL queries
    - Parameters: `query` (required)
    - Returns: Repo names, descriptions, star counts, URLs, languages
    - Use when: Looking for query collections or specific detection rule repos

**Targeted Repository Search:**
17. **search_repo_kql_queries** - Search within specific repo
    - Parameters: `owner` (required), `repo` (required), `query` (required), `max_results` (optional), `include_context` (optional)
    - Returns: Queries from specified repo with paths, descriptions, relevance scores
    - Use when: Searching Azure/Azure-Sentinel or microsoft/Microsoft-365-Defender-Hunting-Queries

18. **search_user_kql_queries** - Search all repos from user/org
    - Parameters: `user` (required), `query` (required), `max_results` (optional), `include_context` (optional), `sort_by` (optional)
    - Returns: Queries from all user/org repos with repo names, locations, context
    - Use when: Searching all Microsoft or Azure organization queries

19. **search_favorite_repos** - Search configured favorite repos
    - Parameters: `query` (required), `max_results` (optional), `include_context` (optional)
    - Requires: `FAVORITE_REPOS` environment variable (comma-separated owner/repo list)
    - Returns: Queries from favorites with repo names, paths, context
    - Use when: Searching frequently-used repos

**Cache & Rate Limits:**
20. **get_rate_limit** - Check GitHub API rate limit status
    - Returns: Rate limit, remaining requests, reset time, used count
    - Use when: Need to verify API quota before large searches

21. **get_cache_stats** - View cache performance stats
    - Parameters: `clear_cache` (optional, default: false)
    - Returns: Search cache size, file cache size, hit rates, TTL info
    - Use when: Optimizing performance or troubleshooting

### ASIM Schema Tools (13 tools)

**Schema Discovery:**
22. **search_asim_schemas** - Search ASIM schemas by keyword
    - Parameters: `query` (required - e.g., "authentication", "network", "file", "dns")
    - Returns: Schema names/versions, status (GA/Preview), descriptions, key fields, entities
    - Use when: Need normalized security event schemas

23. **get_asim_schema_info** - Get comprehensive schema details
    - Parameters: `schemaName` (required - e.g., "authentication_event", "network_session")
    - Returns: All fields with classifications, types, logical types, entity info, key fields, relationships, use cases
    - Use when: Building ASIM-normalized queries

24. **get_asim_field_info** - Get details on specific ASIM field
    - Parameters: `fieldName` (required - e.g., "EventStartTime", "UserName", "EventResult")
    - Returns: Type, logical type, class (Mandatory/Recommended/Optional), description, examples, allowed values, related fields
    - Use when: Understanding specific ASIM field requirements

25. **list_asim_schemas** - List all 11 ASIM schemas
    - Returns: All schemas with versions, status, descriptions, entities, supported sources
    - Use when: Browsing available ASIM schemas

26. **search_asim_fields** - Search fields across all schemas
    - Parameters: `query` (required - search term for fields)
    - Returns: Matching fields, names/types, containing schemas, descriptions, examples
    - Use when: Finding specific field across ASIM schemas

27. **get_asim_schema_relationships** - Get schema relationships
    - Parameters: `schemaName` (required)
    - Returns: Related schemas, relationship descriptions, cross-schema field mappings
    - Use when: Building multi-schema correlation queries

28. **get_asim_logical_types** - Get ASIM logical types reference
    - Returns: All logical types, descriptions, examples, formatting requirements
    - Use when: Understanding ASIM data type conventions

29. **list_available_asim_schemas** - List schemas for validation
    - Returns: Complete schema list with versions, status, descriptions, field counts
    - Use when: Overview of ASIM schema catalog

**Query & Parser Generation:**
30. **generate_asim_query_template** - Generate ASIM query template
    - Parameters: `schemaName` (required)
    - Returns: Complete KQL template, standard filters, field selections, best practices, query explanation
    - Use when: Creating ASIM-normalized queries

31. **get_asim_parser_recommendations** - Get parser naming/best practices
    - Parameters: `schemaName` (required)
    - Returns: Unifying parser naming, source-specific patterns, recommendations, template examples, docs links
    - Use when: Creating ASIM parsers

**Parser Validation:**
32. **validate_asim_parser** - Validate parser against schema requirements
    - Parameters: `schemaName` (required), `parserName` (required), `parserFields` (required - array of field names)
    - Returns: Validation status (passed/issues), missing mandatory/recommended fields, extra fields, coverage summary
    - Use when: Verifying ASIM parser implementation

33. **get_asim_parser_requirements** - Get mandatory/recommended fields
    - Parameters: `schemaName` (required)
    - Returns: Mandatory fields with descriptions, recommended fields with descriptions, total field count
    - Use when: Planning ASIM parser development

34. **compare_parser_to_schema** - Compare parser fields to schema
    - Parameters: `schemaName` (required), `parserFields` (required - array)
    - Returns: Field coverage percentage, matched/unmatched fields, missing fields (by requirement level), gap analysis
    - Use when: Analyzing parser completeness

---

## Workflow for KQL Query Generation

### Workflow 1: Create Investigation Query from Natural Language

**User Request Example:** "I need a query to find failed sign-ins from the last 24 hours for admin accounts"

**Step-by-Step Process:**

1. **Generate Validated Query:**
```
Call: generate_kql_query
Parameters: {
  "description": "Find failed sign-ins from the last 24 hours for admin accounts",
  "time_range": "24h",
  "limit": 100
}
```

2. **Review Output:**
   - Validated KQL query with schema verification
   - Microsoft Learn documentation links
   - Query explanation and usage notes
   - Validation results (errors/warnings if any)

3. **Optimize if Needed:**
   - If validation shows warnings, call `validate_kql_query` with modifications
   - If need to understand table better, call `get_table_schema` for SigninLogs
   - If need community examples, call `search_kql_queries` with "failed login admin accounts"

4. **Present to User:**
   - Provide complete query with comments
   - Include Microsoft Learn reference links
   - Suggest execution method (Sentinel workspace query or Investigation-Guide.md patterns)

**Expected Query Output:**
```kql
// Failed sign-ins for admin accounts in last 24 hours
// Table: SigninLogs (Sentinel Data Lake)
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"  // Failed sign-ins (0 = success)
| where UserPrincipalName contains "admin" or UserType == "Admin"
| project TimeGenerated, UserPrincipalName, IPAddress, 
          Location = LocationDetails.countryOrRegion, 
          ResultType, ResultDescription, AppDisplayName, DeviceDetail
| order by TimeGenerated desc
| take 100
```

**CRITICAL REMINDERS:**
- ✅ Always use `SigninLogs` (Sentinel Data Lake) - NOT `IdentityLogonEvents` (Advanced Hunting)
- ✅ Use `TimeGenerated` for timestamp field - NOT `Timestamp`
- ✅ Use `LocationDetails.countryOrRegion` for location - NOT `Location` field directly
- ✅ Reference Investigation-Guide.md Section 8 for field mappings and examples

---

### Workflow 2: Create Sentinel Analytic Rule

**User Request Example:** "Create a Sentinel Analytic Rule to detect impossible travel for critical asset users"

**Step-by-Step Process:**

1. **Search for Community Examples:**
```
Call: search_kql_queries
Parameters: {
  "query": "impossible travel detection Sentinel analytic rule",
  "max_results": 10,
  "include_context": true,
  "sort_by": "stars"
}
```

2. **Review GitHub Examples:**
   - Identify best practices from Azure/Azure-Sentinel repo
   - Extract MITRE ATT&CK techniques
   - Note detection logic patterns

3. **Generate Base Query (Using Sentinel Data Lake Tables):**
```
Call: generate_kql_query
Parameters: {
  "description": "Detect impossible travel - same user signing in from different geolocations within short timeframe using SigninLogs table from Sentinel Data Lake",
  "table_name": "SigninLogs",
  "time_range": "1d"
}

CRITICAL: Ensure query uses:
- SigninLogs (NOT IdentityLogonEvents)
- TimeGenerated (NOT Timestamp)
- UserPrincipalName (NOT AccountUpn)
- LocationDetails.countryOrRegion (NOT Location field directly)
```

4. **Validate Query:**
```
Call: validate_kql_query
Parameters: {
  "query": "[generated query from step 3]"
}
```

5. **Get Table Schema for Additional Fields:**
```
Call: get_table_schema
Parameters: {
  "table_name": "SigninLogs"
}
```

6. **Search for ASIM Normalized Version:**
```
Call: search_asim_schemas
Parameters: {
  "query": "authentication"
}
```

7. **Generate ASIM Template (if needed):**
```
Call: generate_asim_query_template
Parameters: {
  "schemaName": "authentication_event"
}
```

8. **Build Complete Analytic Rule:**
   - Combine validated query with Sentinel rule YAML structure
   - Add MITRE ATT&CK mapping (T1078 - Valid Accounts)
   - Set severity, tactics, frequency, query period
   - Include entity mappings (Account, IP, Location)

**Expected Analytic Rule Output:**

```yaml
id: impossible-travel-critical-assets
name: Impossible Travel for Critical Asset Users
description: |
  Detects when a critical asset user account signs in from two different 
  geographic locations within an impossible timeframe (less than 2 hours 
  for >500km distance). This may indicate credential compromise or 
  account sharing.
severity: High
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: PT1H
queryPeriod: P1D
triggerOperator: GreaterThan
triggerThreshold: 0
tactics:
  - InitialAccess
  - CredentialAccess
relevantTechniques:
  - T1078
  - T1078.004
query: |
  let velocity_threshold = 500; // km
  let time_threshold = 2h;
  let critical_assets = dynamic(["admin", "global", "privileged"]);
  
  SigninLogs
  | where TimeGenerated > ago(1d)
  | where ResultType == "0"  // Successful sign-ins only
  | where UserPrincipalName has_any (critical_assets)
  | extend LocationDetails = parse_json(LocationDetails)
  | extend City = tostring(LocationDetails.city)
  | extend Country = tostring(LocationDetails.countryOrRegion)
  | extend Latitude = toreal(LocationDetails.geoCoordinates.latitude)
  | extend Longitude = toreal(LocationDetails.geoCoordinates.longitude)
  | where isnotempty(Latitude) and isnotempty(Longitude)
  | summarize SignIns = make_list(pack_all()) by UserPrincipalName
  | mv-expand SignIns
  | extend TimeGenerated = todatetime(SignIns.TimeGenerated)
  | extend Lat = toreal(SignIns.Latitude)
  | extend Lon = toreal(SignIns.Longitude)
  | extend City = tostring(SignIns.City)
  | extend Country = tostring(SignIns.Country)
  | extend IPAddress = tostring(SignIns.IPAddress)
  | order by UserPrincipalName, TimeGenerated asc
  | extend PrevTime = prev(TimeGenerated, 1)
  | extend PrevLat = prev(Lat, 1)
  | extend PrevLon = prev(Lon, 1)
  | extend PrevCity = prev(City, 1)
  | extend PrevIP = prev(IPAddress, 1)
  | where UserPrincipalName == prev(UserPrincipalName, 1)
  | extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
  | extend Distance = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000  // km
  | where Distance > velocity_threshold and TimeDiff < 120  // 2 hours
  | project TimeGenerated, UserPrincipalName, 
            Location1 = strcat(PrevCity, ", ", Country),
            Location2 = strcat(City, ", ", Country),
            IP1 = PrevIP, IP2 = IPAddress,
            DistanceKm = round(Distance, 2),
            TimeDiffMinutes = TimeDiff
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IP2
version: 1.0.0
kind: Scheduled
```

---

### Workflow 3: Validate & Optimize Existing Query

**User Request Example:** "Can you check if this query is correct and optimize it?"
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where RiskLevel == "high"
| project UserPrincipalName, IPAddress, Location
```

**Step-by-Step Process:**

1. **FIRST: Verify Table Exists in Sentinel Data Lake**
```
Check Investigation-Guide.md Section 8 to confirm:
- SigninLogs ✅ (Available in Sentinel Data Lake)
- Correct field names: TimeGenerated ✅, ResultType ✅
- Field mappings for Location, RiskLevel
```

2. **Validate Query Syntax:**
```
Call: validate_kql_query
Parameters: {
  "query": "SigninLogs\n| where TimeGenerated > ago(7d)\n| where ResultType == \"0\"\n| where RiskLevel == \"high\"\n| project UserPrincipalName, IPAddress, Location"
}
```

3. **Check Sentinel Table Schema:**
```
Refer to Investigation-Guide.md Section 8.1 "Azure AD Sign-In Logs" for:
- Correct field names (LocationDetails.countryOrRegion NOT Location)
- Risk level fields (RiskLevelDuringSignIn, RiskLevelAggregated NOT RiskLevel)
- Available columns and data types
```

4. **Identify Issues:**
   - ❌ `RiskLevel` → ✅ Should be `RiskLevelDuringSignIn` or `RiskLevelAggregated`
   - ❌ `Location` → ✅ Should be `LocationDetails.countryOrRegion` or `tostring(LocationDetails)`
   - ❌ Missing time filter optimization
   - ❌ Missing important fields like `AppDisplayName`, `DeviceDetail`

5. **Search for Sentinel Best Practices:**
```
Call: search_kql_queries
Parameters: {
  "query": "risky sign-ins high risk SigninLogs Sentinel",
  "max_results": 5,
  "include_context": true
}
```

6. **Generate Optimized Version for Sentinel Data Lake:**
```
Call: generate_kql_query
Parameters: {
  "description": "Find high-risk successful sign-ins with proper field handling",
  "table_name": "SigninLogs",
  "time_range": "7d"
}
```

6. **Present Optimized Query for Sentinel Data Lake:**

```kql
// Optimized: High-risk successful sign-ins (last 7 days)
// Table: SigninLogs (Sentinel Data Lake)
// Reference: Investigation-Guide.md Section 8.1
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"  // Successful sign-ins (0 = success)
| where RiskLevelDuringSignIn == "high" or RiskLevelAggregated == "high"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| extend State = tostring(LocationDetails.state)
| project 
    TimeGenerated, 
    UserPrincipalName, 
    IPAddress, 
    Location = strcat(City, ", ", State, ", ", Country),
    RiskLevel = coalesce(RiskLevelDuringSignIn, RiskLevelAggregated),
    RiskEventTypes,
    AppDisplayName,
    DeviceDetail,
    ConditionalAccessStatus,
    ResultType,
    ResultDescription
| order by TimeGenerated desc
```

**Changes Made:**
- ✅ Fixed `RiskLevel` → `RiskLevelDuringSignIn`/`RiskLevelAggregated` (Sentinel field names)
- ✅ Proper `LocationDetails.countryOrRegion` extraction (Sentinel Data Lake schema)
- ✅ Added `RiskEventTypes` for detailed risk context
- ✅ Added critical Sentinel fields (`ConditionalAccessStatus`, `DeviceDetail`)
- ✅ Added `ResultDescription` for failure reason details
- ✅ Used `coalesce()` for handling null risk levels
- ✅ Verified all fields against Investigation-Guide.md Section 8.1

**VERIFICATION CHECKLIST:**
- ✅ Table name: SigninLogs (Sentinel Data Lake) ✓
- ✅ Timestamp field: TimeGenerated ✓
- ✅ User field: UserPrincipalName ✓
- ✅ Location fields: LocationDetails.* ✓
- ✅ All fields exist in Investigation-Guide.md ✓

---

### Workflow 4: Build ASIM-Normalized Query

**User Request Example:** "Create an ASIM-normalized query to detect authentication failures across all data sources"

**Step-by-Step Process:**

1. **Search for Relevant ASIM Schema:**
```
Call: search_asim_schemas
Parameters: {
  "query": "authentication"
}
```

2. **Get Schema Details:**
```
Call: get_asim_schema_info
Parameters: {
  "schemaName": "authentication_event"
}
```

3. **Generate ASIM Query Template:**
```
Call: generate_asim_query_template
Parameters: {
  "schemaName": "authentication_event"
}
```

4. **Get Parser Recommendations:**
```
Call: get_asim_parser_recommendations
Parameters: {
  "schemaName": "authentication_event"
}
```

5. **Search for Community ASIM Examples:**
```
Call: search_kql_queries
Parameters: {
  "query": "ASIM authentication failed login imAuthentication",
  "max_results": 10,
  "include_context": true
}
```

6. **Build Complete ASIM Query:**

```kql
// ASIM-Normalized Authentication Failures (All Sources)
imAuthentication
| where TimeGenerated > ago(24h)
| where EventResult == "Failure"
| where EventResultDetails in ("No such user", "Incorrect password", "Account locked", "MFA denied")
| extend EventSeverity = case(
    EventResultDetails == "Account locked", "High",
    EventResultDetails == "MFA denied", "Medium",
    "Low"
)
| project TimeGenerated,
          EventResult,
          EventResultDetails,
          EventSeverity,
          TargetUserName,
          TargetUserId,
          SrcIpAddr,
          SrcGeoCountry,
          SrcGeoCity,
          LogonMethod,
          TargetAppName,
          EventOriginalType,
          EventProduct,
          EventVendor
| order by TimeGenerated desc
```

**Benefits of ASIM Approach:**
- ✅ Works across Azure AD, Active Directory, AWS IAM, Okta, etc.
- ✅ Standardized field names (TargetUserName vs UserPrincipalName vs Account)
- ✅ Single query for multi-cloud/hybrid environments
- ✅ Easier correlation with other ASIM schemas

---

## Best Practices

### Query Generation Best Practices

1. **Always Validate Before Use:**
   - Call `validate_kql_query` on generated queries before execution
   - Check for warnings about performance or deprecated syntax
   - Verify table and column names against schema

2. **Use Time Filters First:**
   - Always filter `TimeGenerated` early in query
   - Use `ago()` function for relative time ranges
   - Example: `where TimeGenerated > ago(24h)` before other filters

3. **Handle Dynamic Fields Properly:**
   - Use `parse_json()` for LocationDetails, DeviceDetail, ModifiedProperties
   - Extract specific fields with `tostring()`, `toreal()`, `toint()`
   - Example: `extend LocationDetails = parse_json(LocationDetails) | extend City = tostring(LocationDetails.city)`

4. **Optimize Query Performance:**
   - Use `project` to reduce columns early
   - Use `take` or `top` to limit results
   - Avoid `search` operator for large datasets (use specific `where` conditions)
   - Use `summarize` instead of multiple aggregations

5. **Include Comments:**
   - Add header comment describing query purpose
   - Document complex logic with inline comments
   - Include example usage or expected output

### Sentinel Analytic Rule Best Practices

1. **Required Components:**
   - Unique rule ID (GUID format recommended)
   - Descriptive name (max 256 characters)
   - Detailed description with detection logic explanation
   - Severity (Informational, Low, Medium, High, Critical)
   - MITRE ATT&CK tactics and techniques
   - Entity mappings (Account, IP, Host, File, etc.)
   - Query frequency and period

2. **MITRE ATT&CK Mapping:**
   - Always include relevant tactics (InitialAccess, Persistence, PrivilegeEscalation, etc.)
   - Add specific technique IDs (T1078, T1078.004, etc.)
   - Reference MITRE documentation for accuracy

3. **Entity Mappings:**
   - Map Account entities: `UserPrincipalName`, `AccountName`, `AccountDomain`
   - Map IP entities: `IPAddress`, `SourceIP`, `DestinationIP`
   - Map Host entities: `DeviceName`, `HostName`, `ComputerName`
   - Map File entities: `FileName`, `FilePath`, `SHA256`

4. **Testing & Validation:**
   - Test query in Sentinel workspace before deployment
   - Verify false positive rate with historical data
   - Ensure entity mappings populate correctly
   - Set appropriate query frequency (avoid API throttling)

5. **Documentation:**
   - Include remediation steps in description
   - Link to relevant playbooks or response procedures
   - Document tuning parameters (thresholds, exclusions)
   - Version tracking in comments

### ASIM Query Best Practices

1. **Use Unifying Parsers:**
   - Use `imAuthentication`, `imNetworkSession`, `imFileEvent` instead of source-specific tables
   - Enables multi-source correlation with single query
   - Standardizes field names across vendors

2. **Understand Schema Requirements:**
   - Call `get_asim_parser_requirements` to see mandatory fields
   - Validate parsers with `validate_asim_parser` before deployment
   - Use `get_asim_schema_relationships` for cross-schema joins

3. **Field Naming Conventions:**
   - Use ASIM standard names: `TargetUserName`, `SrcIpAddr`, `DstIpAddr`
   - Don't mix ASIM and source-specific fields in same query
   - Use logical types: `Datetime`, `String`, `IpAddress`, `Url`

4. **Performance Optimization:**
   - ASIM parsers add overhead - use specific parsers when possible
   - Filter on `EventProduct` or `EventVendor` to reduce scope
   - Use `_Im_` prefix parsers for optimized versions (e.g., `_Im_Authentication`)

---

## Common Query Patterns (Sentinel Data Lake Tables Only)

**CRITICAL: All patterns below use Sentinel Data Lake tables. Verify table availability in Investigation-Guide.md Section 8 before using.**

### Pattern 1: Failed Authentication Detection (SigninLogs)
```kql
// Failed authentication attempts detection
// Table: SigninLogs (Sentinel Data Lake)
// Reference: Investigation-Guide.md Section 8.1
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"  // 0 = success, non-zero = failure
| summarize 
    FailureCount = count(), 
    UniqueIPs = dcount(IPAddress),
    FailureReasons = make_set(ResultDescription),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by UserPrincipalName
| where FailureCount > 10
| extend AttackDuration = LastFailure - FirstFailure
| order by FailureCount desc
```

### Pattern 2: Anomalous IP Detection (SigninLogs)
```kql
// Detect sign-ins from new/unusual IP addresses
// Table: SigninLogs (Sentinel Data Lake)
// Reference: Investigation-Guide.md Section 8.1
let baseline_period = 30d;
let detection_period = 1h;
let baseline_ips = 
    SigninLogs
    | where TimeGenerated between (ago(baseline_period) .. ago(detection_period))
    | where ResultType == "0"
    | where UserPrincipalName == "target.user@domain.com"
    | distinct IPAddress;
SigninLogs
| where TimeGenerated > ago(detection_period)
| where ResultType == "0"
| where UserPrincipalName == "target.user@domain.com"
| where IPAddress !in (baseline_ips)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project 
    TimeGenerated, 
    IPAddress, 
    Location = strcat(City, ", ", Country), 
    AppDisplayName,
    DeviceDetail,
    RiskLevelDuringSignIn
```

### Pattern 3: Privileged Account Monitoring (AuditLogs)
```kql
// Monitor privileged role assignments and usage
// Tables: AuditLogs (Sentinel Data Lake)
// Reference: Investigation-Guide.md Section 8.2
let privileged_roles = dynamic([
    "Global Administrator", 
    "Security Administrator", 
    "Privileged Role Administrator",
    "Application Administrator"
]);
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role"
)
| extend RoleName = tostring(TargetResources[0].displayName)
| where RoleName in (privileged_roles)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project 
    TimeGenerated, 
    OperationName, 
    InitiatedBy, 
    TargetUser, 
    RoleName,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

### Pattern 4: Data Exfiltration Detection (OfficeActivity)
```kql
// Detect unusual file download/share activity
// Table: OfficeActivity (Sentinel Data Lake)  
// Reference: Investigation-Guide.md Section 8.4
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileUploaded", "FileCopied")
| summarize 
    FileCount = count(),
    UniqueFiles = dcount(OfficeObjectId),
    Operations = make_set(Operation),
    FirstActivity = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId, ClientIP
    by AccountObjectId, bin(TimeGenerated, 1h)
| where TotalSizeBytes > 1000000000  // >1GB
| order by TotalSizeBytes desc
```

### Pattern 5: ASIM Multi-Source Authentication
```kql
imAuthentication
| where TimeGenerated > ago(1d)
| where EventResult == "Failure"
| summarize FailureCount = count() 
    by TargetUserName, SrcIpAddr, EventProduct, EventVendor
| where FailureCount > 50
| order by FailureCount desc
```

---

## Error Handling & Troubleshooting

### Common Errors & Solutions

**Error: "Table 'X' does not exist"**
- Solution: Call `search_tables` with table description to find correct table name
- Example: Instead of "Logins", use `search_tables("sign-in events")` → `SigninLogs`

**Error: "Column 'X' does not exist"**
- Solution: Call `get_table_schema` to see available columns
- Check if field is dynamic and needs `parse_json()` extraction

**Error: "Query validation failed: syntax error"**
- Solution: Call `validate_kql_query` to get specific error details
- Check for missing pipes (`|`), incorrect operators, or unclosed strings

**Error: "GitHub API rate limit exceeded"**
- Solution: Call `get_rate_limit` to check status
- Wait for reset time or use cached results with `get_cache_stats`

**Error: "ASIM parser not found"**
- Solution: Verify schema name with `list_asim_schemas`
- Use exact schema name format (e.g., `authentication_event`, not `AuthenticationEvent`)

### Performance Issues

**Slow Query Execution:**
1. Add time filter early: `where TimeGenerated > ago(24h)`
2. Use specific filters before summarize/join
3. Reduce columns with `project` early in pipeline
4. Use `take` to limit results for testing

**Too Many Results:**
1. Add `take 100` or `top 100 by TimeGenerated desc`
2. Use `summarize` to aggregate instead of raw results
3. Add more specific filters (user, IP, application)

**GitHub Search Returns No Results:**
1. Broaden search terms (use "failed login" instead of "impossible travel failed authentication")
2. Try searching specific repos: `search_repo_kql_queries` with "Azure/Azure-Sentinel"
3. Use `search_kql_repositories` to find relevant repos first

---

## Integration with Investigation Workflow

This skill integrates with the existing CyberProbe Investigation-Guide.md workflows:

### When to Generate New Queries vs Use Guide Queries

**Use Investigation-Guide.md Sample Queries When:**
- ✅ Standard investigation patterns (user investigation, incident triage, device analysis)
- ✅ Queries already tested and validated in production
- ✅ Investigation follows documented playbooks

**Generate New Queries with This Skill When:**
- ✅ Custom detection scenarios not covered in guide
- ✅ Need ASIM-normalized multi-source queries
- ✅ Building new Sentinel Analytic Rules
- ✅ Investigating unique threat patterns or IOCs
- ✅ Optimizing existing queries for performance

### Workflow Integration Example

**Scenario:** User investigating compromised account (follows Investigation-Guide.md)

1. **Use Guide Query** for initial sign-in analysis (Sample Query #3)
2. **Generate Custom Query** for specific anomaly:
   ```
   User: "I see unusual sign-ins from Nigeria - create a query to check if this user has ever signed in from Africa before"
   
   Agent: Calls generate_kql_query with:
   {
     "description": "Check historical sign-ins from African countries for specific user",
     "table_name": "SigninLogs",
     "time_range": "90d"
   }
   ```
3. **Validate** generated query before execution
4. **Document** findings in investigation report

---

## Examples

### Example 1: Simple Query Generation

**User:** "Create a query to show all emails with malicious attachments in the last 7 days"

**Agent Response:**
```
Generating validated KQL query for email threats...

[Calls: generate_kql_query]
Parameters: {
  "description": "Show all emails with malicious attachments in the last 7 days",
  "time_range": "7d",
  "limit": 100
}

[Result: Validated query returned]

Here's your validated KQL query:

```kql
// Emails with malicious attachments (last 7 days)
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Malware"
| join kind=inner (
    EmailAttachmentInfo
    | where TimeGenerated > ago(7d)
    | project NetworkMessageId, FileName, FileType, SHA256
) on NetworkMessageId
| project TimeGenerated, 
          SenderFromAddress, 
          RecipientEmailAddress, 
          Subject, 
          ThreatTypes, 
          FileName, 
          SHA256, 
          DeliveryAction
| order by TimeGenerated desc
| take 100
```

**Validation Status:** ✅ Passed
**Tables:** EmailEvents, EmailAttachmentInfo
**Microsoft Learn Docs:** [EmailEvents Reference](https://learn.microsoft.com/...)

**Usage:** Execute in Sentinel workspace or add to Investigation-Guide.md
```

---

### Example 2: Sentinel Analytic Rule Creation

**User:** "Create a Sentinel detection rule for brute force attacks"

**Agent Response:**
```
Generating Sentinel Analytic Rule for brute force detection...

[Calls: search_kql_queries]
Parameters: {
  "query": "brute force detection multiple failed login attempts",
  "max_results": 5,
  "include_context": true
}

[Reviews community examples from Azure/Azure-Sentinel]

[Calls: generate_kql_query]
Parameters: {
  "description": "Detect multiple failed sign-in attempts followed by successful sign-in",
  "table_name": "SigninLogs",
  "time_range": "1h"
}

[Validates query]

Here's your Sentinel Analytic Rule:

```yaml
id: brute-force-detection-v1
name: Multiple Failed Sign-ins Followed by Success
description: |
  Detects potential brute force attacks where a user account experiences 
  multiple failed sign-in attempts followed by a successful sign-in within 
  a short timeframe. This pattern indicates password guessing or credential 
  stuffing attacks.
  
  **Remediation Steps:**
  1. Verify successful sign-in legitimacy with user
  2. Check source IP reputation and geolocation
  3. Force password reset if suspicious
  4. Enable MFA if not already active
  5. Review account for persistence mechanisms
severity: High
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: PT1H
queryPeriod: PT1H
triggerOperator: GreaterThan
triggerThreshold: 0
tactics:
  - CredentialAccess
  - InitialAccess
relevantTechniques:
  - T1110
  - T1110.001
  - T1110.003
query: |
  let threshold = 5;
  let timeframe = 1h;
  
  SigninLogs
  | where TimeGenerated > ago(timeframe)
  | extend LoginResult = case(ResultType == "0", "Success", "Failure")
  | summarize FailureCount = countif(LoginResult == "Failure"),
              SuccessCount = countif(LoginResult == "Success"),
              IPAddresses = make_set(IPAddress),
              FailureReasons = make_set(ResultDescription),
              FirstFailure = minif(TimeGenerated, LoginResult == "Failure"),
              FirstSuccess = minif(TimeGenerated, LoginResult == "Success")
      by UserPrincipalName
  | where FailureCount >= threshold and SuccessCount > 0
  | extend TimeBetweenFailureAndSuccess = datetime_diff('minute', FirstSuccess, FirstFailure)
  | where TimeBetweenFailureAndSuccess >= 0 and TimeBetweenFailureAndSuccess <= 60
  | project UserPrincipalName, 
            FailureCount, 
            SuccessCount,
            IPAddresses,
            FailureReasons,
            FirstFailure,
            FirstSuccess,
            TimeBetweenFailureAndSuccess
  | order by FailureCount desc
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddresses
customDetails:
  FailureCount: FailureCount
  SuccessCount: SuccessCount
  TimeBetween: TimeBetweenFailureAndSuccess
alertDetailsOverride:
  alertDisplayNameFormat: "Brute Force Detected: {{UserPrincipalName}}"
  alertDescriptionFormat: "{{FailureCount}} failed attempts followed by successful sign-in for {{UserPrincipalName}}"
version: 1.0.0
kind: Scheduled
```

**Deployment:** Save to `.yaml` file and import to Sentinel Analytics Rules
**MITRE ATT&CK:** T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying)
```

---

### Example 3: Query Validation & Optimization

**User:** "Can you check this query? It's running slow"
```kql
SecurityEvent
| where EventID == 4625
| project Computer, Account, IpAddress
```

**Agent Response:**
```
Validating query...

[Calls: validate_kql_query]
[Calls: get_table_schema for SecurityEvent]

**Validation Results:**
⚠️ **Warnings Found:**
1. Missing time filter - query will scan entire table history (performance issue)
2. Column names use incorrect casing (should be lowercase)
3. EventID filter could be more specific

[Calls: search_kql_queries]
Parameters: {
  "query": "failed login SecurityEvent 4625 optimization",
  "max_results": 3
}

**Optimized Query:**

```kql
// Failed Windows logon events (last 24 hours) - Optimized
SecurityEvent
| where TimeGenerated > ago(24h)  // ✅ Added time filter
| where EventID == 4625  // Failed logon
| where AccountType == "User"  // ✅ Exclude system accounts
| project TimeGenerated,  // ✅ Added timestamp
          Computer, 
          Account, 
          IpAddress,
          LogonType,  // ✅ Added context (Interactive, Network, etc.)
          Status,  // ✅ Added failure reason
          SubStatus
| order by TimeGenerated desc
| take 1000  // ✅ Limit results
```

**Performance Improvements:**
- ✅ Added `TimeGenerated > ago(24h)` - reduces scan from years to 1 day
- ✅ Added `AccountType` filter - removes noise from system accounts
- ✅ Added `take 1000` - prevents overwhelming results
- ✅ Added contextual fields - LogonType shows attack method (RDP, SMB, etc.)
- ✅ Proper column casing - matches table schema

**Estimated Performance Gain:** ~95% faster (hours → seconds)
```

---

## Summary

This skill transforms natural language investigation requirements into production-ready KQL queries and Sentinel Analytic Rules by leveraging:

- **331+ validated table schemas** for query generation
- **GitHub community examples** from thousands of public repos
- **ASIM normalization** for multi-source correlation
- **Automated validation** against Microsoft schemas
- **Best practice templates** from Azure/Microsoft repositories

**Key Capabilities:**
1. Generate queries from "show me failed logins" → validated KQL
2. Create Analytic Rules with MITRE ATT&CK mapping
3. Validate and optimize existing queries
4. Build ASIM-normalized multi-source queries
5. Search community detection patterns
6. Ensure schema compliance before execution

**Integration with CyberProbe:**
- Complements Investigation-Guide.md sample queries
- Generates custom queries for unique scenarios
- Validates queries before adding to guide
- Creates new Analytic Rules for threat detection
- Optimizes existing investigation patterns

**Expected Outcome:** Security analysts can create sophisticated, validated KQL queries and detection rules in minutes instead of hours, with confidence that queries will execute correctly and efficiently.
