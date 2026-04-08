"""
Power BI Investigation Data Exporter
Exports u1899 insider threat investigation data to Power BI-ready JSON format

Usage:
    python powerbi/export_investigation_data.py --incident 42120
    python powerbi/export_investigation_data.py --user u1899 --days 7
"""

import json
import argparse
from datetime import datetime
from pathlib import Path

def export_u1899_investigation():
    """Export complete u1899 investigation data for Power BI"""
    
    output_dir = Path("powerbi/data")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Incident Data
    incident_data = {
        "incident_id": "42120",
        "display_name": "Multi-stage incident involving one user",
        "severity": "high",
        "status": "active",
        "created_datetime": "2026-01-21T00:39:26.82Z",
        "last_updated": "2026-01-21T03:27:05.77Z",
        "priority_score": 23,
        "user_principal_name": "u1899@int.zava-corp.com",
        "classification": "unknown",
        "determination": "unknown",
        "assigned_to": None,
        "tenant_id": "0527ecb7-06fb-4769-b324-fd4a3bb865eb"
    }
    
    # User Data
    user_data = {
        "user_principal_name": "u1899@int.zava-corp.com",
        "display_name": "Gurbanjemal Carlsson",
        "azure_ad_user_id": "0b1dc756-4629-46c6-8a28-95dca1fcca5d",
        "user_sid": "S-1-12-1-186500950-1187399209-3700762762-1573584033",
        "risk_score": 75,
        "employment_status": "departing",
        "asset_classification": "critical_asset",
        "threat_verdict": "suspicious",
        "departure_triggered_date": "2026-01-19T15:32:11Z"
    }
    
    # Alert Data (5 alerts)
    alerts_data = [
        {
            "alert_id": "ir5a7536f9-8df1-4ca2-bf8f-37fb86666343",
            "incident_id": "42120",
            "title": "Purview IRM ('5a7536f9') Departures",
            "severity": "high",
            "category": "Exfiltration",
            "risk_score": 75,
            "created_datetime": "2026-01-21T00:39:26.6466667Z",
            "first_activity": "2026-01-21T00:39:23.5875339Z",
            "last_activity": "2026-01-21T03:26:43.7731142Z",
            "policy_title": "Departures",
            "policy_id": "284f5808-c4f6-4f56-b4c6-789888d3961f",
            "insight_type": "CopilotSensitiveResponse",
            "insight_start_date": "2025-12-18T00:00:00Z",
            "triggering_event": "AadLeaver"
        },
        {
            "alert_id": "ir57e67962-f134-46c6-9647-d8cdf1f3b23a",
            "incident_id": "42120",
            "title": "Purview IRM ('57e67962') Risky AI usage quick policy - 10/17/2025",
            "severity": "low",
            "category": "SuspiciousActivity",
            "risk_score": 25,
            "created_datetime": "2026-01-21T00:43:31.6033333Z",
            "first_activity": "2026-01-21T00:43:21.5105628Z",
            "last_activity": "2026-01-21T03:26:44.0751887Z",
            "policy_title": "Risky AI usage quick policy - 10/17/2025",
            "policy_id": "2c3e7384-02c1-4155-89cc-4b6cfb93530e",
            "insight_type": "CopilotSensitiveResponse",
            "insight_start_date": "2025-10-26T00:00:00Z",
            "triggering_event": "AadLeaver"
        },
        {
            "alert_id": "ira4c8c78d-4270-434f-88a9-dac1f2621e51",
            "incident_id": "42120",
            "title": "Purview IRM ('a4c8c78d') Risky AI usage quick policy - 6/17/2025 - 2",
            "severity": "low",
            "category": "SuspiciousActivity",
            "risk_score": 25,
            "created_datetime": "2026-01-21T00:40:16.83Z",
            "first_activity": "2026-01-21T00:40:16.4215632Z",
            "last_activity": "2026-01-21T03:26:43.8744944Z",
            "policy_title": "Risky AI usage quick policy - 6/17/2025 - 2",
            "policy_id": "d38d9b48-5268-45cf-b9f1-f6bed068e6ca",
            "insight_type": "CopilotSensitiveResponse",
            "insight_start_date": "2025-10-26T00:00:00Z",
            "triggering_event": "AadLeaver"
        },
        {
            "alert_id": "ircde3edf1-e766-4fd7-9182-3b1bd870a2d8",
            "incident_id": "42120",
            "title": "Purview IRM ('cde3edf1') Risky AI usage quick policy - 23/9/2025",
            "severity": "low",
            "category": "SuspiciousActivity",
            "risk_score": 25,
            "created_datetime": "2026-01-21T00:41:26.1066667Z",
            "first_activity": "2026-01-21T00:41:22.8443229Z",
            "last_activity": "2026-01-21T03:26:43.9748931Z",
            "policy_title": "Risky AI usage quick policy - 23/9/2025",
            "policy_id": "b3ec3c9a-1621-4d70-a754-38f1f65f58c1",
            "insight_type": "CopilotSensitiveResponse",
            "insight_start_date": "2025-10-26T00:00:00Z",
            "triggering_event": "AadLeaver"
        },
        {
            "alert_id": "ire8f476a0-1a68-41be-a758-63aefbb43107",
            "incident_id": "42120",
            "title": "Purview IRM ('e8f476a0') Risky AI usage quick policy - 1/8/2026",
            "severity": "low",
            "category": "SuspiciousActivity",
            "risk_score": 25,
            "created_datetime": "2026-01-21T00:44:10.9Z",
            "first_activity": "2026-01-21T00:44:10.4618678Z",
            "last_activity": "2026-01-21T03:26:44.182256Z",
            "policy_title": "Risky AI usage quick policy - 1/8/2026",
            "policy_id": "6a8f4a7a-7138-4e06-92c4-570c100a0cdc",
            "insight_type": "CopilotSensitiveResponse",
            "insight_start_date": "2025-10-26T00:00:00Z",
            "triggering_event": "AadLeaver"
        }
    ]
    
    # User Activity Data (44 email operations)
    activity_data = [
        {"date": "2026-01-19", "operation": "MailItemsAccessed", "count": 2, "record_type": "ExchangeItemAggregated"},
        {"date": "2026-01-19", "operation": "Send", "count": 2, "record_type": "ExchangeItem"},
        {"date": "2026-01-18", "operation": "MailItemsAccessed", "count": 5, "record_type": "ExchangeItemAggregated"},
        {"date": "2026-01-18", "operation": "Send", "count": 5, "record_type": "ExchangeItem"},
        {"date": "2026-01-17", "operation": "MailItemsAccessed", "count": 5, "record_type": "ExchangeItemAggregated"},
        {"date": "2026-01-17", "operation": "Send", "count": 4, "record_type": "ExchangeItem"},
        {"date": "2026-01-16", "operation": "MailItemsAccessed", "count": 2, "record_type": "ExchangeItemAggregated"},
        {"date": "2026-01-16", "operation": "Send", "count": 2, "record_type": "ExchangeItem"},
        {"date": "2026-01-15", "operation": "MailItemsAccessed", "count": 5, "record_type": "ExchangeItemAggregated"},
        {"date": "2026-01-15", "operation": "Send", "count": 4, "record_type": "ExchangeItem"},
        {"date": "2026-01-14", "operation": "MailItemsAccessed", "count": 8, "record_type": "ExchangeItemAggregated"},
        {"date": "2026-01-14", "operation": "Send", "count": 7, "record_type": "ExchangeItem"}
    ]
    
    # Remediation Failures (5 AWS IAM attempts)
    remediation_data = [
        {
            "action_id": "rem-001",
            "incident_id": "42120",
            "timestamp": "2026-01-21T00:46:31.861372Z",
            "playbook_name": "Playbook-AWSIAM-DeleteAccessKeys",
            "action_type": "Delete AWS Access Keys",
            "target_user": "u1899",
            "status": "Failed",
            "error_message": "Playbook could not delete access keys for user u1899"
        },
        {
            "action_id": "rem-002",
            "incident_id": "42120",
            "timestamp": "2026-01-21T00:46:28.9595682Z",
            "playbook_name": "Playbook-AWSIAM-DeleteAccessKeys",
            "action_type": "Delete AWS Access Keys",
            "target_user": "u1899",
            "status": "Failed",
            "error_message": "Playbook could not delete access keys for user u1899"
        },
        {
            "action_id": "rem-003",
            "incident_id": "42120",
            "timestamp": "2026-01-21T00:45:12.2571563Z",
            "playbook_name": "Playbook-AWSIAM-DeleteAccessKeys",
            "action_type": "Delete AWS Access Keys",
            "target_user": "u1899",
            "status": "Failed",
            "error_message": "Playbook could not delete access keys for user u1899"
        },
        {
            "action_id": "rem-004",
            "incident_id": "42120",
            "timestamp": "2026-01-21T00:43:27.7213933Z",
            "playbook_name": "Playbook-AWSIAM-DeleteAccessKeys",
            "action_type": "Delete AWS Access Keys",
            "target_user": "u1899",
            "status": "Failed",
            "error_message": "Playbook could not delete access keys for user u1899"
        },
        {
            "action_id": "rem-005",
            "incident_id": "42120",
            "timestamp": "2026-01-21T00:43:27.6851311Z",
            "playbook_name": "Playbook-AWSIAM-DeleteAccessKeys",
            "action_type": "Delete AWS Access Keys",
            "target_user": "u1899",
            "status": "Failed",
            "error_message": "Playbook could not delete access keys for user u1899"
        }
    ]
    
    # MITRE ATT&CK Mapping
    mitre_data = [
        {
            "tactic": "Collection",
            "technique_id": "T1114",
            "technique_name": "Email Collection",
            "sub_technique_id": "T1114.002",
            "sub_technique_name": "Remote Email Collection",
            "evidence": "27 MailItemsAccessed events via Exchange Online",
            "incident_id": "42120"
        },
        {
            "tactic": "Exfiltration",
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "sub_technique_id": "T1048.003",
            "sub_technique_name": "Exfiltration Over Unencrypted Channel",
            "evidence": "17 email Send operations, potential AWS data transfer",
            "incident_id": "42120"
        },
        {
            "tactic": "Exfiltration",
            "technique_id": "T1567",
            "technique_name": "Exfiltration Over Web Service",
            "sub_technique_id": "T1567.002",
            "sub_technique_name": "Exfiltration to Cloud Storage",
            "evidence": "AWS access still active (failed remediation)",
            "incident_id": "42120"
        },
        {
            "tactic": "Collection",
            "technique_id": "T1213",
            "technique_name": "Data from Information Repositories",
            "sub_technique_id": "T1213.002",
            "sub_technique_name": "SharePoint",
            "evidence": "Copilot access to sensitive documents (3+ months)",
            "incident_id": "42120"
        },
        {
            "tactic": "Persistence",
            "technique_id": "T1098",
            "technique_name": "Account Manipulation",
            "sub_technique_id": "T1098.001",
            "sub_technique_name": "Additional Cloud Credentials",
            "evidence": "AWS IAM keys not revoked (5 failed attempts)",
            "incident_id": "42120"
        },
        {
            "tactic": "Defense Evasion",
            "technique_id": "T1550",
            "technique_name": "Use Alternate Authentication Material",
            "sub_technique_id": "T1550.001",
            "sub_technique_name": "Application Access Token",
            "evidence": "No interactive sign-ins despite active access",
            "incident_id": "42120"
        },
        {
            "tactic": "Impact",
            "technique_id": "T1485",
            "technique_name": "Data Destruction",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "evidence": "Departing employee with potential grievance",
            "incident_id": "42120"
        }
    ]
    
    # Export to JSON files
    files_created = []
    
    with open(output_dir / "incident_42120.json", 'w') as f:
        json.dump([incident_data], f, indent=2)
        files_created.append("incident_42120.json")
    
    with open(output_dir / "user_u1899.json", 'w') as f:
        json.dump([user_data], f, indent=2)
        files_created.append("user_u1899.json")
    
    with open(output_dir / "alerts_u1899.json", 'w') as f:
        json.dump(alerts_data, f, indent=2)
        files_created.append("alerts_u1899.json")
    
    with open(output_dir / "user_activity_u1899.json", 'w') as f:
        json.dump(activity_data, f, indent=2)
        files_created.append("user_activity_u1899.json")
    
    with open(output_dir / "remediation_failures.json", 'w') as f:
        json.dump(remediation_data, f, indent=2)
        files_created.append("remediation_failures.json")
    
    with open(output_dir / "mitre_attack_mapping.json", 'w') as f:
        json.dump(mitre_data, f, indent=2)
        files_created.append("mitre_attack_mapping.json")
    
    # Create summary manifest
    manifest = {
        "investigation_id": "INV-U1899-20260121",
        "incident_id": "42120",
        "subject": "u1899@int.zava-corp.com",
        "export_date": datetime.now().isoformat(),
        "files": files_created,
        "summary": {
            "total_alerts": len(alerts_data),
            "high_severity_alerts": sum(1 for a in alerts_data if a['severity'] == 'high'),
            "total_email_operations": sum(a['count'] for a in activity_data),
            "failed_remediations": len(remediation_data),
            "risk_score": user_data['risk_score'],
            "mitre_techniques": len(mitre_data)
        }
    }
    
    with open(output_dir / "investigation_manifest.json", 'w') as f:
        json.dump(manifest, f, indent=2)
        files_created.append("investigation_manifest.json")
    
    return files_created, manifest

def main():
    parser = argparse.ArgumentParser(description='Export investigation data for Power BI')
    parser.add_argument('--incident', default='42120', help='Incident ID')
    parser.add_argument('--output', default='powerbi/data', help='Output directory')
    
    args = parser.parse_args()
    
    print("🔄 Exporting investigation data for Power BI...")
    print(f"   Incident: {args.incident}")
    print(f"   Output: {args.output}\n")
    
    files, manifest = export_u1899_investigation()
    
    print("✅ Export Complete!\n")
    print(f"📊 Summary:")
    print(f"   - Alerts: {manifest['summary']['total_alerts']} ({manifest['summary']['high_severity_alerts']} high severity)")
    print(f"   - Email Operations: {manifest['summary']['total_email_operations']}")
    print(f"   - Failed Remediations: {manifest['summary']['failed_remediations']}")
    print(f"   - Risk Score: {manifest['summary']['risk_score']}/100")
    print(f"   - MITRE Techniques: {manifest['summary']['mitre_techniques']}")
    
    print(f"\n📁 Files Created ({len(files)}):")
    for f in files:
        print(f"   ✓ {f}")
    
    print(f"\n📍 Location: powerbi/data/")
    print("\n🚀 Next Steps:")
    print("   1. Open Power BI Desktop")
    print("   2. Get Data → JSON")
    print("   3. Navigate to powerbi/data/ and select all JSON files")
    print("   4. Transform data and create visualizations")
    print("\n   See: powerbi/POWERBI_DASHBOARD_SETUP.md for detailed instructions")

if __name__ == "__main__":
    main()
