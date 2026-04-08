"""
Power BI Data Export Script for CyberProbe
Connects to Microsoft Defender/Sentinel APIs and creates refreshable datasets

This script is used by the 'report-generation' Agent Skill.
See: .github/skills/report-generation/SKILL.md

Usage:
    python enrichment/powerbi_data_export.py [--days 7] [--format excel|csv|json|all]
    cd enrichment && python powerbi_data_export.py [--days 7] [--format excel|csv|json|all]

Requirements:
    pip install azure-identity msal requests pandas openpyxl

For complete documentation, see:
- .github/skills/report-generation/SKILL.md
- docs/POWERBI_SETUP.md
- Investigation-Guide.md Section 17 (Report Template)
"""

import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import requests
import pandas as pd
from typing import List, Dict, Any

class DefenderDataExporter:
    """Export Defender XDR and Sentinel data for Power BI consumption"""
    
    def __init__(self, config_path: str = "config.json"):
        """Initialize with configuration"""
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        self.tenant_id = self.config.get('tenant_id')
        self.workspace_id = self.config.get('sentinel_workspace_id')
        self.access_token = None
        self.output_dir = Path('../' + self.config.get('settings', {}).get('output_dir', 'reports'))
        self.output_dir.mkdir(exist_ok=True)
        
    def get_access_token(self) -> str:
        """
        Get Azure AD access token for Microsoft Graph API
        
        For production use, implement one of these methods:
        1. Azure CLI: az login + az account get-access-token
        2. Service Principal: client_id + client_secret
        3. Managed Identity: for Azure-hosted solutions
        4. Interactive: MSAL device code flow
        
        For now, returns placeholder - user must implement authentication
        """
        print("\n⚠️  AUTHENTICATION REQUIRED")
        print("This script requires Azure AD authentication.")
        print("\nImplement one of these methods in get_access_token():")
        print("1. Use Azure CLI: az login && az account get-access-token --resource https://graph.microsoft.com")
        print("2. Use MSAL with client credentials")
        print("3. Use azure-identity DefaultAzureCredential")
        print("\nFor quick testing, run:")
        print("  az account get-access-token --resource https://api.securitycenter.microsoft.com --query accessToken -o tsv")
        
        # Placeholder - implement actual authentication
        raise NotImplementedError("Please implement authentication method in get_access_token()")
    
    def fetch_defender_incidents(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Fetch incidents from Microsoft Defender API
        
        API: https://api.securitycenter.microsoft.com/api/incidents
        Documentation: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents
        """
        print(f"Fetching Defender incidents from last {days} days...")
        
        # Calculate date filter
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        
        endpoint = "https://api.securitycenter.microsoft.com/api/incidents"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        params = {
            '$filter': f"createdTime ge {start_date}",
            '$top': 100  # Adjust as needed, max 100 per page
        }
        
        incidents = []
        next_link = endpoint
        
        while next_link:
            if next_link == endpoint:
                response = requests.get(endpoint, headers=headers, params=params)
            else:
                response = requests.get(next_link, headers=headers)
            
            response.raise_for_status()
            data = response.json()
            
            incidents.extend(data.get('value', []))
            next_link = data.get('@odata.nextLink')
            
            print(f"  Fetched {len(incidents)} incidents so far...")
        
        print(f"✓ Total incidents fetched: {len(incidents)}")
        return incidents
    
    def fetch_sentinel_alerts(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Fetch alerts from Microsoft Sentinel via Azure Monitor API
        
        API: Azure Monitor Query API
        Documentation: https://learn.microsoft.com/en-us/rest/api/loganalytics/
        """
        print(f"Fetching Sentinel alerts from last {days} days...")
        
        # KQL query for Sentinel alerts
        kql_query = f"""
        SecurityAlert
        | where TimeGenerated > ago({days}d)
        | project 
            TimeGenerated,
            AlertName,
            AlertSeverity,
            Description,
            ProviderName,
            Status,
            Tactics,
            Techniques,
            Entities,
            ExtendedProperties,
            CompromisedEntity
        | order by TimeGenerated desc
        """
        
        endpoint = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        body = {
            'query': kql_query
        }
        
        response = requests.post(endpoint, headers=headers, json=body)
        response.raise_for_status()
        data = response.json()
        
        # Parse tabular results
        columns = [col['name'] for col in data['tables'][0]['columns']]
        rows = data['tables'][0]['rows']
        
        alerts = [dict(zip(columns, row)) for row in rows]
        
        print(f"✓ Total alerts fetched: {len(alerts)}")
        return alerts
    
    def flatten_incident_data(self, incidents: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Flatten incident data into Power BI-friendly tabular format
        Handles nested JSON structures
        """
        print("Flattening incident data for Power BI...")
        
        flattened = []
        
        for incident in incidents:
            # Extract main incident fields
            base_record = {
                'IncidentId': incident.get('incidentId'),
                'IncidentName': incident.get('incidentName'),
                'Severity': incident.get('severity'),
                'Status': incident.get('status'),
                'Classification': incident.get('classification'),
                'Determination': incident.get('determination'),
                'AssignedTo': incident.get('assignedTo'),
                'CreatedTime': incident.get('createdTime'),
                'LastUpdateTime': incident.get('lastUpdateTime'),
                'ResolvedTime': incident.get('resolvedTime'),
                'FirstActivityTime': incident.get('firstActivityTime'),
                'LastActivityTime': incident.get('lastActivityTime'),
                'AlertCount': len(incident.get('alerts', [])),
                'Tags': ','.join(incident.get('tags', [])),
                'Comments': len(incident.get('comments', [])),
            }
            
            # Extract MITRE ATT&CK techniques
            categories = incident.get('incidentCategories', [])
            techniques = incident.get('mitreTechniques', [])
            base_record['MitreCategories'] = ','.join(categories) if categories else ''
            base_record['MitreTechniques'] = ','.join(techniques) if techniques else ''
            
            # Extract entities (IPs, Users, Devices)
            entities = []
            devices = []
            users = []
            ips = []
            
            for alert in incident.get('alerts', []):
                for entity in alert.get('entities', []):
                    entity_type = entity.get('entityType', '')
                    if entity_type == 'Ip':
                        ips.append(entity.get('ipAddress', ''))
                    elif entity_type == 'User':
                        users.append(entity.get('accountName', ''))
                    elif entity_type == 'Machine':
                        devices.append(entity.get('deviceDnsName', ''))
            
            base_record['DeviceNames'] = ','.join(set(devices))
            base_record['UserNames'] = ','.join(set(users))
            base_record['IpAddresses'] = ','.join(set(ips))
            base_record['DeviceCount'] = len(set(devices))
            base_record['UserCount'] = len(set(users))
            base_record['IpCount'] = len(set(ips))
            
            flattened.append(base_record)
        
        df = pd.DataFrame(flattened)
        
        # Convert timestamps to datetime
        timestamp_cols = ['CreatedTime', 'LastUpdateTime', 'ResolvedTime', 
                         'FirstActivityTime', 'LastActivityTime']
        for col in timestamp_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        print(f"✓ Flattened {len(df)} incident records")
        return df
    
    def create_alerts_dataframe(self, incidents: List[Dict[str, Any]]) -> pd.DataFrame:
        """Create a separate alerts table for Power BI relationship model"""
        print("Creating alerts dataframe...")
        
        alerts_data = []
        
        for incident in incidents:
            incident_id = incident.get('incidentId')
            
            for alert in incident.get('alerts', []):
                alert_record = {
                    'IncidentId': incident_id,
                    'AlertId': alert.get('alertId'),
                    'Title': alert.get('title'),
                    'Severity': alert.get('severity'),
                    'Category': alert.get('category'),
                    'Status': alert.get('status'),
                    'DetectionSource': alert.get('detectionSource'),
                    'ServiceSource': alert.get('serviceSource'),
                    'CreatedTime': alert.get('alertCreationTime'),
                    'FirstActivity': alert.get('firstActivity'),
                    'LastActivity': alert.get('lastActivity'),
                    'MitreTechniques': ','.join(alert.get('mitreTechniques', [])),
                }
                alerts_data.append(alert_record)
        
        df = pd.DataFrame(alerts_data)
        
        # Convert timestamps
        timestamp_cols = ['CreatedTime', 'FirstActivity', 'LastActivity']
        for col in timestamp_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
        
        print(f"✓ Created {len(df)} alert records")
        return df
    
    def create_entities_dataframe(self, incidents: List[Dict[str, Any]]) -> pd.DataFrame:
        """Create entities table (IPs, Users, Devices) for detailed analysis"""
        print("Creating entities dataframe...")
        
        entities_data = []
        
        for incident in incidents:
            incident_id = incident.get('incidentId')
            
            for alert in incident.get('alerts', []):
                alert_id = alert.get('alertId')
                
                for entity in alert.get('entities', []):
                    entity_record = {
                        'IncidentId': incident_id,
                        'AlertId': alert_id,
                        'EntityType': entity.get('entityType'),
                        'IpAddress': entity.get('ipAddress', ''),
                        'AccountName': entity.get('accountName', ''),
                        'DeviceName': entity.get('deviceDnsName', ''),
                        'FileName': entity.get('fileName', ''),
                        'FilePath': entity.get('filePath', ''),
                        'Sha1': entity.get('sha1', ''),
                        'Sha256': entity.get('sha256', ''),
                        'Url': entity.get('url', ''),
                    }
                    entities_data.append(entity_record)
        
        df = pd.DataFrame(entities_data)
        print(f"✓ Created {len(df)} entity records")
        return df
    
    def export_to_csv(self, dataframes: Dict[str, pd.DataFrame], prefix: str = "powerbi"):
        """Export dataframes to CSV files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for name, df in dataframes.items():
            filename = self.output_dir / f"{prefix}_{name}_{timestamp}.csv"
            df.to_csv(filename, index=False, encoding='utf-8-sig')
            print(f"✓ Exported: {filename}")
    
    def export_to_json(self, dataframes: Dict[str, pd.DataFrame], prefix: str = "powerbi"):
        """Export dataframes to JSON files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for name, df in dataframes.items():
            filename = self.output_dir / f"{prefix}_{name}_{timestamp}.json"
            df.to_json(filename, orient='records', date_format='iso', indent=2)
            print(f"✓ Exported: {filename}")
    
    def export_to_excel(self, dataframes: Dict[str, pd.DataFrame], prefix: str = "powerbi"):
        """Export all dataframes to a single Excel file with multiple sheets"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"{prefix}_dataset_{timestamp}.xlsx"
        
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            for name, df in dataframes.items():
                # Excel sheet names limited to 31 characters
                sheet_name = name[:31]
                df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        print(f"✓ Exported Excel: {filename}")
    
    def create_metadata(self, dataframes: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
        """Create metadata file for Power BI import"""
        metadata = {
            'export_timestamp': datetime.now().isoformat(),
            'tenant_id': self.tenant_id,
            'workspace_id': self.workspace_id,
            'tables': {}
        }
        
        for name, df in dataframes.items():
            metadata['tables'][name] = {
                'row_count': len(df),
                'columns': list(df.columns),
                'dtypes': {col: str(dtype) for col, dtype in df.dtypes.items()}
            }
        
        return metadata
    
    def run(self, days: int = 7, export_format: str = 'both'):
        """Main execution flow"""
        print("=" * 80)
        print("CyberProbe Power BI Data Export")
        print("=" * 80)
        
        try:
            # Authenticate
            print("\n[1/5] Authenticating...")
            # self.access_token = self.get_access_token()  # Uncomment when auth is implemented
            
            # For now, show instructions
            print("\n⚠️  This script requires Azure AD authentication to be implemented.")
            print("Once authentication is configured, it will:")
            print("  1. Fetch incidents from Defender XDR API")
            print("  2. Fetch alerts from Sentinel API")
            print("  3. Flatten data into Power BI tables")
            print("  4. Export to CSV/JSON/Excel")
            
            print("\n" + "=" * 80)
            print("POWER BI IMPORT INSTRUCTIONS")
            print("=" * 80)
            print("\n1. After running this script successfully, you'll have:")
            print("   - incidents.csv: Main incidents table")
            print("   - alerts.csv: Alert details (many-to-one with incidents)")
            print("   - entities.csv: IP/User/Device entities (many-to-many)")
            
            print("\n2. Import into Power BI Desktop:")
            print("   - Get Data > Text/CSV > Select each CSV file")
            print("   - Or: Get Data > Excel > Import all sheets at once")
            
            print("\n3. Create relationships:")
            print("   - incidents[IncidentId] 1:* alerts[IncidentId]")
            print("   - incidents[IncidentId] 1:* entities[IncidentId]")
            print("   - alerts[AlertId] 1:* entities[AlertId]")
            
            print("\n4. Create a Date table for time intelligence:")
            print("   Date = CALENDAR(MIN(incidents[CreatedTime]), MAX(incidents[CreatedTime]))")
            
            print("\n5. Suggested DAX measures:")
            print("   Total Incidents = COUNTROWS(incidents)")
            print("   High Severity = CALCULATE([Total Incidents], incidents[Severity] = \"High\")")
            print("   Avg Resolution Time = AVERAGEX(incidents, incidents[ResolvedTime] - incidents[CreatedTime])")
            print("   Active Incidents = CALCULATE([Total Incidents], incidents[Status] <> \"Resolved\")")
            
            print("\n6. For automated refresh:")
            print("   - Publish to Power BI Service")
            print("   - Configure Gateway for file refresh")
            print("   - Or: Use Python script in Power BI dataflow")
            print("   - Set up scheduled refresh (daily/hourly)")
            
            print("\n" + "=" * 80)
            
            return {
                'status': 'pending_authentication',
                'message': 'Please implement authentication in get_access_token() method'
            }
            
            # Uncomment below when authentication is ready:
            """
            # Fetch data
            print("\n[2/5] Fetching Defender incidents...")
            incidents = self.fetch_defender_incidents(days)
            
            print("\n[3/5] Processing data...")
            dataframes = {
                'incidents': self.flatten_incident_data(incidents),
                'alerts': self.create_alerts_dataframe(incidents),
                'entities': self.create_entities_dataframe(incidents)
            }
            
            # Export
            print("\n[4/5] Exporting data...")
            if export_format in ['csv', 'both']:
                self.export_to_csv(dataframes)
            
            if export_format in ['json', 'both']:
                self.export_to_json(dataframes)
            
            # Always create Excel for convenience
            self.export_to_excel(dataframes)
            
            # Create metadata
            print("\n[5/5] Creating metadata...")
            metadata = self.create_metadata(dataframes)
            metadata_file = self.output_dir / f"powerbi_metadata_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            print(f"✓ Metadata saved: {metadata_file}")
            
            print("\n" + "=" * 80)
            print("✓ EXPORT COMPLETE")
            print("=" * 80)
            print(f"\nFiles exported to: {self.output_dir}")
            print("\nNext steps:")
            print("1. Open Power BI Desktop")
            print("2. Get Data > Excel > Select the .xlsx file")
            print("3. Create relationships between tables")
            print("4. Build your visualizations")
            
            return {
                'status': 'success',
                'dataframes': dataframes,
                'metadata': metadata
            }
            """
            
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
            raise


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Export Defender/Sentinel data for Power BI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enrichment/powerbi_data_export.py --days 7 --format csv
  python enrichment/powerbi_data_export.py --days 30 --format both
  cd enrichment && python powerbi_data_export.py --format excel
        """
    )
    
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to fetch data for (default: 7)'
    )
    
    parser.add_argument(
        '--format',
        choices=['csv', 'json', 'excel', 'both'],
        default='both',
        help='Export format (default: both csv and json)'
    )
    
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to config file (default: config.json)'
    )
    
    args = parser.parse_args()
    
    exporter = DefenderDataExporter(args.config)
    exporter.run(days=args.days, export_format=args.format)


if __name__ == '__main__':
    main()
