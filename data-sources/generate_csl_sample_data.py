"""
CommonSecurityLog Sample Data Generator

Generates realistic CEF events and sends them to Microsoft Sentinel
via the Azure Monitor Logs Ingestion API (DCR-based).

Usage:
    # Generate JSON file only (no Azure required)
    python generate_csl_sample_data.py --output sample_csl_events.json --count 100

    # Send to Sentinel via Logs Ingestion API
    python generate_csl_sample_data.py --send --dce-url <DCE_URL> --dcr-id <DCR_ID> --stream <STREAM_NAME>

    # Both: generate file AND send to Sentinel
    python generate_csl_sample_data.py --output sample_csl_events.json --send --dce-url <DCE_URL> --dcr-id <DCR_ID>

Prerequisites for --send mode:
    pip install azure-identity azure-monitor-ingestion

    Required Azure resources:
    1. Data Collection Endpoint (DCE)
    2. Data Collection Rule (DCR) targeting CommonSecurityLog
    3. App Registration with 'Monitoring Metrics Publisher' role on the DCR
    See: LOGS_INGESTION_SETUP.md for step-by-step instructions

For complete documentation, see:
    - enrichment/LOGS_INGESTION_SETUP.md
    - https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview
"""

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Vendor / Product profiles
# ---------------------------------------------------------------------------

VENDOR_PROFILES = [
    {
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "version": "11.1.2",
        "scenarios": [
            {"class_id": "TRAFFIC", "activity": "traffic", "actions": ["allow", "deny", "drop", "reset-both"]},
            {"class_id": "THREAT", "activity": "threat", "actions": ["alert", "drop", "reset-both", "block-url"]},
            {"class_id": "URL", "activity": "url", "actions": ["allow", "block-url", "alert"]},
        ],
    },
    {
        "vendor": "Fortinet",
        "product": "FortiGate",
        "version": "7.4.3",
        "scenarios": [
            {"class_id": "0000000013", "activity": "traffic:forward", "actions": ["accept", "deny", "close"]},
            {"class_id": "0419016384", "activity": "utm:ips", "actions": ["detected", "dropped", "blocked"]},
            {"class_id": "0211008192", "activity": "utm:webfilter", "actions": ["passthrough", "blocked"]},
        ],
    },
    {
        "vendor": "Check Point",
        "product": "VPN-1",
        "version": "R82",
        "scenarios": [
            {"class_id": "Accept", "activity": "Accept", "actions": ["Accept", "Drop", "Reject"]},
            {"class_id": "Log", "activity": "Log", "actions": ["Accept", "Drop", "Reject", "Detect"]},
            {"class_id": "Alert", "activity": "Alert", "actions": ["Detect", "Prevent"]},
        ],
    },
    {
        "vendor": "Zscaler",
        "product": "ZscalerNSS",
        "version": "6.2",
        "scenarios": [
            {"class_id": "1", "activity": "Web Traffic", "actions": ["Allowed", "Blocked", "Cautioned"]},
            {"class_id": "4", "activity": "SSL Inspection", "actions": ["Inspected", "Bypassed"]},
        ],
    },
    {
        "vendor": "Cisco",
        "product": "ASA",
        "version": "9.18",
        "scenarios": [
            {"class_id": "106023", "activity": "Deny inbound packet", "actions": ["Deny"]},
            {"class_id": "302013", "activity": "Built outbound TCP connection", "actions": ["Built"]},
            {"class_id": "302014", "activity": "Teardown TCP connection", "actions": ["Teardown"]},
            {"class_id": "710003", "activity": "TCP access permitted", "actions": ["Permit"]},
        ],
    },
]

# ---------------------------------------------------------------------------
# Attack scenario templates
# ---------------------------------------------------------------------------

ATTACK_SCENARIOS = {
    "port_scan": {
        "severity": "5",
        "protocol": "TCP",
        "dst_ports": [22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443],
        "event_category": "Reconnaissance",
        "reason": "Multiple connection attempts to different ports from single source",
    },
    "brute_force": {
        "severity": "7",
        "protocol": "TCP",
        "dst_ports": [22, 3389, 443],
        "event_category": "Authentication",
        "reason": "Multiple failed authentication attempts",
    },
    "malware_download": {
        "severity": "9",
        "protocol": "TCP",
        "dst_ports": [80, 443, 8080],
        "event_category": "Malware",
        "reason": "Known malware signature detected in payload",
    },
    "c2_communication": {
        "severity": "10",
        "protocol": "TCP",
        "dst_ports": [443, 8443, 4444, 9001],
        "event_category": "Command-and-Control",
        "reason": "Periodic beaconing to known C2 infrastructure",
    },
    "data_exfiltration": {
        "severity": "8",
        "protocol": "TCP",
        "dst_ports": [443, 53, 8080],
        "event_category": "Exfiltration",
        "reason": "Large outbound data transfer to external IP",
    },
    "normal_traffic": {
        "severity": "1",
        "protocol": "TCP",
        "dst_ports": [80, 443, 53, 25, 110, 993],
        "event_category": "Traffic",
        "reason": "",
    },
}

# ---------------------------------------------------------------------------
# IP pools
# ---------------------------------------------------------------------------

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.25", "10.0.1.50", "10.0.1.100",
    "10.0.2.15", "10.0.2.30", "10.0.2.55", "10.0.2.80",
    "172.16.0.10", "172.16.0.20", "172.16.0.50",
    "192.168.1.10", "192.168.1.25", "192.168.1.100",
]

EXTERNAL_IPS_CLEAN = [
    "8.8.8.8", "1.1.1.1", "13.107.42.14", "20.54.36.100",
    "52.96.166.130", "104.18.21.226", "151.101.1.140",
    "142.250.80.46", "157.240.1.35", "23.32.248.100",
]

EXTERNAL_IPS_SUSPICIOUS = [
    "185.220.101.45", "91.234.100.22", "45.155.205.233",
    "193.42.33.100", "89.248.167.131", "5.188.86.172",
    "103.136.42.20", "45.83.64.1", "194.26.29.110",
    "178.128.83.165",
]

USERNAMES = [
    "jdoe", "admin", "svc-backup", "root", "webadmin",
    "scanner", "sa", "postgres", "ftpuser", "guest",
]

FIREWALL_NAMES = [
    "fw-edge-01.contoso.local", "fw-dmz-01.contoso.local",
    "fw-internal-01.contoso.local", "fw-branch-01.contoso.local",
]

REQUEST_URLS = [
    "https://login.microsoftonline.com/common/oauth2/token",
    "https://outlook.office365.com/api/v2.0/me/messages",
    "http://evil-download.ru/payload.exe",
    "https://pastebin.com/raw/abc123",
    "https://api.telegram.org/bot/sendMessage",
    "http://103.136.42.20:8080/beacon",
    "https://drive.google.com/uc?export=download&id=FAKE",
    "https://contoso.sharepoint.com/sites/finance/report.xlsx",
]


def generate_event(
    event_time: datetime,
    scenario_name: str,
    tenant_id: str = "00000000-0000-0000-0000-000000000000",
) -> dict:
    """Generate a single CommonSecurityLog event."""

    scenario = ATTACK_SCENARIOS[scenario_name]
    vendor_profile = random.choice(VENDOR_PROFILES)
    vendor_scenario = random.choice(vendor_profile["scenarios"])

    is_malicious = scenario_name != "normal_traffic"
    src_ip = random.choice(EXTERNAL_IPS_SUSPICIOUS if is_malicious else INTERNAL_IPS)
    dst_ip = random.choice(INTERNAL_IPS if is_malicious else EXTERNAL_IPS_CLEAN)
    dst_port = random.choice(scenario["dst_ports"])
    src_port = random.randint(1024, 65535)

    # For exfiltration, reverse direction
    if scenario_name == "data_exfiltration":
        src_ip, dst_ip = dst_ip, src_ip

    action = random.choice(vendor_scenario["actions"])
    direction = "1" if src_ip.startswith(("10.", "172.16.", "192.168.")) else "0"
    comm_direction = "Outbound" if direction == "1" else "Inbound"

    sent = random.randint(40, 500)
    received = random.randint(40, 2000)
    if scenario_name == "data_exfiltration":
        sent = random.randint(50000, 5000000)
    if scenario_name == "malware_download":
        received = random.randint(100000, 10000000)

    fw_name = random.choice(FIREWALL_NAMES)

    # TI matching for suspicious IPs
    malicious_ip = ""
    threat_severity = 0
    threat_type = ""
    threat_desc = ""
    threat_confidence = ""
    malicious_country = ""
    mal_lat = None
    mal_lon = None

    if is_malicious and src_ip in EXTERNAL_IPS_SUSPICIOUS:
        malicious_ip = src_ip
        threat_severity = random.choice([3, 5, 7, 9])
        threat_type = random.choice(["Botnet", "C2", "MalwareDownload", "Scanner", "BruteForce"])
        threat_desc = scenario["reason"]
        threat_confidence = str(random.randint(60, 99))
        malicious_country = random.choice(["RU", "CN", "RO", "NG", "VN"])
        mal_lat = round(random.uniform(30.0, 60.0), 4)
        mal_lon = round(random.uniform(20.0, 120.0), 4)

    event = {
        "TenantId": tenant_id,
        "TimeGenerated": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "DeviceVendor": vendor_profile["vendor"],
        "DeviceProduct": vendor_profile["product"],
        "DeviceVersion": vendor_profile["version"],
        "DeviceEventClassID": vendor_scenario["class_id"],
        "Activity": vendor_scenario["activity"],
        "LogSeverity": scenario["severity"],
        "OriginalLogSeverity": scenario["severity"],
        "AdditionalExtensions": f"scenario={scenario_name};category={scenario['event_category']}",
        "DeviceAction": action,
        "ApplicationProtocol": random.choice(["HTTP", "HTTPS", "SSH", "DNS", "SMTP", ""]),
        "EventCount": 1,
        "DestinationDnsDomain": "",
        "DestinationServiceName": "",
        "DestinationTranslatedAddress": dst_ip,
        "DestinationTranslatedPort": dst_port,
        "CommunicationDirection": comm_direction,
        "DeviceDnsDomain": "contoso.local",
        "DeviceExternalID": str(uuid.uuid4()),
        "DeviceFacility": "",
        "DeviceInboundInterface": "ethernet1/1" if direction == "0" else "",
        "DeviceNtDomain": "CONTOSO",
        "DeviceOutboundInterface": "ethernet1/2" if direction == "1" else "",
        "DevicePayloadId": "",
        "ProcessName": "",
        "DeviceTranslatedAddress": fw_name.split(".")[0],
        "DestinationHostName": "",
        "DestinationMACAddress": "",
        "DestinationNTDomain": "",
        "DestinationProcessId": 0,
        "DestinationUserPrivileges": "",
        "DestinationProcessName": "",
        "DestinationPort": dst_port,
        "DestinationIP": dst_ip,
        "DeviceTimeZone": "UTC",
        "DestinationUserID": "",
        "DestinationUserName": random.choice(USERNAMES) if scenario_name == "brute_force" else "",
        "DeviceAddress": f"10.0.0.{random.randint(1, 5)}",
        "DeviceName": fw_name,
        "DeviceMacAddress": "",
        "ProcessID": 0,
        "EndTime": (event_time + timedelta(seconds=random.randint(0, 30))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "ExternalID": random.randint(100000, 999999),
        "ExtID": str(random.randint(100000, 999999)),
        "FileCreateTime": "",
        "FileHash": "",
        "FileID": "",
        "FileModificationTime": "",
        "FilePath": "",
        "FilePermission": "",
        "FileType": "",
        "FileName": "payload.exe" if scenario_name == "malware_download" else "",
        "FileSize": received if scenario_name == "malware_download" else 0,
        "ReceivedBytes": received,
        "Message": f"CEF:0|{vendor_profile['vendor']}|{vendor_profile['product']}|{vendor_profile['version']}|{vendor_scenario['class_id']}|{vendor_scenario['activity']}|{scenario['severity']}|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} act={action}",
        "OldFileCreateTime": "",
        "OldFileHash": "",
        "OldFileID": "",
        "OldFileModificationTime": "",
        "OldFileName": "",
        "OldFilePath": "",
        "OldFilePermission": "",
        "OldFileSize": 0,
        "OldFileType": "",
        "SentBytes": sent,
        "EventOutcome": "Success" if "allow" in action.lower() or "accept" in action.lower() or "built" in action.lower() or "permit" in action.lower() else "Failure",
        "Protocol": scenario["protocol"],
        "Reason": scenario["reason"],
        "RequestURL": random.choice(REQUEST_URLS) if scenario_name in ("malware_download", "c2_communication", "data_exfiltration") else "",
        "RequestClientApplication": random.choice(["Mozilla/5.0", "curl/7.88.1", "Python-urllib/3.11", "PowerShell/7.3", ""]),
        "RequestContext": "",
        "RequestCookies": "",
        "RequestMethod": random.choice(["GET", "POST", ""]),
        "ReceiptTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SourceHostName": "",
        "SourceMACAddress": "",
        "SourceNTDomain": "",
        "SourceDnsDomain": "",
        "SourceServiceName": "",
        "SourceTranslatedAddress": src_ip,
        "SourceTranslatedPort": src_port,
        "SourceProcessId": 0,
        "SourceUserPrivileges": "",
        "SourceProcessName": "",
        "SourcePort": src_port,
        "SourceIP": src_ip,
        "StartTime": event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "SourceUserID": "",
        "SourceUserName": random.choice(USERNAMES) if scenario_name == "brute_force" else "",
        "EventType": 0,
        "DeviceEventCategory": scenario["event_category"],
        "DeviceCustomIPv6Address1": "",
        "DeviceCustomIPv6Address1Label": "",
        "DeviceCustomIPv6Address2": "",
        "DeviceCustomIPv6Address2Label": "",
        "DeviceCustomIPv6Address3": "",
        "DeviceCustomIPv6Address3Label": "",
        "DeviceCustomIPv6Address4": "",
        "DeviceCustomIPv6Address4Label": "",
        "DeviceCustomFloatingPoint1": 0.0,
        "DeviceCustomFloatingPoint1Label": "",
        "DeviceCustomFloatingPoint2": 0.0,
        "DeviceCustomFloatingPoint2Label": "",
        "DeviceCustomFloatingPoint3": 0.0,
        "DeviceCustomFloatingPoint3Label": "",
        "DeviceCustomFloatingPoint4": 0.0,
        "DeviceCustomFloatingPoint4Label": "",
        "DeviceCustomNumber1": 0,
        "FieldDeviceCustomNumber1": sent,
        "DeviceCustomNumber1Label": "TotalBytesSent",
        "DeviceCustomNumber2": 0,
        "FieldDeviceCustomNumber2": received,
        "DeviceCustomNumber2Label": "TotalBytesReceived",
        "DeviceCustomNumber3": 0,
        "FieldDeviceCustomNumber3": 0,
        "DeviceCustomNumber3Label": "",
        "DeviceCustomString1": scenario_name,
        "DeviceCustomString1Label": "AttackScenario",
        "DeviceCustomString2": scenario["event_category"],
        "DeviceCustomString2Label": "ThreatCategory",
        "DeviceCustomString3": "",
        "DeviceCustomString3Label": "",
        "DeviceCustomString4": "",
        "DeviceCustomString4Label": "",
        "DeviceCustomString5": "",
        "DeviceCustomString5Label": "",
        "DeviceCustomString6": "",
        "DeviceCustomString6Label": "",
        "DeviceCustomDate1": "",
        "DeviceCustomDate1Label": "",
        "DeviceCustomDate2": "",
        "DeviceCustomDate2Label": "",
        "FlexDate1": "",
        "FlexDate1Label": "",
        "FlexNumber1": 0,
        "FlexNumber1Label": "",
        "FlexNumber2": 0,
        "FlexNumber2Label": "",
        "FlexString1": vendor_profile["vendor"],
        "FlexString1Label": "OriginalVendor",
        "FlexString2": action,
        "FlexString2Label": "OriginalAction",
        "RemoteIP": src_ip if direction == "0" else dst_ip,
        "RemotePort": str(src_port if direction == "0" else dst_port),
        "MaliciousIP": malicious_ip,
        "ThreatSeverity": threat_severity,
        "IndicatorThreatType": threat_type,
        "ThreatDescription": threat_desc,
        "ThreatConfidence": threat_confidence,
        "ReportReferenceLink": "",
        "MaliciousIPLongitude": mal_lon if mal_lon else 0.0,
        "MaliciousIPLatitude": mal_lat if mal_lat else 0.0,
        "MaliciousIPCountry": malicious_country,
        "Computer": fw_name,
        "SourceSystem": "OpsManager",
        "SimplifiedDeviceAction": action.lower().replace("-", "").replace("_", ""),
        "CollectorHostName": "cef-collector-01.contoso.local",
    }

    return event


def generate_dataset(
    count: int = 100,
    days_back: int = 7,
    tenant_id: str = "00000000-0000-0000-0000-000000000000",
) -> list[dict]:
    """Generate a dataset of CommonSecurityLog events with realistic scenario distribution."""

    # Weighted scenario distribution
    scenario_weights = {
        "normal_traffic": 60,
        "port_scan": 10,
        "brute_force": 10,
        "malware_download": 5,
        "c2_communication": 5,
        "data_exfiltration": 10,
    }

    scenarios = []
    for name, weight in scenario_weights.items():
        scenarios.extend([name] * weight)

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days_back)

    events = []
    for _ in range(count):
        scenario_name = random.choice(scenarios)
        event_time = start_time + timedelta(
            seconds=random.randint(0, int(timedelta(days=days_back).total_seconds()))
        )
        events.append(generate_event(event_time, scenario_name, tenant_id))

    # Sort chronologically
    events.sort(key=lambda e: e["TimeGenerated"])
    return events


def send_to_sentinel(events: list[dict], dce_url: str, dcr_id: str, stream_name: str) -> None:
    """Send events to Sentinel via Azure Monitor Logs Ingestion API."""

    try:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.ingestion import LogsIngestionClient
    except ImportError:
        print("ERROR: Required packages not installed. Run:")
        print("  pip install azure-identity azure-monitor-ingestion")
        sys.exit(1)

    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=dce_url, credential=credential)

    # Send in batches of 500 (API limit is ~1MB per request)
    batch_size = 500
    total_sent = 0

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        try:
            client.upload(rule_id=dcr_id, stream_name=stream_name, logs=batch)
            total_sent += len(batch)
            print(f"  Sent batch {i // batch_size + 1}: {len(batch)} events (total: {total_sent}/{len(events)})")
        except Exception as e:
            print(f"  ERROR sending batch {i // batch_size + 1}: {e}")
            raise

    print(f"\nDone. {total_sent} events sent to CommonSecurityLog.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate CommonSecurityLog sample data and optionally send to Sentinel via Logs Ingestion API"
    )
    parser.add_argument("--count", type=int, default=100, help="Number of events to generate (default: 100)")
    parser.add_argument("--days", type=int, default=7, help="Days of history to spread events across (default: 7)")
    parser.add_argument("--output", type=str, help="Output JSON file path (e.g., sample_csl_events.json)")
    parser.add_argument("--send", action="store_true", help="Send events to Sentinel via Logs Ingestion API")
    parser.add_argument("--dce-url", type=str, help="Data Collection Endpoint URL (required with --send)")
    parser.add_argument("--dcr-id", type=str, help="Data Collection Rule immutable ID (required with --send)")
    parser.add_argument("--stream", type=str, default="Custom-CommonSecurityLog", help="DCR stream name (default: Custom-CommonSecurityLog)")
    parser.add_argument("--tenant-id", type=str, default="00000000-0000-0000-0000-000000000000", help="Tenant GUID for TenantId field")

    args = parser.parse_args()

    if not args.output and not args.send:
        parser.error("Specify --output, --send, or both")

    if args.send and (not args.dce_url or not args.dcr_id):
        parser.error("--send requires --dce-url and --dcr-id")

    # Load tenant ID from config if available
    tenant_id = args.tenant_id
    if tenant_id == "00000000-0000-0000-0000-000000000000":
        config_path = Path(__file__).parent.parent / "enrichment" / "config.json"
        if config_path.exists():
            with open(config_path, "r") as f:
                config = json.load(f)
                tenant_id = config.get("tenant_id", tenant_id)

    print(f"Generating {args.count} CommonSecurityLog events over {args.days} days...")
    events = generate_dataset(count=args.count, days_back=args.days, tenant_id=tenant_id)

    # Print scenario distribution
    from collections import Counter
    scenarios = Counter(e["DeviceCustomString1"] for e in events)
    print(f"\nScenario distribution:")
    for name, cnt in scenarios.most_common():
        print(f"  {name}: {cnt}")

    vendors = Counter(e["DeviceVendor"] for e in events)
    print(f"\nVendor distribution:")
    for name, cnt in vendors.most_common():
        print(f"  {name}: {cnt}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(events, f, indent=2)
        print(f"\nSaved {len(events)} events to {output_path}")

    if args.send:
        print(f"\nSending {len(events)} events to Sentinel...")
        print(f"  DCE: {args.dce_url}")
        print(f"  DCR: {args.dcr_id}")
        print(f"  Stream: {args.stream}")
        send_to_sentinel(events, args.dce_url, args.dcr_id, args.stream)


if __name__ == "__main__":
    main()
