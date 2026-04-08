"""
Ad-hoc IP Enrichment Utility

This script is used by the 'threat-enrichment' Agent Skill.
See: .github/skills/threat-enrichment/SKILL.md

Usage:
    python enrich_ips.py <ip1> <ip2> <ip3> ...
    python enrich_ips.py --file investigation.json
    python enrich_ips.py 203.0.113.42 198.51.100.10

Enriches IP addresses using ipinfo.io, vpnapi.io, AbuseIPDB, and Shodan.

For complete documentation, see:
- .github/skills/threat-enrichment/SKILL.md
- Investigation-Guide.md Section 11 (External Enrichment)
"""

import json
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def load_config() -> dict:
    """Load API tokens from config.json"""
    config_path = Path(__file__).parent / 'config.json'
    with open(config_path, 'r') as f:
        return json.load(f)


def enrich_single_ip(ip: str, config: dict) -> dict:
    """Enrich a single IP address using multiple threat intelligence APIs"""
    result = {
        'ip': ip,
        'city': 'Unknown',
        'region': 'Unknown',
        'country': 'Unknown',
        'org': 'Unknown',
        'asn': 'Unknown',
        'timezone': 'Unknown',
        'is_vpn': False,
        'is_proxy': False,
        'is_tor': False,
        'is_hosting': False,
        'vpnapi_security_vpn': False,
        'vpnapi_security_proxy': False,
        'vpnapi_security_tor': False,
        'vpnapi_security_relay': False,
        'abuse_confidence_score': 0,
        'total_reports': 0,
        'is_whitelisted': False,
        'shodan_ports': [],
        'shodan_vulns': [],
        'shodan_tags': [],
        'shodan_os': None,
        'shodan_hostnames': [],
    }
    
    # 1. IPInfo.io enrichment
    ipinfo_token = config.get('api_keys', {}).get('ipinfo')
    try:
        url = f"https://ipinfo.io/{ip}/json"
        params = {'token': ipinfo_token} if ipinfo_token else {}
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            ipinfo_data = response.json()
            result['city'] = ipinfo_data.get('city', 'Unknown')
            result['region'] = ipinfo_data.get('region', 'Unknown')
            result['country'] = ipinfo_data.get('country', 'Unknown')
            result['org'] = ipinfo_data.get('org', 'Unknown')
            result['timezone'] = ipinfo_data.get('timezone', 'Unknown')
            
            privacy = ipinfo_data.get('privacy', {})
            result['is_vpn'] = privacy.get('vpn', False)
            result['is_proxy'] = privacy.get('proxy', False)
            result['is_tor'] = privacy.get('tor', False)
            result['is_hosting'] = privacy.get('hosting', False)
            
            org_str = ipinfo_data.get('org', '')
            if org_str.startswith('AS'):
                result['asn'] = org_str.split(' ')[0]
    except Exception as e:
        print(f"  [ipinfo.io] Error for {ip}: {str(e)}", file=sys.stderr)
    
    # 2. VPNapi.io enrichment
    vpnapi_token = config.get('api_keys', {}).get('vpnapi')
    try:
        url = f"https://vpnapi.io/api/{ip}"
        params = {'key': vpnapi_token} if vpnapi_token else {}
        response = requests.get(url, params=params, timeout=5)
        
        if response.status_code == 200:
            vpnapi_data = response.json()
            security = vpnapi_data.get('security', {})
            result['vpnapi_security_vpn'] = security.get('vpn', False)
            result['vpnapi_security_proxy'] = security.get('proxy', False)
            result['vpnapi_security_tor'] = security.get('tor', False)
            result['vpnapi_security_relay'] = security.get('relay', False)
    except Exception as e:
        print(f"  [vpnapi.io] Error for {ip}: {str(e)}", file=sys.stderr)
    
    # 3. AbuseIPDB enrichment
    abuseipdb_token = config.get('api_keys', {}).get('abuseipdb')
    if abuseipdb_token:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': abuseipdb_token,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                abuse_data = response.json().get('data', {})
                result['abuse_confidence_score'] = abuse_data.get('abuseConfidenceScore', 0)
                result['total_reports'] = abuse_data.get('totalReports', 0)
                result['is_whitelisted'] = abuse_data.get('isWhitelisted', False)
            elif response.status_code == 429:
                print(f"  [AbuseIPDB] Rate limit for {ip}", file=sys.stderr)
        except Exception as e:
            print(f"  [AbuseIPDB] Error for {ip}: {str(e)}", file=sys.stderr)
    
    # 4. Shodan enrichment (full API with InternetDB fallback)
    shodan_token = config.get('api_keys', {}).get('shodan')
    shodan_done = False
    if shodan_token:
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {'key': shodan_token}
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                shodan_data = response.json()
                result['shodan_ports'] = shodan_data.get('ports', [])
                result['shodan_vulns'] = list(shodan_data.get('vulns', []))
                result['shodan_tags'] = shodan_data.get('tags', [])
                result['shodan_os'] = shodan_data.get('os')
                result['shodan_hostnames'] = shodan_data.get('hostnames', [])
                shodan_done = True
            elif response.status_code in (403, 429):
                print(f"  [Shodan] API limit/auth error for {ip}, falling back to InternetDB", file=sys.stderr)
        except Exception as e:
            print(f"  [Shodan] API error for {ip}: {str(e)}, falling back to InternetDB", file=sys.stderr)
    
    # Shodan InternetDB fallback (free, no API key needed)
    if not shodan_done:
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                idb_data = response.json()
                result['shodan_ports'] = idb_data.get('ports', [])
                result['shodan_vulns'] = idb_data.get('vulns', [])
                result['shodan_tags'] = idb_data.get('tags', [])
                result['shodan_hostnames'] = idb_data.get('hostnames', [])
        except Exception as e:
            print(f"  [InternetDB] Error for {ip}: {str(e)}", file=sys.stderr)
    
    return result


def enrich_ips(ip_list: list[str], max_workers: int = 3) -> list[dict]:
    """Enrich multiple IPs in parallel"""
    config = load_config()
    results = []
    
    print(f"Enriching {len(ip_list)} IPs using ipinfo.io, vpnapi.io, AbuseIPDB, Shodan...\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(enrich_single_ip, ip, config): ip for ip in ip_list}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                
                # Show inline status
                flags = []
                if result['is_vpn'] or result['vpnapi_security_vpn']:
                    flags.append("VPN")
                if result['is_proxy'] or result['vpnapi_security_proxy']:
                    flags.append("Proxy")
                if result['is_tor'] or result['vpnapi_security_tor']:
                    flags.append("Tor")
                if result['vpnapi_security_relay']:
                    flags.append("Relay")
                if result['abuse_confidence_score'] > 0:
                    flags.append(f"Abuse:{result['abuse_confidence_score']}%")
                if result['shodan_ports']:
                    flags.append(f"Ports:{len(result['shodan_ports'])}")
                if result['shodan_vulns']:
                    flags.append(f"CVEs:{len(result['shodan_vulns'])}")
                
                flag_str = f"[{', '.join(flags)}]" if flags else "[Clean]"
                print(f"  OK {ip:<17} {flag_str}")
            except Exception as e:
                print(f"  FAIL {ip} - {str(e)}")
    
    return sorted(results, key=lambda x: x['ip'])


def print_detailed_results(results: list[dict]):
    """Print detailed enrichment results table"""
    print(f"\n{'='*130}")
    print(f"Detailed Results ({len(results)} IPs):\n")
    print(f"{'IP Address':<17} | {'City':<20} | {'Country':<3} | {'ISP/Org':<30} | {'Flags':<45}")
    print(f"{'-'*130}")
    
    for item in results:
        flags = []
        if item['is_vpn']:
            flags.append("ipinfo:VPN")
        if item['vpnapi_security_vpn']:
            flags.append("vpnapi:VPN")
        if item['is_proxy']:
            flags.append("ipinfo:Proxy")
        if item['vpnapi_security_proxy']:
            flags.append("vpnapi:Proxy")
        if item['is_tor']:
            flags.append("ipinfo:Tor")
        if item['vpnapi_security_tor']:
            flags.append("vpnapi:Tor")
        if item['vpnapi_security_relay']:
            flags.append("vpnapi:Relay")
        if item['abuse_confidence_score'] > 0:
            flags.append(f"Abuse:{item['abuse_confidence_score']}%")
        if item['total_reports'] > 0:
            flags.append(f"Reports:{item['total_reports']}")
        if item['is_whitelisted']:
            flags.append("Whitelisted")
        if item['shodan_ports']:
            flags.append(f"Ports:{','.join(str(p) for p in item['shodan_ports'][:5])}")
        if item['shodan_vulns']:
            flags.append(f"CVEs:{','.join(item['shodan_vulns'][:3])}")
        if item['shodan_tags']:
            flags.append(f"Tags:{','.join(item['shodan_tags'][:3])}")
        
        flag_str = ", ".join(flags) if flags else "Clean"
        print(f"{item['ip']:<17} | {item['city']:<20} | {item['country']:<3} | {item['org'][:30]:<30} | {flag_str}")


def print_summary(results: list[dict]):
    """Print summary statistics"""
    print(f"\n{'='*130}")
    print("Summary Statistics:\n")
    print("  ipinfo.io Detection:")
    print(f"    VPN IPs: {sum(1 for x in results if x['is_vpn'])}")
    print(f"    Proxy IPs: {sum(1 for x in results if x['is_proxy'])}")
    print(f"    Tor IPs: {sum(1 for x in results if x['is_tor'])}")
    print(f"    Hosting IPs: {sum(1 for x in results if x['is_hosting'])}")
    print("\n  vpnapi.io Detection:")
    print(f"    VPN IPs: {sum(1 for x in results if x['vpnapi_security_vpn'])}")
    print(f"    Proxy IPs: {sum(1 for x in results if x['vpnapi_security_proxy'])}")
    print(f"    Tor IPs: {sum(1 for x in results if x['vpnapi_security_tor'])}")
    print(f"    Relay IPs: {sum(1 for x in results if x['vpnapi_security_relay'])}")
    print("\n  AbuseIPDB Detection:")
    print(f"    IPs with reports: {sum(1 for x in results if x['total_reports'] > 0)}")
    print(f"    High confidence (>75%): {sum(1 for x in results if x['abuse_confidence_score'] > 75)}")
    print(f"    Medium confidence (25-75%): {sum(1 for x in results if 25 <= x['abuse_confidence_score'] <= 75)}")
    print(f"    Whitelisted: {sum(1 for x in results if x['is_whitelisted'])}")
    print("\n  Shodan Detection:")
    print(f"    IPs with open ports: {sum(1 for x in results if x['shodan_ports'])}")
    print(f"    IPs with CVEs: {sum(1 for x in results if x['shodan_vulns'])}")
    all_ports = [p for x in results for p in (x['shodan_ports'] or [])]
    if all_ports:
        from collections import Counter
        top_ports = Counter(all_ports).most_common(5)
        print(f"    Top ports: {', '.join(f'{p}(x{c})' for p, c in top_ports)}")
    all_vulns = [v for x in results for v in (x['shodan_vulns'] or [])]
    if all_vulns:
        print(f"    Total unique CVEs: {len(set(all_vulns))}")
    print("\n  Overall:")
    print(f"    Clean residential IPs: {sum(1 for x in results if not any([x['is_vpn'], x['vpnapi_security_vpn'], x['is_proxy'], x['vpnapi_security_proxy'], x['is_tor'], x['vpnapi_security_tor'], x['abuse_confidence_score'] > 0]))}")


def extract_ips_from_investigation(json_path: str) -> list[str]:
    """Extract unenriched IPs from an investigation JSON file"""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # Get already enriched IPs
    enriched_ips = {item['ip'] for item in data.get('ip_enrichment', [])}
    
    # Extract all IPv4 addresses from signin data
    all_ips = set()
    for app in data.get('signin_apps', []):
        for ip in app.get('IPAddresses', []):
            if ':' not in ip:  # Skip IPv6
                all_ips.add(ip)
    
    for loc in data.get('signin_locations', []):
        for ip in loc.get('IPAddresses', []):
            if ':' not in ip:  # Skip IPv6
                all_ips.add(ip)
    
    # Return unenriched IPs
    return sorted(all_ips - enriched_ips)


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python enrich_ips.py <ip1> <ip2> <ip3> ...")
        print("  python enrich_ips.py --file investigation.json")
        print("\nExamples:")
        print("  python enrich_ips.py 203.0.113.42 198.51.100.10")
        print("  python enrich_ips.py --file temp/investigation_user_20251130.json")
        sys.exit(1)
    
    # Parse arguments
    if sys.argv[1] == '--file':
        if len(sys.argv) < 3:
            print("Error: --file requires a path to investigation JSON")
            sys.exit(1)
        ip_list = extract_ips_from_investigation(sys.argv[2])
        if not ip_list:
            print("No unenriched IPs found in investigation file")
            sys.exit(0)
    else:
        ip_list = sys.argv[1:]
    
    # Enrich IPs
    results = enrich_ips(ip_list)
    
    # Display results
    print_detailed_results(results)
    print_summary(results)
    
    # Optionally save to JSON
    config = load_config()
    output_dir = config.get('settings', {}).get('output_dir', 'temp')
    output_file = Path(output_dir) / f'ip_enrichment_{len(results)}_ips.json'
    output_file.parent.mkdir(exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")


if __name__ == '__main__':
    main()
