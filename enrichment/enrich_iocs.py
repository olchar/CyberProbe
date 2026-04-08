"""
IOC Enrichment Utility - Domains and File Hashes

Enriches domains and file hashes using VirusTotal API.

Usage:
    python enrich_iocs.py --domain malicious-code-repo.org
    python enrich_iocs.py --hash d97e1c9dea13f7a213e8c2687bf2f0c162a48657fd3d494112e370d6d71a893c
"""

import json
import sys
import requests
import argparse
from pathlib import Path
from datetime import datetime


def load_config() -> dict:
    """Load API tokens from config.json"""
    config_path = Path(__file__).parent / 'config.json'
    with open(config_path, 'r') as f:
        return json.load(f)


def enrich_domain(domain: str, vt_api_key: str) -> dict:
    """Enrich a domain using VirusTotal"""
    result = {
        'domain': domain,
        'enrichment_time': datetime.utcnow().isoformat(),
        'source': 'VirusTotal',
        'malicious_votes': 0,
        'suspicious_votes': 0,
        'harmless_votes': 0,
        'undetected_votes': 0,
        'last_analysis_stats': {},
        'categories': {},
        'reputation': 0,
        'error': None
    }
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': vt_api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            
            # Last analysis stats
            stats = attributes.get('last_analysis_stats', {})
            result['malicious_votes'] = stats.get('malicious', 0)
            result['suspicious_votes'] = stats.get('suspicious', 0)
            result['harmless_votes'] = stats.get('harmless', 0)
            result['undetected_votes'] = stats.get('undetected', 0)
            result['last_analysis_stats'] = stats
            
            # Categories
            result['categories'] = attributes.get('categories', {})
            
            # Reputation
            result['reputation'] = attributes.get('reputation', 0)
            
            # Get voting info
            last_analysis_results = attributes.get('last_analysis_results', {})
            result['detection_engines'] = len(last_analysis_results)
            
            # List detections
            detections = []
            for engine, analysis in last_analysis_results.items():
                if analysis.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': analysis.get('category'),
                        'result': analysis.get('result')
                    })
            result['detections'] = detections[:10]  # Top 10
            
        elif response.status_code == 404:
            result['error'] = 'Domain not found in VirusTotal database'
        elif response.status_code == 401:
            result['error'] = 'Invalid API key'
        else:
            result['error'] = f'HTTP {response.status_code}: {response.text}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def enrich_file_hash(file_hash: str, vt_api_key: str) -> dict:
    """Enrich a file hash using VirusTotal"""
    result = {
        'hash': file_hash,
        'enrichment_time': datetime.utcnow().isoformat(),
        'source': 'VirusTotal',
        'malicious_votes': 0,
        'suspicious_votes': 0,
        'harmless_votes': 0,
        'undetected_votes': 0,
        'file_name': None,
        'file_type': None,
        'file_size': None,
        'reputation': 0,
        'error': None
    }
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {'x-apikey': vt_api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            
            # Last analysis stats
            stats = attributes.get('last_analysis_stats', {})
            result['malicious_votes'] = stats.get('malicious', 0)
            result['suspicious_votes'] = stats.get('suspicious', 0)
            result['harmless_votes'] = stats.get('harmless', 0)
            result['undetected_votes'] = stats.get('undetected', 0)
            result['last_analysis_stats'] = stats
            
            # File info
            result['file_name'] = attributes.get('meaningful_name') or attributes.get('names', ['Unknown'])[0] if attributes.get('names') else 'Unknown'
            result['file_type'] = attributes.get('type_description', 'Unknown')
            result['file_size'] = attributes.get('size', 0)
            result['reputation'] = attributes.get('reputation', 0)
            
            # Get voting info
            last_analysis_results = attributes.get('last_analysis_results', {})
            result['detection_engines'] = len(last_analysis_results)
            
            # List detections
            detections = []
            for engine, analysis in last_analysis_results.items():
                if analysis.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': analysis.get('category'),
                        'result': analysis.get('result')
                    })
            result['detections'] = detections[:10]  # Top 10
            
        elif response.status_code == 404:
            result['error'] = 'File hash not found in VirusTotal database'
        elif response.status_code == 401:
            result['error'] = 'Invalid API key'
        else:
            result['error'] = f'HTTP {response.status_code}: {response.text}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def main():
    parser = argparse.ArgumentParser(description='Enrich IOCs using VirusTotal')
    parser.add_argument('--domain', help='Domain to enrich')
    parser.add_argument('--hash', help='File hash to enrich')
    args = parser.parse_args()
    
    if not args.domain and not args.hash:
        parser.print_help()
        sys.exit(1)
    
    config = load_config()
    vt_api_key = config.get('api_keys', {}).get('virustotal')
    
    if not vt_api_key:
        print("Error: VirusTotal API key not found in config.json")
        sys.exit(1)
    
    results = []
    
    if args.domain:
        print(f"\n[+] Enriching domain: {args.domain}")
        result = enrich_domain(args.domain, vt_api_key)
        results.append(result)
        
        if result['error']:
            print(f"    Error: {result['error']}")
        else:
            print(f"    Malicious: {result['malicious_votes']}")
            print(f"    Suspicious: {result['suspicious_votes']}")
            print(f"    Harmless: {result['harmless_votes']}")
            print(f"    Reputation: {result['reputation']}")
            if result.get('detections'):
                print(f"    Top Detections:")
                for det in result['detections'][:5]:
                    print(f"      - {det['engine']}: {det['result']}")
    
    if args.hash:
        print(f"\n[+] Enriching file hash: {args.hash}")
        result = enrich_file_hash(args.hash, vt_api_key)
        results.append(result)
        
        if result['error']:
            print(f"    Error: {result['error']}")
        else:
            print(f"    File: {result['file_name']}")
            print(f"    Type: {result['file_type']}")
            print(f"    Size: {result['file_size']} bytes")
            print(f"    Malicious: {result['malicious_votes']}")
            print(f"    Suspicious: {result['suspicious_votes']}")
            print(f"    Harmless: {result['harmless_votes']}")
            if result.get('detections'):
                print(f"    Top Detections:")
                for det in result['detections'][:5]:
                    print(f"      - {det['engine']}: {det['result']}")
    
    # Save to file
    output_file = Path(__file__).parent.parent / 'reports' / f'ioc_enrichment_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Results saved to: {output_file}")


if __name__ == '__main__':
    main()
