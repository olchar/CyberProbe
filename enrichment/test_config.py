#!/usr/bin/env python3
"""
Test and validate the enrichment config.json file
"""
import json
from pathlib import Path

def test_config():
    config_file = Path(__file__).parent / 'config.json'
    
    print("=" * 60)
    print("CyberProbe Config Validation Test")
    print("=" * 60)
    print()
    
    # Load and validate JSON
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print("✓ JSON is valid and properly formatted")
    except json.JSONDecodeError as e:
        print(f"✗ JSON parsing error: {e}")
        return
    except Exception as e:
        print(f"✗ Error reading file: {e}")
        return
    
    print()
    print("=" * 60)
    print("ACTIVE API KEYS")
    print("=" * 60)
    
    active_keys = [k for k in data['api_keys'].keys() if not k.startswith('_')]
    print(f"Total: {len(active_keys)} configured sources")
    print()
    
    for i, key in enumerate(active_keys, 1):
        value = data['api_keys'][key]
        # Check if it's a real key or placeholder
        if 'YOUR_' in value or value == 'NO_KEY_NEEDED':
            status = "⚠ PLACEHOLDER"
        else:
            status = "✓ CONFIGURED"
        print(f"  {i}. {key:20} {status}")
    
    print()
    print("=" * 60)
    print("FREE SOURCES TO ADD (Recommended)")
    print("=" * 60)
    
    free_sources = []
    for k, v in data['api_keys'].items():
        if k.startswith('_') and not k.startswith('_comment'):
            free_sources.append((k.lstrip('_'), v))
    
    print(f"Total: {len(free_sources)} additional sources available")
    print()
    
    for i, (key, value) in enumerate(free_sources, 1):
        if value == 'NO_KEY_NEEDED':
            print(f"  {i}. {key:25} [FREE - No API key required]")
        else:
            print(f"  {i}. {key:25} [FREE - API key required]")
    
    print()
    print("=" * 60)
    print("SETTINGS")
    print("=" * 60)
    
    settings = data['settings']
    print(f"  Timeout:        {settings.get('timeout', 'N/A')} seconds")
    print(f"  Max Retries:    {settings.get('max_retries', 'N/A')}")
    print(f"  Cache Enabled:  {settings.get('cache_enabled', 'N/A')}")
    print(f"  Cache TTL:      {settings.get('cache_ttl_hours', 'N/A')} hours")
    print(f"  Output Dir:     {settings.get('output_dir', 'N/A')}")
    
    if 'enabled_sources' in settings:
        print(f"  Enabled Count:  {len(settings['enabled_sources'])}")
    
    print()
    print("=" * 60)
    print("RISK SCORING WEIGHTS")
    print("=" * 60)
    
    if '_risk_scoring_weights' in settings:
        weights = settings['_risk_scoring_weights']
        total_weight = sum([v for k, v in weights.items() if not k.startswith('_')])
        
        for k, v in weights.items():
            if not k.startswith('_'):
                percentage = int(v * 100)
                print(f"  {k:20} {v:.2f} ({percentage}%)")
        
        print()
        print(f"  Total Weight: {total_weight:.2f} ", end="")
        if total_weight == 1.0:
            print("✓ Valid")
        else:
            print(f"⚠ Warning: Should equal 1.0")
    
    print()
    print("=" * 60)
    print("WORKSPACE CONFIGURATION")
    print("=" * 60)
    print(f"  Sentinel Workspace ID: {data.get('sentinel_workspace_id', 'N/A')}")
    print(f"  Tenant ID:             {data.get('tenant_id', 'N/A')}")
    
    print()
    print("=" * 60)
    print("✓ Configuration file is ready to use!")
    print("=" * 60)

if __name__ == '__main__':
    test_config()
