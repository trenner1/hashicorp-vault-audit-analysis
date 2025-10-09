#!/usr/bin/env python3
"""
Compare KV usage across multiple mounts.

This script reads the KV usage CSV files from the data/ directory and generates
a comparison report showing operations, paths, and unique entities per mount.
"""

import csv
import sys
import os

def analyze_mount(csvfile):
    """Analyze a single KV mount CSV file."""
    if not os.path.exists(csvfile):
        return None
    
    try:
        with open(csvfile, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            if not rows:
                return {"operations": 0, "paths": 0, "entities": set()}
            
            operations = sum(int(row['operations_count']) for row in rows)
            paths = len(rows)
            entities = set()
            
            for row in rows:
                if row['entity_ids']:
                    entities.update(eid.strip() for eid in row['entity_ids'].split(','))
            
            return {
                "operations": operations,
                "paths": paths,
                "entities": entities
            }
    except Exception as e:
        print(f"Error reading {csvfile}: {e}", file=sys.stderr)
        return None

def main():
    # Define mounts to analyze
    mounts = {
        "appcodes": "data/kv_usage_oct7_appcodes.csv",
        "compute-fabric": "data/kv_usage_oct7_compute-fabric.csv",
        "github": "data/kv_usage_oct7_github.csv",
        "ansible": "data/kv_usage_oct7_ansible.csv",
        "github-cnb": "data/kv_usage_oct7_github-cnb.csv",
        "ansible-cnb": "data/kv_usage_oct7_ansible-cnb.csv",
    }
    
    print("=" * 95)
    print(f"{'KV Mount':<20} {'Operations':<18} {'Unique Paths':<18} {'Unique Entities':<20}")
    print("=" * 95)
    
    results = {}
    total_ops = 0
    total_paths = 0
    all_entities = set()
    
    # Sort by mount name for consistent output
    for mount in sorted(mounts.keys()):
        csvfile = mounts[mount]
        result = analyze_mount(csvfile)
        
        if result is None:
            print(f"{mount:<20} {'(file not found)':<18}")
            continue
        
        results[mount] = result
        
        print(f"{mount:<20} {result['operations']:<18,} {result['paths']:<18,} {len(result['entities']):<20,}")
        
        total_ops += result['operations']
        total_paths += result['paths']
        all_entities.update(result['entities'])
    
    print("=" * 95)
    print(f"{'TOTAL':<20} {total_ops:<18,} {total_paths:<18,} {len(all_entities):<20,}")
    print("=" * 95)
    
    # Show percentage breakdown
    if results:
        print("\nPercentage Breakdown by Operations:")
        print("-" * 50)
        for mount in sorted(results.keys(), key=lambda m: results[m]['operations'], reverse=True):
            pct = (results[mount]['operations'] / total_ops * 100) if total_ops > 0 else 0
            print(f"{mount:<20} {pct:>6.2f}%")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
