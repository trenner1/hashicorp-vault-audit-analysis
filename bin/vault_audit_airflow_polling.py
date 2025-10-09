#!/usr/bin/env python3
"""
Analyze Airflow secret polling patterns from Vault audit logs.

This script identifies all Airflow-related secret access patterns, including:
- All Airflow connection paths and their read frequencies
- Entity patterns accessing Airflow secrets
- Time-based access patterns to detect polling behavior
- Recommendations for optimization
"""

import json
import argparse
from collections import defaultdict
from datetime import datetime

def parse_timestamp(ts_str: str) -> datetime:
    """Parse Vault audit log timestamp."""
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        return None

def analyze_airflow_patterns(log_file: str):
    """Analyze Airflow secret access patterns."""
    
    # Data structures
    airflow_paths = defaultdict(lambda: {
        'operations': 0,
        'entities': set(),
        'timestamps': [],
        'operations_by_entity': defaultdict(int)
    })
    
    entity_patterns = defaultdict(lambda: {
        'paths_accessed': set(),
        'total_operations': 0,
        'timestamps': []
    })
    
    total_lines = 0
    airflow_operations = 0
    
    print(f"Analyzing Airflow patterns in {log_file}...")
    
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 500000 == 0:
                print(f"  Processed {total_lines:,} lines, found {airflow_operations:,} Airflow operations...")
            
            try:
                entry = json.loads(line.strip())
                
                # Extract fields
                request = entry.get('request', {})
                path = request.get('path', '')
                
                # Check if this is an Airflow-related path
                # Looking for patterns like: */Airflow* or */airflow*
                if 'airflow' not in path.lower():
                    continue
                
                airflow_operations += 1
                
                # Get entity info
                auth = entry.get('auth', {})
                entity_id = auth.get('entity_id', 'no-entity')
                
                # Get timestamp
                timestamp = entry.get('time', '')
                ts = parse_timestamp(timestamp)
                
                # Track path statistics
                airflow_paths[path]['operations'] += 1
                airflow_paths[path]['entities'].add(entity_id)
                airflow_paths[path]['operations_by_entity'][entity_id] += 1
                if ts:
                    airflow_paths[path]['timestamps'].append(ts)
                
                # Track entity patterns
                entity_patterns[entity_id]['paths_accessed'].add(path)
                entity_patterns[entity_id]['total_operations'] += 1
                if ts:
                    entity_patterns[entity_id]['timestamps'].append(ts)
                
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
    
    print(f"\nProcessed {total_lines:,} total lines")
    print(f"Found {airflow_operations:,} Airflow-related operations")
    
    # Analysis and reporting
    print("\n" + "=" * 100)
    print("AIRFLOW SECRET ACCESS ANALYSIS")
    print("=" * 100)
    
    # 1. Top Airflow paths by operations
    print("\n1. TOP AIRFLOW PATHS BY OPERATIONS")
    print("-" * 100)
    print(f"{'Path':<80} {'Operations':<12} {'Entities':<10}")
    print("-" * 100)
    
    sorted_paths = sorted(airflow_paths.items(), key=lambda x: x[1]['operations'], reverse=True)
    
    total_airflow_ops = 0
    for path, data in sorted_paths[:30]:
        ops = data['operations']
        entity_count = len(data['entities'])
        total_airflow_ops += ops
        
        # Truncate path if too long
        display_path = path if len(path) <= 78 else path[:75] + "..."
        print(f"{display_path:<80} {ops:<12,} {entity_count:<10,}")
    
    print("-" * 100)
    print(f"{'TOTAL AIRFLOW OPERATIONS':<80} {total_airflow_ops:<12,}")
    print("-" * 100)
    
    # 2. Entity access patterns
    print("\n2. ENTITIES ACCESSING AIRFLOW SECRETS")
    print("-" * 100)
    print(f"{'Entity ID':<50} {'Operations':<12} {'Unique Paths':<15}")
    print("-" * 100)
    
    sorted_entities = sorted(entity_patterns.items(), 
                           key=lambda x: x[1]['total_operations'], 
                           reverse=True)
    
    for entity_id, data in sorted_entities[:20]:
        ops = data['total_operations']
        path_count = len(data['paths_accessed'])
        
        display_entity = entity_id if len(entity_id) <= 48 else entity_id[:45] + "..."
        print(f"{display_entity:<50} {ops:<12,} {path_count:<15,}")
    
    # 3. Polling pattern analysis
    print("\n3. POLLING PATTERN ANALYSIS (Paths with Time Data)")
    print("-" * 100)
    print(f"{'Path':<60} {'Operations':<12} {'Time Span':<12} {'Avg Interval':<15}")
    print("-" * 100)
    
    polling_patterns = []
    
    for path, data in sorted_paths:
        if len(data['timestamps']) < 2:
            continue
        
        timestamps = sorted(data['timestamps'])
        time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600  # hours
        
        if time_span > 0:
            ops_per_hour = data['operations'] / time_span
            avg_interval_seconds = (time_span * 3600) / data['operations']
            
            polling_patterns.append({
                'path': path,
                'operations': data['operations'],
                'time_span_hours': time_span,
                'ops_per_hour': ops_per_hour,
                'avg_interval_seconds': avg_interval_seconds,
                'entities': len(data['entities'])
            })
    
    # Sort by operations per hour (highest polling rate)
    polling_patterns.sort(key=lambda x: x['ops_per_hour'], reverse=True)
    
    for pattern in polling_patterns[:25]:
        path_display = pattern['path'] if len(pattern['path']) <= 58 else pattern['path'][:55] + "..."
        time_span = f"{pattern['time_span_hours']:.1f}h"
        interval = f"{pattern['avg_interval_seconds']:.1f}s"
        
        print(f"{path_display:<60} {pattern['operations']:<12,} {time_span:<12} {interval:<15}")
    
    # 4. Entity-path combinations (who's polling what)
    print("\n4. ENTITY-PATH POLLING BEHAVIOR (Top 30)")
    print("-" * 100)
    print(f"{'Entity':<40} {'Path':<45} {'Operations':<15}")
    print("-" * 100)
    
    entity_path_combos = []
    
    for path, data in airflow_paths.items():
        for entity_id, ops in data['operations_by_entity'].items():
            entity_path_combos.append({
                'entity': entity_id,
                'path': path,
                'operations': ops
            })
    
    entity_path_combos.sort(key=lambda x: x['operations'], reverse=True)
    
    for combo in entity_path_combos[:30]:
        entity_display = combo['entity'] if len(combo['entity']) <= 38 else combo['entity'][:35] + "..."
        path_display = combo['path'] if len(combo['path']) <= 43 else combo['path'][:40] + "..."
        
        print(f"{entity_display:<40} {path_display:<45} {combo['operations']:<15,}")
    
    # 5. Recommendations
    print("\n5. OPTIMIZATION RECOMMENDATIONS")
    print("-" * 100)
    
    # Calculate potential savings
    high_frequency_paths = [p for p in polling_patterns if p['ops_per_hour'] > 100]
    total_high_freq_ops = sum(p['operations'] for p in high_frequency_paths)
    
    print(f"Total Airflow operations: {total_airflow_ops:,}")
    print(f"Paths with >100 ops/hour: {len(high_frequency_paths)}")
    print(f"Operations from high-frequency paths: {total_high_freq_ops:,} ({total_high_freq_ops/total_airflow_ops*100:.1f}%)")
    print()
    print("Recommended Actions:")
    print()
    print("1. IMPLEMENT AIRFLOW CONNECTION CACHING")
    print("   - Configure Airflow to cache connection objects")
    print("   - Expected reduction: 80-90% of reads")
    print(f"   - Potential savings: {int(total_airflow_ops * 0.85):,} operations/day")
    print()
    print("2. DEPLOY VAULT AGENT WITH AIRFLOW")
    print("   - Run Vault agent as sidecar/daemon")
    print("   - Configure template rendering for connections")
    print("   - Expected reduction: 95% of reads")
    print(f"   - Potential savings: {int(total_airflow_ops * 0.95):,} operations/day")
    print()
    print("3. USE AIRFLOW SECRETS BACKEND EFFICIENTLY")
    print("   - Review connection lookup patterns in DAGs")
    print("   - Implement connection object reuse within tasks")
    print("   - Cache connections at DAG level where appropriate")
    print()
    
    # Identify specific paths for immediate attention
    critical_paths = [p for p in polling_patterns[:10]]
    if critical_paths:
        print("4. PRIORITY PATHS FOR IMMEDIATE OPTIMIZATION:")
        for i, p in enumerate(critical_paths, 1):
            path_name = p['path'].split('/')[-1] if '/' in p['path'] else p['path']
            print(f"   {i}. {path_name}: {p['operations']:,} operations ({p['ops_per_hour']:.0f}/hour)")
    
    print("\n" + "=" * 100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze Airflow secret polling patterns from Vault audit logs'
    )
    parser.add_argument('audit_log', help='Path to Vault audit log file')
    
    args = parser.parse_args()
    analyze_airflow_patterns(args.audit_log)
