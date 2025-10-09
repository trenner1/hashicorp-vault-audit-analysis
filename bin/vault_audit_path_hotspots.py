#!/usr/bin/env python3
"""
Analyze path-specific hot spots from Vault audit logs.

This script identifies the most-accessed paths across ALL mount types
and provides optimization recommendations for each.
"""

import json
import argparse
from collections import defaultdict
from datetime import datetime

def parse_timestamp(ts_str: str):
    """Parse Vault audit log timestamp."""
    try:
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except:
        return None

def analyze_path_hotspots(log_file: str, top_n: int = 50):
    """Analyze top N most-accessed paths."""
    
    # Data structures
    path_stats = defaultdict(lambda: {
        'operations': 0,
        'entities': set(),
        'operations_by_type': defaultdict(int),
        'timestamps': [],
        'entity_operations': defaultdict(int)
    })
    
    total_lines = 0
    total_operations = 0
    
    print(f"Analyzing path hot spots in {log_file}...")
    
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 500000 == 0:
                print(f"  Processed {total_lines:,} lines...")
            
            try:
                entry = json.loads(line.strip())
                
                # Extract fields
                request = entry.get('request', {})
                path = request.get('path', '')
                operation = request.get('operation', '')
                timestamp = entry.get('time', '')
                
                if not path:
                    continue
                
                total_operations += 1
                
                # Get entity info
                auth = entry.get('auth', {})
                entity_id = auth.get('entity_id', 'no-entity')
                
                ts = parse_timestamp(timestamp)
                
                # Track path statistics
                path_stats[path]['operations'] += 1
                path_stats[path]['entities'].add(entity_id)
                path_stats[path]['operations_by_type'][operation] += 1
                path_stats[path]['entity_operations'][entity_id] += 1
                if ts:
                    path_stats[path]['timestamps'].append(ts)
                
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
    
    print(f"\nProcessed {total_lines:,} total lines")
    print(f"Found {total_operations:,} operations across {len(path_stats):,} unique paths")
    
    # Sort paths by operation count
    sorted_paths = sorted(path_stats.items(), key=lambda x: x[1]['operations'], reverse=True)
    
    # Analysis and reporting
    print("\n" + "=" * 120)
    print(f"TOP {top_n} PATH HOT SPOTS ANALYSIS")
    print("=" * 120)
    
    # 1. Summary table
    print(f"\n{'#':<5} {'Path':<60} {'Ops':<12} {'Entities':<10} {'Top Op':<10} {'%':<10}")
    print("-" * 120)
    
    for i, (path, data) in enumerate(sorted_paths[:top_n], 1):
        ops = data['operations']
        entity_count = len(data['entities'])
        percentage = (ops / total_operations) * 100
        
        # Top operation type
        top_op = max(data['operations_by_type'].items(), key=lambda x: x[1])[0] if data['operations_by_type'] else 'N/A'
        
        # Truncate path
        display_path = path if len(path) <= 58 else path[:55] + "..."
        
        print(f"{i:<5} {display_path:<60} {ops:<12,} {entity_count:<10,} {top_op:<10} {percentage:<10.2f}%")
    
    # 2. Detailed analysis for top paths
    print(f"\n\nDETAILED ANALYSIS OF TOP {min(20, top_n)} PATHS")
    print("=" * 120)
    
    for i, (path, data) in enumerate(sorted_paths[:min(20, top_n)], 1):
        print(f"\n{i}. PATH: {path}")
        print("-" * 120)
        
        ops = data['operations']
        entity_count = len(data['entities'])
        percentage = (ops / total_operations) * 100
        
        print(f"   Total Operations: {ops:,} ({percentage:.2f}% of all traffic)")
        print(f"   Unique Entities: {entity_count:,}")
        
        # Calculate time span and rate
        if len(data['timestamps']) >= 2:
            timestamps = sorted(data['timestamps'])
            time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
            if time_span > 0:
                ops_per_hour = ops / time_span
                print(f"   Access Rate: {ops_per_hour:.1f} operations/hour ({ops_per_hour/60:.2f}/minute)")
        
        # Operation breakdown
        print("   Operations by type:")
        for op, count in sorted(data['operations_by_type'].items(), key=lambda x: x[1], reverse=True)[:5]:
            op_pct = (count / ops) * 100
            print(f"      - {op}: {count:,} ({op_pct:.1f}%)")
        
        # Top entities
        top_entities = sorted(data['entity_operations'].items(), key=lambda x: x[1], reverse=True)[:5]
        if top_entities:
            print(f"   Top {len(top_entities)} entities:")
            for entity_id, entity_ops in top_entities:
                entity_pct = (entity_ops / ops) * 100
                entity_display = entity_id if len(entity_id) <= 40 else entity_id[:37] + "..."
                print(f"      - {entity_display}: {entity_ops:,} ops ({entity_pct:.1f}%)")
        
        # Categorize and provide recommendations
        print("   Category: ", end="")
        recommendations = []
        
        if 'token/lookup' in path:
            print("TOKEN LOOKUP")
            recommendations.append("Implement client-side token TTL tracking to eliminate polling")
            recommendations.append(f"Potential reduction: 80-90% ({int(ops * 0.85):,} operations)")
        elif 'airflow' in path.lower():
            print("AIRFLOW SECRET")
            recommendations.append("Deploy Vault agent with template rendering for Airflow")
            recommendations.append("Configure connection caching in Airflow")
            recommendations.append(f"Potential reduction: 95% ({int(ops * 0.95):,} operations)")
        elif 'approle/login' in path:
            print("APPROLE AUTHENTICATION")
            if entity_count == 1:
                recommendations.append(f"⚠️  CRITICAL: Single entity making all {ops:,} login requests")
                recommendations.append("Review token TTL configuration - may be too short")
                recommendations.append("Consider SecretID caching if appropriate")
        elif 'openshift' in path.lower() or 'kubernetes' in path.lower():
            print("KUBERNETES/OPENSHIFT AUTH")
            recommendations.append("Review pod authentication token TTLs")
            recommendations.append("Consider increasing default token lifetime")
            recommendations.append("Implement token renewal strategy in applications")
        elif 'github' in path.lower() and 'login' in path:
            print("GITHUB AUTHENTICATION")
            recommendations.append("Review GitHub auth token TTLs")
            if entity_count == 1:
                recommendations.append(f"⚠️  Single entity ({entity_count}) - investigate why")
        elif 'data/' in path or 'metadata/' in path:
            print("KV SECRET ENGINE")
            if entity_count <= 3 and ops > 10000:
                recommendations.append(f"⚠️  HIGH-FREQUENCY ACCESS: {ops:,} operations from only {entity_count} entities")
                recommendations.append("Implement caching layer or Vault agent")
                recommendations.append("Review if secret needs this frequency of access")
            else:
                recommendations.append("Consider Vault agent for high-frequency consumers")
        else:
            print("OTHER")
            if ops > 5000:
                recommendations.append(f"High-volume path ({ops:,} operations) - review necessity")
        
        # Entity concentration check
        if top_entities and top_entities[0][1] / ops > 0.5:
            top_entity_pct = (top_entities[0][1] / ops) * 100
            if "CRITICAL" not in str(recommendations):
                recommendations.append(f"⚠️  Entity concentration: Single entity responsible for {top_entity_pct:.1f}% of access")
        
        if recommendations:
            print("   Recommendations:")
            for rec in recommendations:
                print(f"      • {rec}")
    
    # 3. Summary by category
    print("\n\nSUMMARY BY PATH CATEGORY")
    print("=" * 120)
    
    categories = {
        'Token Operations': 0,
        'KV Secret Access': 0,
        'Authentication': 0,
        'Airflow Secrets': 0,
        'System/Admin': 0,
        'Other': 0
    }
    
    for path, data in path_stats.items():
        ops = data['operations']
        if 'token/' in path:
            categories['Token Operations'] += ops
        elif '/data/' in path or '/metadata/' in path:
            if 'airflow' in path.lower():
                categories['Airflow Secrets'] += ops
            else:
                categories['KV Secret Access'] += ops
        elif '/login' in path or '/auth/' in path:
            categories['Authentication'] += ops
        elif 'sys/' in path:
            categories['System/Admin'] += ops
        else:
            categories['Other'] += ops
    
    print(f"{'Category':<30} {'Operations':<15} {'% of Total':<15}")
    print("-" * 120)
    
    for category, ops in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        percentage = (ops / total_operations) * 100
        print(f"{category:<30} {ops:<15,} {percentage:<15.2f}%")
    
    print("\n" + "=" * 120)
    
    # 4. Overall recommendations
    print("\nTOP OPTIMIZATION OPPORTUNITIES (by impact)")
    print("=" * 120)
    
    opportunities = []
    
    # Calculate token lookup impact
    token_lookup_ops = sum(data['operations'] for path, data in path_stats.items() if 'token/lookup' in path)
    if token_lookup_ops > 10000:
        opportunities.append({
            'name': 'Eliminate Token Lookup Polling',
            'current_ops': token_lookup_ops,
            'potential_reduction': int(token_lookup_ops * 0.85),
            'effort': 'Medium',
            'priority': 1
        })
    
    # Calculate Airflow impact
    airflow_ops = sum(data['operations'] for path, data in path_stats.items() if 'airflow' in path.lower())
    if airflow_ops > 10000:
        opportunities.append({
            'name': 'Deploy Vault Agent for Airflow',
            'current_ops': airflow_ops,
            'potential_reduction': int(airflow_ops * 0.95),
            'effort': 'Medium',
            'priority': 2
        })
    
    # Calculate high-frequency single-entity paths
    high_freq_single = []
    for path, data in sorted_paths[:100]:
        if len(data['entities']) <= 3 and data['operations'] > 10000:
            high_freq_single.append((path, data['operations']))
    
    if high_freq_single:
        total_hf_ops = sum(ops for _, ops in high_freq_single)
        opportunities.append({
            'name': f'Cache High-Frequency Paths ({len(high_freq_single)} paths)',
            'current_ops': total_hf_ops,
            'potential_reduction': int(total_hf_ops * 0.7),
            'effort': 'Low-Medium',
            'priority': 3
        })
    
    # Sort and display
    opportunities.sort(key=lambda x: x['potential_reduction'], reverse=True)
    
    print(f"\n{'Priority':<10} {'Opportunity':<50} {'Current Ops':<15} {'Savings':<15} {'Effort':<15}")
    print("-" * 120)
    
    for opp in opportunities:
        print(f"{opp['priority']:<10} {opp['name']:<50} {opp['current_ops']:<15,} {opp['potential_reduction']:<15,} {opp['effort']:<15}")
    
    total_potential_savings = sum(opp['potential_reduction'] for opp in opportunities)
    current_total_ops = sum(opp['current_ops'] for opp in opportunities)
    
    print("-" * 120)
    print(f"{'TOTAL POTENTIAL SAVINGS':<60} {current_total_ops:<15,} {total_potential_savings:<15,}")
    print(f"\nProjected reduction: {(total_potential_savings/total_operations)*100:.1f}% of all Vault operations")
    print("=" * 120)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze path-specific hot spots from Vault audit logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python vault_audit_path_hotspots.py vault_audit.log 50
        '''
    )
    parser.add_argument('audit_log', help='Path to Vault audit log file')
    parser.add_argument('top_n', nargs='?', type=int, default=50,
                       help='Number of top paths to analyze (default: 50)')
    
    args = parser.parse_args()
    analyze_path_hotspots(args.audit_log, args.top_n)
