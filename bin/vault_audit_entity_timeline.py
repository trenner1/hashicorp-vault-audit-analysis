#!/usr/bin/env python3
"""
Analyze entity behavior timeline from Vault audit logs.

This script creates a time-series analysis of a specific entity's operations
to identify patterns, peak times, operation types, and potential issues.
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

def analyze_entity_timeline(log_file: str, entity_id: str, display_name: str = None):
    """Analyze timeline of operations for a specific entity."""
    
    # Data structures
    operations_by_hour = defaultdict(lambda: defaultdict(int))
    operations_by_type = defaultdict(int)
    paths_accessed = defaultdict(int)
    operations_timeline = []
    
    total_lines = 0
    entity_operations = 0
    
    print(f"Analyzing timeline for entity: {entity_id}")
    if display_name:
        print(f"Display name: {display_name}")
    print()
    
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 500000 == 0:
                print(f"  Processed {total_lines:,} lines, found {entity_operations:,} operations for this entity...")
            
            try:
                entry = json.loads(line.strip())
                
                # Check if this is our entity
                auth = entry.get('auth', {})
                entry_entity_id = auth.get('entity_id', '')
                
                if entry_entity_id != entity_id:
                    continue
                
                entity_operations += 1
                
                # Extract fields
                request = entry.get('request', {})
                path = request.get('path', '')
                operation = request.get('operation', '')
                timestamp = entry.get('time', '')
                
                ts = parse_timestamp(timestamp)
                
                if ts:
                    # Track by hour
                    hour_key = ts.strftime('%Y-%m-%d %H:00')
                    operations_by_hour[hour_key]['total'] += 1
                    operations_by_hour[hour_key][operation] += 1
                    
                    # Store operation for timeline
                    operations_timeline.append({
                        'timestamp': ts,
                        'path': path,
                        'operation': operation
                    })
                
                # Track operation types
                operations_by_type[operation] += 1
                
                # Track paths
                paths_accessed[path] += 1
                
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
    
    print(f"\nProcessed {total_lines:,} total lines")
    print(f"Found {entity_operations:,} operations for entity: {entity_id}")
    
    if entity_operations == 0:
        print("\nNo operations found for this entity!")
        return
    
    # Sort timeline
    operations_timeline.sort(key=lambda x: x['timestamp'])
    
    # Calculate time span
    if operations_timeline:
        first_op = operations_timeline[0]['timestamp']
        last_op = operations_timeline[-1]['timestamp']
        time_span = (last_op - first_op).total_seconds() / 3600  # hours
    else:
        time_span = 0
    
    # Analysis and reporting
    print("\n" + "=" * 100)
    print(f"TIMELINE ANALYSIS FOR: {entity_id}")
    print("=" * 100)
    
    # 1. Summary statistics
    print("\n1. SUMMARY STATISTICS")
    print("-" * 100)
    print(f"Total operations: {entity_operations:,}")
    print(f"Time span: {time_span:.2f} hours ({time_span/24:.2f} days)")
    print(f"Average rate: {entity_operations/time_span:.1f} operations/hour ({entity_operations/time_span/60:.2f}/minute)")
    if operations_timeline:
        print(f"First operation: {first_op.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Last operation: {last_op.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 2. Operation type distribution
    print("\n2. OPERATION TYPE DISTRIBUTION")
    print("-" * 100)
    print(f"{'Operation':<30} {'Count':<15} {'Percentage':<15}")
    print("-" * 100)
    
    sorted_ops = sorted(operations_by_type.items(), key=lambda x: x[1], reverse=True)
    for op, count in sorted_ops:
        percentage = (count / entity_operations) * 100
        print(f"{op:<30} {count:<15,} {percentage:<15.2f}%")
    
    # 3. Top paths accessed
    print("\n3. TOP 30 PATHS ACCESSED")
    print("-" * 100)
    print(f"{'Path':<70} {'Count':<15} {'Percentage':<15}")
    print("-" * 100)
    
    sorted_paths = sorted(paths_accessed.items(), key=lambda x: x[1], reverse=True)
    for path, count in sorted_paths[:30]:
        percentage = (count / entity_operations) * 100
        display_path = path if len(path) <= 68 else path[:65] + "..."
        print(f"{display_path:<70} {count:<15,} {percentage:<15.2f}%")
    
    # 4. Hourly activity pattern
    print("\n4. HOURLY ACTIVITY PATTERN (Top 30 Hours)")
    print("-" * 100)
    print(f"{'Hour':<20} {'Total Ops':<12} {'read':<10} {'update':<10} {'list':<10} {'Other':<10}")
    print("-" * 100)
    
    sorted_hours = sorted(operations_by_hour.items(), key=lambda x: x[1]['total'], reverse=True)
    
    for hour, ops in sorted_hours[:30]:
        total = ops['total']
        read = ops.get('read', 0)
        update = ops.get('update', 0)
        list_op = ops.get('list', 0)
        other = total - read - update - list_op
        
        print(f"{hour:<20} {total:<12,} {read:<10,} {update:<10,} {list_op:<10,} {other:<10,}")
    
    # 5. Activity distribution by hour of day
    print("\n5. ACTIVITY DISTRIBUTION BY HOUR OF DAY")
    print("-" * 100)
    
    hour_of_day_stats = defaultdict(int)
    for op in operations_timeline:
        hour_of_day = op['timestamp'].hour
        hour_of_day_stats[hour_of_day] += 1
    
    print(f"{'Hour':<10} {'Operations':<15} {'Bar Chart':<50}")
    print("-" * 100)
    
    max_ops_in_hour = max(hour_of_day_stats.values()) if hour_of_day_stats else 1
    
    for hour in range(24):
        ops = hour_of_day_stats[hour]
        bar_length = int((ops / max_ops_in_hour) * 50) if max_ops_in_hour > 0 else 0
        bar = "█" * bar_length
        print(f"{hour:02d}:00     {ops:<15,} {bar}")
    
    # 6. Peak activity analysis
    print("\n6. PEAK ACTIVITY WINDOWS")
    print("-" * 100)
    
    # Find 5-minute windows with highest activity
    window_counts = defaultdict(int)
    
    for op in operations_timeline:
        # Round to 5-minute window
        window_start = op['timestamp'].replace(second=0, microsecond=0)
        minute = (window_start.minute // 5) * 5
        window_start = window_start.replace(minute=minute)
        window_counts[window_start] += 1
    
    sorted_windows = sorted(window_counts.items(), key=lambda x: x[1], reverse=True)
    
    print(f"{'5-Minute Window':<25} {'Operations':<15} {'Rate (ops/sec)':<20}")
    print("-" * 100)
    
    for window, count in sorted_windows[:20]:
        rate = count / 300  # operations per second
        print(f"{window.strftime('%Y-%m-%d %H:%M'):<25} {count:<15,} {rate:<20.3f}")
    
    # 7. Behavioral patterns
    print("\n7. BEHAVIORAL PATTERNS")
    print("-" * 100)
    
    # Check for regular polling
    if time_span > 1:
        ops_per_hour = entity_operations / time_span
        if ops_per_hour > 100:
            print(f"⚠️  HIGH FREQUENCY: {ops_per_hour:.0f} operations/hour suggests automated polling")
            print("   Recommended action: Implement caching or increase polling interval")
        
        # Check for token lookup abuse
        token_lookup_paths = [p for p in paths_accessed.keys() if 'token/lookup' in p]
        total_token_lookups = sum(paths_accessed[p] for p in token_lookup_paths)
        
        if total_token_lookups > 1000:
            print(f"⚠️  TOKEN LOOKUP ABUSE: {total_token_lookups:,} token lookups detected")
            print(f"   Rate: {total_token_lookups/time_span:.1f} lookups/hour = {total_token_lookups/time_span/3600:.2f} lookups/second")
            print("   Recommended action: Implement client-side token TTL tracking")
        
        # Check for path concentration
        top_path_count = sorted_paths[0][1] if sorted_paths else 0
        top_path_pct = (top_path_count / entity_operations * 100) if entity_operations > 0 else 0
        
        if top_path_pct > 30:
            top_path = sorted_paths[0][0]
            print(f"⚠️  PATH CONCENTRATION: {top_path_pct:.1f}% of operations on single path")
            print(f"   Path: {top_path}")
            print(f"   Recommended action: Review why this path is accessed {top_path_count:,} times")
        
        # Check for 24/7 activity
        hours_with_activity = len([h for h in range(24) if hour_of_day_stats[h] > 0])
        if hours_with_activity >= 20:
            print(f"⚠️  24/7 ACTIVITY: Active in {hours_with_activity}/24 hours")
            print("   Suggests automated system or background process")
    
    print("\n" + "=" * 100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze entity behavior timeline from Vault audit logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python vault_audit_entity_timeline.py vault_audit.log f110e727-2f83-bad5-0dbf-7569a1ca510c "DevOps Service"
        '''
    )
    parser.add_argument('audit_log', help='Path to Vault audit log file')
    parser.add_argument('entity_id', help='Entity ID to analyze')
    parser.add_argument('display_name', nargs='?', help='Optional display name for reports')
    
    args = parser.parse_args()
    analyze_entity_timeline(args.audit_log, args.entity_id, args.display_name)
