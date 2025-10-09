#!/usr/bin/env python3
"""
Analyze Vault audit logs to identify high-volume operations causing system stress.
Reports top operations by path pattern and entity to find potential bottlenecks.
"""

import json
import sys
import argparse
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser(
        description='Identify high-volume Vault operations causing system stress'
    )
    parser.add_argument('log_file', help='Path to Vault audit log file')
    parser.add_argument(
        '--top',
        type=int,
        default=30,
        help='Number of top operations to show (default: 30)'
    )
    parser.add_argument(
        '--min-operations',
        type=int,
        default=1000,
        help='Minimum operations to report (default: 1000)'
    )
    return parser.parse_args()


def analyze_operations(log_file):
    """
    Parse audit log and aggregate all operations by path pattern and type.
    Returns multiple aggregations for different analysis views.
    """
    # Track by path
    path_operations = defaultdict(lambda: {
        'count': 0,
        'operations': defaultdict(int),
        'entities': set()
    })
    
    # Track by operation type
    operation_types = defaultdict(int)
    
    # Track by path prefix (first 2-3 components)
    path_prefixes = defaultdict(int)
    
    # Track by entity + path for heavy users
    entity_paths = defaultdict(lambda: defaultdict(int))
    entity_names = {}
    
    total_lines = 0

    print(f"Analyzing: {log_file}", file=sys.stderr)

    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 100000 == 0:
                print(f"[INFO] Processed {total_lines:,} lines", file=sys.stderr)

            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            req = entry.get('request', {})
            auth = entry.get('auth', {})

            path = req.get('path', '')
            operation = req.get('operation', '')
            entity_id = auth.get('entity_id', 'no-entity')
            display_name = auth.get('display_name', 'N/A')

            if not path or not operation:
                continue

            # Track by full path
            path_data = path_operations[path]
            path_data['count'] += 1
            path_data['operations'][operation] += 1
            if entity_id:
                path_data['entities'].add(entity_id)

            # Track by operation type
            operation_types[operation] += 1

            # Track by path prefix
            parts = path.strip('/').split('/')
            if len(parts) >= 2:
                prefix = f"{parts[0]}/{parts[1]}"
            else:
                prefix = parts[0] if parts else 'root'
            path_prefixes[prefix] += 1

            # Track entity usage
            if entity_id:
                entity_paths[entity_id][path] += 1
                if entity_id not in entity_names:
                    entity_names[entity_id] = display_name

    print(f"[INFO] Processed {total_lines:,} total lines", file=sys.stderr)

    return {
        'path_operations': path_operations,
        'operation_types': operation_types,
        'path_prefixes': path_prefixes,
        'entity_paths': entity_paths,
        'entity_names': entity_names,
        'total_lines': total_lines
    }


def main():
    args = parse_args()

    # Analyze operations
    results = analyze_operations(args.log_file)

    path_operations = results['path_operations']
    operation_types = results['operation_types']
    path_prefixes = results['path_prefixes']
    entity_paths = results['entity_paths']
    entity_names = results['entity_names']

    total_operations = sum(operation_types.values())

    print("\n" + "=" * 100)
    print("High-Volume Vault Operations Analysis")
    print("=" * 100)

    # 1. Operation Types Summary
    print("\n1. Operation Types (Overall)")
    print("-" * 100)
    print(f"{'Operation':<20} {'Count':>15} {'Percentage':>12}")
    print("-" * 100)

    sorted_ops = sorted(operation_types.items(), key=lambda x: x[1], reverse=True)
    for op, count in sorted_ops:
        pct = (count / total_operations * 100) if total_operations > 0 else 0
        print(f"{op:<20} {count:>15,} {pct:>11.2f}%")

    print("-" * 100)
    print(f"{'TOTAL':<20} {total_operations:>15,} {100.0:>11.2f}%")

    # 2. Top Path Prefixes
    print("\n2. Top Path Prefixes (First 2 components)")
    print("-" * 100)
    print(f"{'Path Prefix':<40} {'Operations':>15} {'Percentage':>12}")
    print("-" * 100)

    sorted_prefixes = sorted(path_prefixes.items(), key=lambda x: x[1], reverse=True)
    for prefix, count in sorted_prefixes[:args.top]:
        pct = (count / total_operations * 100) if total_operations > 0 else 0
        print(f"{prefix:<40} {count:>15,} {pct:>11.2f}%")

    # 3. Top Individual Paths
    print(f"\n3. Top {args.top} Individual Paths (Highest Volume)")
    print("-" * 100)
    print(f"{'Path':<60} {'Ops':>10} {'Entities':>10} {'Top Op':>15}")
    print("-" * 100)

    sorted_paths = sorted(path_operations.items(), key=lambda x: x[1]['count'], reverse=True)
    for path, data in sorted_paths[:args.top]:
        if data['count'] < args.min_operations:
            break
        top_op = max(data['operations'].items(), key=lambda x: x[1])[0]
        path_display = path[:58] + '..' if len(path) > 60 else path
        print(f"{path_display:<60} {data['count']:>10,} {len(data['entities']):>10,} {top_op:>15}")

    # 4. Top Entities by Total Operations
    print(f"\n4. Top {args.top} Entities by Total Operations")
    print("-" * 100)
    print(f"{'Display Name':<50} {'Entity ID':<38} {'Total Ops':>10}")
    print("-" * 100)

    entity_totals = {eid: sum(paths.values()) for eid, paths in entity_paths.items()}
    sorted_entities = sorted(entity_totals.items(), key=lambda x: x[1], reverse=True)

    for entity_id, total in sorted_entities[:args.top]:
        name = entity_names.get(entity_id, 'N/A')[:48]
        entity_short = entity_id[:36]
        print(f"{name:<50} {entity_short:<38} {total:>10,}")

    # 5. Potential Stress Points
    print("\n5. Potential System Stress Points")
    print("-" * 100)

    # Find paths with high operation counts from single entities
    stress_points = []
    for path, data in path_operations.items():
        if data['count'] >= args.min_operations:
            # Check if dominated by few entities
            for entity_id in data['entities']:
                entity_ops = entity_paths[entity_id].get(path, 0)
                if entity_ops >= args.min_operations:
                    stress_points.append({
                        'path': path,
                        'entity_id': entity_id,
                        'entity_name': entity_names.get(entity_id, 'N/A'),
                        'operations': entity_ops,
                        'total_path_ops': data['count']
                    })

    stress_points.sort(key=lambda x: x['operations'], reverse=True)

    print(f"{'Entity':<40} {'Path':<40} {'Ops':>10}")
    print("-" * 100)
    for sp in stress_points[:args.top]:
        entity_display = sp['entity_name'][:38]
        path_display = sp['path'][:38]
        print(f"{entity_display:<40} {path_display:<40} {sp['operations']:>10,}")

    print("=" * 100)
    print(f"\nTotal Lines Processed: {results['total_lines']:,}")
    print(f"Total Operations: {total_operations:,}")
    print("=" * 100)


if __name__ == '__main__':
    main()
