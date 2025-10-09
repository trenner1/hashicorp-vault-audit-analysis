#!/usr/bin/env python3
"""
Export all token lookup operations by entity from Vault audit logs to CSV.
Provides comprehensive view of token lookup patterns for analysis.
"""

import json
import sys
import csv
import argparse
from collections import defaultdict
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(
        description='Export token lookup operations by entity to CSV'
    )
    parser.add_argument('log_file', help='Path to Vault audit log file')
    parser.add_argument(
        '--output',
        default='data/token_lookups_by_entity.csv',
        help='Output CSV file (default: data/token_lookups_by_entity.csv)'
    )
    parser.add_argument(
        '--include-display-names',
        action='store_true',
        help='Include display names in output (requires entity mapping)'
    )
    return parser.parse_args()


def analyze_lookups(log_file):
    """
    Parse audit log and aggregate token lookup operations by entity.
    Returns dict: {
        entity_id: {
            'display_name': str,
            'tokens': {
                token_accessor: {
                    'lookups': count,
                    'first_seen': timestamp,
                    'last_seen': timestamp
                }
            }
        }
    }
    """
    entities = defaultdict(lambda: {
        'display_name': '',
        'tokens': defaultdict(lambda: {
            'lookups': 0,
            'first_seen': None,
            'last_seen': None
        })
    })

    total_lines = 0
    lookup_count = 0

    print(f"Processing: {log_file}", file=sys.stderr)

    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 100000 == 0:
                print(f"[INFO] Processed {total_lines:,} lines, "
                      f"found {lookup_count:,} token lookups",
                      file=sys.stderr)

            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            # Filter for token lookup operations
            req = entry.get('request', {})
            auth = entry.get('auth', {})

            path = req.get('path', '')
            if not path.startswith('auth/token/lookup'):
                continue

            entity_id = auth.get('entity_id')
            if not entity_id:
                continue

            lookup_count += 1

            # Get entity info
            entity_data = entities[entity_id]
            if not entity_data['display_name']:
                entity_data['display_name'] = auth.get('display_name', 'N/A')

            # Track token accessor
            accessor = auth.get('accessor', 'unknown')
            timestamp = entry.get('time', '')

            token_data = entity_data['tokens'][accessor]
            token_data['lookups'] += 1

            if token_data['first_seen'] is None:
                token_data['first_seen'] = timestamp
            token_data['last_seen'] = timestamp

    print(f"[INFO] Processed {total_lines:,} total lines", file=sys.stderr)
    print(f"[INFO] Found {lookup_count:,} token lookup operations", file=sys.stderr)
    print(f"[INFO] Found {len(entities):,} unique entities", file=sys.stderr)

    return entities


def calculate_time_span(first_seen, last_seen):
    """Calculate time span between first and last lookup in hours."""
    try:
        first = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
        last = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
        delta = last - first
        return delta.total_seconds() / 3600  # hours
    except Exception:
        return 0


def export_to_csv(entities, output_file):
    """Export entity lookup data to CSV."""
    import os
    os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)

    rows = []
    
    for entity_id, entity_data in entities.items():
        for accessor, token_data in entity_data['tokens'].items():
            time_span = calculate_time_span(
                token_data['first_seen'],
                token_data['last_seen']
            )
            lookups_per_hour = token_data['lookups'] / time_span if time_span > 0 else 0

            rows.append({
                'entity_id': entity_id,
                'display_name': entity_data['display_name'],
                'token_accessor': accessor,
                'total_lookups': token_data['lookups'],
                'time_span_hours': round(time_span, 2),
                'lookups_per_hour': round(lookups_per_hour, 2),
                'first_seen': token_data['first_seen'],
                'last_seen': token_data['last_seen']
            })

    # Sort by total lookups descending
    rows.sort(key=lambda x: x['total_lookups'], reverse=True)

    # Write CSV
    with open(output_file, 'w', newline='') as f:
        fieldnames = [
            'entity_id',
            'display_name',
            'token_accessor',
            'total_lookups',
            'time_span_hours',
            'lookups_per_hour',
            'first_seen',
            'last_seen'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[SUCCESS] Exported {len(rows):,} token lookup records to: {output_file}",
          file=sys.stderr)
    
    return rows


def print_summary(rows):
    """Print summary statistics."""
    if not rows:
        return

    total_lookups = sum(r['total_lookups'] for r in rows)
    unique_entities = len(set(r['entity_id'] for r in rows))
    unique_tokens = len(rows)

    print("\n" + "=" * 80, file=sys.stderr)
    print("Summary Statistics:", file=sys.stderr)
    print("-" * 80, file=sys.stderr)
    print(f"Total Token Lookup Operations: {total_lookups:,}", file=sys.stderr)
    print(f"Unique Entities: {unique_entities:,}", file=sys.stderr)
    print(f"Unique Token Accessors: {unique_tokens:,}", file=sys.stderr)
    print(f"Average Lookups per Token: {total_lookups / unique_tokens:.1f}",
          file=sys.stderr)
    
    # Top 5 entities by lookup count
    print("\nTop 5 Entities by Lookup Count:", file=sys.stderr)
    print("-" * 80, file=sys.stderr)
    
    entity_totals = defaultdict(int)
    entity_names = {}
    for row in rows:
        entity_totals[row['entity_id']] += row['total_lookups']
        entity_names[row['entity_id']] = row['display_name']
    
    top_entities = sorted(entity_totals.items(), key=lambda x: x[1], reverse=True)[:5]
    for i, (entity_id, count) in enumerate(top_entities, 1):
        name = entity_names[entity_id]
        print(f"{i}. {name} ({entity_id}): {count:,} lookups", file=sys.stderr)
    
    print("=" * 80, file=sys.stderr)


def main():
    args = parse_args()

    # Analyze audit log
    entities = analyze_lookups(args.log_file)

    # Export to CSV
    rows = export_to_csv(entities, args.output)

    # Print summary
    print_summary(rows)

    print(f"\n✓ Token lookup data exported to: {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
