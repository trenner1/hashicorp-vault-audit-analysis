#!/usr/bin/env python3
"""
Analyze token lookup patterns to find entities performing multiple lookups on the same token.
Identifies potential misconfigurations or inefficient token usage.
"""

import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(
        description='Analyze token lookup patterns from Vault audit logs'
    )
    parser.add_argument('log_file', help='Path to Vault audit log file')
    parser.add_argument(
        '--min-lookups',
        type=int,
        default=10,
        help='Minimum number of lookups to report (default: 10)'
    )
    parser.add_argument(
        '--top',
        type=int,
        default=20,
        help='Number of top offenders to show (default: 20)'
    )
    return parser.parse_args()


def analyze_lookup_patterns(log_file):
    """
    Analyze audit log for token lookup patterns.
    Returns dict with:
    {
        entity_id: {
            token_accessor: {
                'lookups': count,
                'first_seen': timestamp,
                'last_seen': timestamp
            }
        }
    }
    """
    patterns = defaultdict(lambda: defaultdict(lambda: {
        'lookups': 0,
        'first_seen': None,
        'last_seen': None
    }))

    total_lines = 0
    lookup_lines = 0

    print(f"Analyzing: {log_file}", file=sys.stderr)

    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 100000 == 0:
                print(f"[INFO] Processed {total_lines:,} lines, "
                      f"found {lookup_lines:,} lookups",
                      file=sys.stderr)

            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            # Filter for token lookup-self operations
            req = entry.get('request', {})
            auth = entry.get('auth', {})

            if req.get('path') != 'auth/token/lookup-self':
                continue

            entity_id = auth.get('entity_id')
            accessor = auth.get('accessor')
            timestamp = entry.get('time', '')

            if not entity_id or not accessor:
                continue

            lookup_lines += 1

            # Track lookup pattern
            token_data = patterns[entity_id][accessor]
            token_data['lookups'] += 1

            if token_data['first_seen'] is None:
                token_data['first_seen'] = timestamp
            token_data['last_seen'] = timestamp

    print(f"[INFO] Processed {total_lines:,} total lines", file=sys.stderr)
    print(f"[INFO] Found {lookup_lines:,} token lookup operations", file=sys.stderr)

    return patterns


def calculate_time_span(first_seen, last_seen):
    """Calculate time span between first and last lookup in hours."""
    try:
        first = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
        last = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
        delta = last - first
        return delta.total_seconds() / 3600  # hours
    except Exception:
        return 0


def main():
    args = parse_args()

    patterns = analyze_lookup_patterns(args.log_file)

    # Find entities with excessive lookups on the same token
    excessive_patterns = []

    for entity_id, tokens in patterns.items():
        for accessor, data in tokens.items():
            if data['lookups'] >= args.min_lookups:
                time_span = calculate_time_span(
                    data['first_seen'],
                    data['last_seen']
                )
                excessive_patterns.append({
                    'entity_id': entity_id,
                    'accessor': accessor[:20] + '...',  # Truncate for display
                    'lookups': data['lookups'],
                    'time_span_hours': time_span,
                    'lookups_per_hour': data['lookups'] / time_span if time_span > 0 else 0,
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen']
                })

    # Sort by number of lookups (descending)
    excessive_patterns.sort(key=lambda x: x['lookups'], reverse=True)

    # Print summary
    print("\n" + "=" * 120)
    print("Token Lookup Pattern Analysis")
    print("=" * 120)
    print(f"\nTotal Entities: {len(patterns):,}")
    print(f"Entities with ≥{args.min_lookups} lookups on same token: "
          f"{len(excessive_patterns):,}")

    if excessive_patterns:
        print(f"\nTop {args.top} Entities with Excessive Token Lookups:")
        print("-" * 120)
        print(f"{'Entity ID':<40} {'Token Accessor':<25} {'Lookups':>10} "
              f"{'Time Span':>12} {'Rate':>15}")
        print(f"{'':40} {'':25} {'':10} {'(hours)':>12} {'(lookups/hr)':>15}")
        print("-" * 120)

        for pattern in excessive_patterns[:args.top]:
            print(f"{pattern['entity_id']:<40} "
                  f"{pattern['accessor']:<25} "
                  f"{pattern['lookups']:>10,} "
                  f"{pattern['time_span_hours']:>12.1f} "
                  f"{pattern['lookups_per_hour']:>15.1f}")

    # Statistics
    if excessive_patterns:
        total_excessive_lookups = sum(p['lookups'] for p in excessive_patterns)
        avg_lookups = total_excessive_lookups / len(excessive_patterns)
        max_lookups = excessive_patterns[0]['lookups']

        print("\n" + "-" * 120)
        print(f"Total Excessive Lookups: {total_excessive_lookups:,}")
        print(f"Average Lookups per Entity: {avg_lookups:.1f}")
        print(f"Maximum Lookups (single token): {max_lookups:,}")

        # Find highest rate
        by_rate = sorted(excessive_patterns, key=lambda x: x['lookups_per_hour'],
                        reverse=True)
        if by_rate[0]['lookups_per_hour'] > 0:
            print(f"\nHighest Rate: {by_rate[0]['lookups_per_hour']:.1f} lookups/hour")
            print(f"  Entity: {by_rate[0]['entity_id']}")
            print(f"  Lookups: {by_rate[0]['lookups']:,}")

    print("=" * 120)


if __name__ == '__main__':
    main()
