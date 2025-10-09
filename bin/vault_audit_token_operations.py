#!/usr/bin/env python3
"""
Analyze token requests from Vault audit logs.

This script identifies who is requesting tokens (auth/token operations)
and counts how many requests each entity makes.
"""

import json
import sys
from collections import defaultdict
import argparse

def parse_token_operations(log_file):
    """
    Parse audit log for token-related operations.
    Returns dict of entity_id -> operation counts.
    """
    token_ops = defaultdict(lambda: {
        'lookup-self': 0,
        'renew-self': 0,
        'revoke-self': 0,
        'create': 0,
        'other': 0,
        'display_name': None,
        'metadata': {}
    })
    
    total_lines = 0
    
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            
            req = entry.get('request', {})
            auth = entry.get('auth', {})
            
            # Filter for token operations
            path = req.get('path', '')
            if not path.startswith('auth/token/'):
                continue
            
            operation = req.get('operation', '')
            entity_id = auth.get('entity_id')
            
            if not entity_id:
                continue
            
            # Categorize operation
            if 'lookup-self' in path:
                token_ops[entity_id]['lookup-self'] += 1
            elif 'renew-self' in path:
                token_ops[entity_id]['renew-self'] += 1
            elif 'revoke-self' in path:
                token_ops[entity_id]['revoke-self'] += 1
            elif 'create' in path or operation == 'create':
                token_ops[entity_id]['create'] += 1
            else:
                token_ops[entity_id]['other'] += 1
            
            # Capture display name and metadata (first occurrence)
            if token_ops[entity_id]['display_name'] is None:
                token_ops[entity_id]['display_name'] = auth.get('display_name', 'unknown')
                token_ops[entity_id]['metadata'] = auth.get('metadata', {})
    
    print(f"[INFO] Processed {total_lines:,} lines", file=sys.stderr)
    return dict(token_ops)

def main():
    parser = argparse.ArgumentParser(
        description='Analyze token requests from Vault audit logs'
    )
    parser.add_argument('log_file', help='Path to Vault audit log file')
    parser.add_argument('--top', type=int, default=50, 
                       help='Show top N entities (default: 50)')
    parser.add_argument('--min-ops', type=int, default=1,
                       help='Minimum operations to display (default: 1)')
    
    args = parser.parse_args()
    
    print(f"Processing: {args.log_file}", file=sys.stderr)
    token_ops = parse_token_operations(args.log_file)
    
    # Calculate totals per entity
    entity_totals = []
    for entity_id, ops in token_ops.items():
        total = ops['lookup-self'] + ops['renew-self'] + ops['revoke-self'] + ops['create'] + ops['other']
        if total >= args.min_ops:
            entity_totals.append({
                'entity_id': entity_id,
                'total': total,
                'display_name': ops['display_name'],
                'lookup': ops['lookup-self'],
                'renew': ops['renew-self'],
                'revoke': ops['revoke-self'],
                'create': ops['create'],
                'other': ops['other'],
                'username': ops['metadata'].get('username', '')
            })
    
    # Sort by total operations
    entity_totals.sort(key=lambda x: x['total'], reverse=True)
    
    # Display results
    print("\n" + "=" * 140)
    print(f"{'Display Name':<30} {'Username':<25} {'Total':<10} {'Lookup':<10} {'Renew':<10} {'Revoke':<10} {'Create':<10} {'Other':<10}")
    print("=" * 140)
    
    grand_total = 0
    for i, item in enumerate(entity_totals[:args.top]):
        print(f"{item['display_name'][:29]:<30} {item['username'][:24]:<25} "
              f"{item['total']:<10,} {item['lookup']:<10,} {item['renew']:<10,} "
              f"{item['revoke']:<10,} {item['create']:<10,} {item['other']:<10,}")
        grand_total += item['total']
    
    print("=" * 140)
    print(f"{'TOTAL (top ' + str(min(args.top, len(entity_totals))) + ')':<55} {grand_total:<10,}")
    print(f"{'TOTAL ENTITIES':<55} {len(entity_totals):<10,}")
    print("=" * 140)
    
    # Summary by operation type
    total_lookup = sum(item['lookup'] for item in entity_totals)
    total_renew = sum(item['renew'] for item in entity_totals)
    total_revoke = sum(item['revoke'] for item in entity_totals)
    total_create = sum(item['create'] for item in entity_totals)
    total_other = sum(item['other'] for item in entity_totals)
    overall_total = total_lookup + total_renew + total_revoke + total_create + total_other
    
    print("\nOperation Type Breakdown:")
    print("-" * 60)
    print(f"Lookup (lookup-self):  {total_lookup:>12,}  ({total_lookup/overall_total*100:>5.1f}%)")
    print(f"Renew (renew-self):    {total_renew:>12,}  ({total_renew/overall_total*100:>5.1f}%)")
    print(f"Revoke (revoke-self):  {total_revoke:>12,}  ({total_revoke/overall_total*100:>5.1f}%)")
    print(f"Create:                {total_create:>12,}  ({total_create/overall_total*100:>5.1f}%)")
    print(f"Other:                 {total_other:>12,}  ({total_other/overall_total*100:>5.1f}%)")
    print("-" * 60)
    print(f"TOTAL:                 {overall_total:>12,}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
