#!/usr/bin/env python3
"""
Pretty-print summary of KV usage analysis from CSV output.
"""

import csv
import sys
import argparse

def summarize_kv_usage(csv_file):
    """Print a formatted summary of KV usage by client."""
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        if not rows:
            print(f"No data found in {csv_file}")
            return
        
        print("\n" + "="*70)
        print("  KV Usage Summary Report".center(70))
        print(f"  Source: {csv_file}".center(70))
        print("="*70 + "\n")
        
        total_paths = len(rows)
        total_clients = sum(int(row['unique_clients']) for row in rows)
        total_operations = sum(int(row['operations_count']) for row in rows)
        
        print("Overview:")
        print(f"   • Total KV Paths: {total_paths}")
        print(f"   • Total Unique Clients: {total_clients}")
        print(f"   • Total Operations: {total_operations}")
        print("\n" + "-"*70 + "\n")
        
        for i, row in enumerate(rows, 1):
            print(f"{i}. KV Path: {row['kv_path']}")
            print(f"   Unique Clients: {row['unique_clients']}")
            print(f"   Total Operations: {row['operations_count']}")
            print(f"   Entity IDs: {row['entity_ids']}")
            
            if row.get('alias_names'):
                print(f"   Alias Names: {row['alias_names']}")
            
            # Truncate sample paths if too long
            sample_paths = row.get('sample_paths_accessed', '')
            if len(sample_paths) > 80:
                sample_paths = sample_paths[:77] + "..."
            print(f"   Sample Paths: {sample_paths}")
            print()
        
        print("-"*70)
        print(f"Report complete. Analyzed {total_paths} KV paths.\n")
        
    except FileNotFoundError:
        print(f"Error: File not found: {csv_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Summarize KV usage analysis from CSV")
    parser.add_argument("csv_file", nargs="?", default="kv_usage_by_client.csv",
                        help="CSV file from kv_usage_analyzer.py (default: kv_usage_by_client.csv)")
    args = parser.parse_args()
    
    summarize_kv_usage(args.csv_file)

if __name__ == "__main__":
    main()
