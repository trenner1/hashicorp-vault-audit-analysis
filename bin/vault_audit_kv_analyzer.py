#!/usr/bin/env python3
"""
Vault KV Usage Analyzer - Parse audit logs to report client usage by KV path.

This script:
1. Parses Vault audit log files (JSON format)
2. Extracts entity IDs and KV paths accessed (read/list operations)
3. Aggregates unique clients per KV path
4. Optionally enriches output with entity/alias names from external CSV

Output: CSV with columns: kv_path, unique_clients, entity_ids, operations_count
"""

import os
import sys
import csv
import json
import argparse
from collections import defaultdict

def parse_audit_log_line(line, kv_prefix="kv/"):
    """
    Parse a single audit log JSON line.
    Returns dict with: entity_id, path, operation, timestamp
    Returns None if line is invalid or not a KV operation.
    """
    try:
        entry = json.loads(line.strip())
    except json.JSONDecodeError:
        return None
    
    # Extract relevant fields
    # Audit log structure: { "type": "response", "auth": {...}, "request": {...}, "response": {...} }
    req = entry.get("request", {})
    auth = entry.get("auth", {})
    
    # Filter for KV operations (read, list)
    operation = req.get("operation", "")
    path = req.get("path", "")
    
    # Only interested in KV read/list operations on the specified KV mount
    # If kv_prefix is empty, match all paths with /data/ or /metadata/ (KV v2 indicator)
    if kv_prefix:
        if not path.startswith(kv_prefix):
            return None
    else:
        # Match any path that contains /data/ or /metadata/ (KV v2 pattern)
        if "/data/" not in path and "/metadata/" not in path:
            return None
    
    if operation not in ["read", "list"]:
        return None
    
    # Extract entity ID from auth
    entity_id = auth.get("entity_id")
    if not entity_id:
        return None
    
    timestamp = entry.get("time", "")
    
    return {
        "entity_id": entity_id,
        "path": path,
        "operation": operation,
        "timestamp": timestamp
    }

def normalize_kv_path(path):
    """
    Normalize KV path to app-level grouping.
    Examples:
      kv/data/app1/config -> kv/app1/
      kv/metadata/app2/secrets -> kv/app2/
      kv/data/dev/apps/app1/secrets -> kv/dev/apps/app1/
      secret/app3/db_password -> secret/app3/
    
    Returns the app-level path (preserves up to 4 path components after mount).
    """
    parts = path.strip("/").split("/")
    
    # Handle KV v2 paths (kv/data/... or kv/metadata/...)
    if len(parts) >= 3 and parts[1] in ("data", "metadata"):
        # Remove the /data/ or /metadata/ component
        # kv/data/dev/apps/app1/... -> [kv, dev, apps, app1, ...]
        mount = parts[0]
        remaining_parts = [parts[2]] + parts[3:]  # Skip mount and data/metadata
        
        # Keep up to 3 more levels after mount (for paths like kv/dev/apps/app1/)
        if len(remaining_parts) >= 3:
            return f"{mount}/{remaining_parts[0]}/{remaining_parts[1]}/{remaining_parts[2]}/"
        elif len(remaining_parts) == 2:
            return f"{mount}/{remaining_parts[0]}/{remaining_parts[1]}/"
        elif len(remaining_parts) == 1:
            return f"{mount}/{remaining_parts[0]}/"
        else:
            return f"{mount}/"
    
    # Handle KV v1 or simple paths (no /data/ or /metadata/)
    # Preserve up to 4 levels to capture: mount/appcode/env/app-name/
    # e.g., appcodes/IOP0/PROD/Rundeck_Keys/ or ansible/DEV/app-name/
    if len(parts) >= 4:
        return f"{parts[0]}/{parts[1]}/{parts[2]}/{parts[3]}/"
    elif len(parts) == 3:
        return f"{parts[0]}/{parts[1]}/{parts[2]}/"
    elif len(parts) == 2:
        return f"{parts[0]}/{parts[1]}/"
    
    # Fallback
    return f"{parts[0]}/"

def analyze_audit_logs(log_files, kv_prefix="kv/"):
    """
    Parse audit log files and aggregate KV usage by path.
    
    Returns dict: {
        "kv/app1/": {
            "entity_ids": set(...),
            "operations_count": 123,
            "paths_accessed": set(...)
        }
    }
    """
    kv_usage = {}
    
    total_lines = 0
    parsed_lines = 0
    
    for log_file in log_files:
        if not os.path.exists(log_file):
            print(f"[WARN] Log file not found: {log_file}", file=sys.stderr)
            continue
        
        print(f"Processing: {log_file}", file=sys.stderr)
        
        with open(log_file, 'r') as f:
            for line in f:
                total_lines += 1
                result = parse_audit_log_line(line, kv_prefix=kv_prefix)
                
                if not result:
                    continue
                
                parsed_lines += 1
                
                # Normalize path to app-level
                app_path = normalize_kv_path(result["path"])
                
                # Initialize if not exists
                if app_path not in kv_usage:
                    kv_usage[app_path] = {
                        "entity_ids": set(),
                        "operations_count": 0,
                        "paths_accessed": set()
                    }
                
                # Aggregate
                kv_usage[app_path]["entity_ids"].add(result["entity_id"])
                kv_usage[app_path]["operations_count"] += 1
                kv_usage[app_path]["paths_accessed"].add(result["path"])
    
    print(f"[INFO] Processed {total_lines} lines, parsed {parsed_lines} KV operations", file=sys.stderr)
    
    return kv_usage

def load_entity_alias_mapping(alias_export_csv):
    """
    Load entity/alias mapping data from CSV (optional enrichment).
    Expected CSV format: entity_id, alias_name columns.
    Returns dict: entity_id -> list of alias names
    """
    entity_aliases = defaultdict(list)
    
    if alias_export_csv is None:
        return entity_aliases
    
    if not os.path.exists(alias_export_csv):
        print(f"[WARN] Entity alias export not found: {alias_export_csv}", file=sys.stderr)
        return entity_aliases
    
    with open(alias_export_csv, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            entity_id = row.get("entity_id")
            alias_name = row.get("alias_name")
            if entity_id and alias_name:
                entity_aliases[entity_id].append(alias_name)
    
    return entity_aliases

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Vault audit logs to determine KV usage by client/entity."
    )
    parser.add_argument(
        "log_files",
        nargs="+",
        help="Path(s) to Vault audit log file(s).",
    )
    parser.add_argument(
        "--kv-prefix",
        default="kv/",
        help="KV mount prefix to filter (default: kv/).",
    )
    parser.add_argument(
        "--alias-export",
        help="Path to vault_identity_alias_export.csv to map entity IDs to alias names.",
    )
    parser.add_argument(
        "--output",
        default="data/kv_usage_by_client.csv",
        help="Output CSV file for KV usage analysis.",
    )
    args = parser.parse_args()

    # Ensure data directory exists
    import os
    os.makedirs("data", exist_ok=True)
    
    # Parse audit logs
    kv_usage = analyze_audit_logs(args.log_files, kv_prefix=args.kv_prefix)
    
    if not kv_usage:
        print("[ERROR] No KV operations found in audit logs.", file=sys.stderr)
        sys.exit(1)
    
    # Load entity/alias mapping for enrichment
    entity_aliases = load_entity_alias_mapping(args.alias_export)
    
    # Write output CSV
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "kv_path",
            "unique_clients",
            "operations_count",
            "entity_ids",
            "alias_names",
            "sample_paths_accessed"
        ])
        
        # Sort by path for readability
        for kv_path in sorted(kv_usage.keys()):
            data = kv_usage[kv_path]
            entity_ids = sorted(data["entity_ids"])
            unique_clients = len(entity_ids)
            operations = data["operations_count"]
            
            # Collect alias names for these entities
            alias_names = []
            for eid in entity_ids:
                alias_names.extend(entity_aliases.get(eid, []))
            
            # Sample of paths accessed (limit to 5 for readability)
            sample_paths = sorted(data["paths_accessed"])[:5]
            
            writer.writerow([
                kv_path,
                unique_clients,
                operations,
                ", ".join(entity_ids),
                ", ".join(alias_names) if alias_names else "",
                ", ".join(sample_paths)
            ])
    
    print(f"Done. Output written to: {args.output}")
    print(f"Summary: {len(kv_usage)} KV paths analyzed")

if __name__ == "__main__":
    main()
