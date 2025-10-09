#!/usr/bin/env python3
"""
Analyze operations with no entity ID from Vault audit logs.

This script investigates operations that have no associated entity_id to understand:
- What types of operations are being performed
- What paths are being accessed  
- What authentication methods are in use (if any)
- Potential security implications
"""

import json
import argparse
from collections import defaultdict

def analyze_no_entity_operations(log_file: str):
    """Analyze operations with no entity ID."""
    
    # Data structures
    operations_by_type = defaultdict(int)
    paths_accessed = defaultdict(int)
    auth_methods = defaultdict(int)
    display_names = defaultdict(int)
    policies = defaultdict(int)
    
    total_lines = 0
    no_entity_operations = 0
    
    print(f"Analyzing no-entity operations in {log_file}...")
    
    with open(log_file, 'r') as f:
        for line in f:
            total_lines += 1
            if total_lines % 500000 == 0:
                print(f"  Processed {total_lines:,} lines, found {no_entity_operations:,} no-entity operations...")
            
            try:
                entry = json.loads(line.strip())
                
                # Check for no entity
                auth = entry.get('auth', {})
                entity_id = auth.get('entity_id', '')
                
                # Skip if there is an entity
                if entity_id and entity_id != 'no-entity':
                    continue
                
                no_entity_operations += 1
                
                # Extract fields
                request = entry.get('request', {})
                path = request.get('path', '')
                operation = request.get('operation', '')
                
                # Auth details
                display_name = auth.get('display_name', 'unknown')
                token_policies = auth.get('policies', [])
                
                # Track data
                operations_by_type[operation] += 1
                paths_accessed[path] += 1
                display_names[display_name] += 1
                
                # Track policies
                for policy in token_policies:
                    policies[policy] += 1
                
                # Determine auth method from path or display name
                if 'approle' in display_name.lower() or 'approle' in path.lower():
                    auth_methods['approle'] += 1
                elif 'token' in display_name.lower() or 'auth/token' in path:
                    auth_methods['token'] += 1
                elif 'kubernetes' in display_name.lower() or 'auth/kubernetes' in path:
                    auth_methods['kubernetes'] += 1
                elif 'ldap' in display_name.lower() or 'auth/ldap' in path:
                    auth_methods['ldap'] += 1
                elif 'userpass' in display_name.lower() or 'auth/userpass' in path:
                    auth_methods['userpass'] += 1
                else:
                    auth_methods['unknown'] += 1
                
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
    
    print(f"\nProcessed {total_lines:,} total lines")
    print(f"Found {no_entity_operations:,} operations with no entity ID")
    
    if no_entity_operations == 0:
        print("\nNo operations without entity ID found!")
        return
    
    # Analysis and reporting
    print("\n" + "=" * 100)
    print("NO-ENTITY OPERATIONS ANALYSIS")
    print("=" * 100)
    
    # 1. Summary
    print("\n1. SUMMARY")
    print("-" * 100)
    print(f"Total no-entity operations: {no_entity_operations:,}")
    print(f"Percentage of all operations: {(no_entity_operations/total_lines)*100:.2f}%")
    
    # 2. Authentication methods
    print("\n2. AUTHENTICATION METHOD DISTRIBUTION")
    print("-" * 100)
    print(f"{'Method':<30} {'Count':<15} {'Percentage':<15}")
    print("-" * 100)
    
    sorted_methods = sorted(auth_methods.items(), key=lambda x: x[1], reverse=True)
    for method, count in sorted_methods:
        percentage = (count / no_entity_operations) * 100
        print(f"{method:<30} {count:<15,} {percentage:<15.2f}%")
    
    # 3. Operation types
    print("\n3. OPERATION TYPE DISTRIBUTION")
    print("-" * 100)
    print(f"{'Operation':<30} {'Count':<15} {'Percentage':<15}")
    print("-" * 100)
    
    sorted_ops = sorted(operations_by_type.items(), key=lambda x: x[1], reverse=True)
    for op, count in sorted_ops[:20]:
        percentage = (count / no_entity_operations) * 100
        print(f"{op:<30} {count:<15,} {percentage:<15.2f}%")
    
    # 4. Top paths
    print("\n4. TOP 30 PATHS ACCESSED")
    print("-" * 100)
    print(f"{'Path':<70} {'Count':<15} {'% of No-Entity':<15}")
    print("-" * 100)
    
    sorted_paths = sorted(paths_accessed.items(), key=lambda x: x[1], reverse=True)
    for path, count in sorted_paths[:30]:
        percentage = (count / no_entity_operations) * 100
        display_path = path if len(path) <= 68 else path[:65] + "..."
        print(f"{display_path:<70} {count:<15,} {percentage:<15.2f}%")
    
    # 5. Display names
    print("\n5. TOP 30 DISPLAY NAMES")
    print("-" * 100)
    print(f"{'Display Name':<60} {'Count':<20} {'Percentage':<15}")
    print("-" * 100)
    
    sorted_names = sorted(display_names.items(), key=lambda x: x[1], reverse=True)
    for name, count in sorted_names[:30]:
        percentage = (count / no_entity_operations) * 100
        display_name = name if len(name) <= 58 else name[:55] + "..."
        print(f"{display_name:<60} {count:<20,} {percentage:<15.2f}%")
    
    # 6. Token policies
    print("\n6. TOP 20 TOKEN POLICIES")
    print("-" * 100)
    print(f"{'Policy':<60} {'Count':<20} {'% of Operations':<15}")
    print("-" * 100)
    
    sorted_policies = sorted(policies.items(), key=lambda x: x[1], reverse=True)
    for policy, count in sorted_policies[:20]:
        percentage = (count / no_entity_operations) * 100
        display_policy = policy if len(policy) <= 58 else policy[:55] + "..."
        print(f"{display_policy:<60} {count:<20,} {percentage:<15.2f}%")
    
    # 7. Security analysis
    print("\n7. SECURITY ANALYSIS")
    print("-" * 100)
    
    # Check for unauthenticated access attempts
    auth_paths = ['auth/token/', 'auth/approle/', 'auth/kubernetes/', 'auth/ldap/', 'sys/']
    unauthenticated_attempts = sum(count for path, count in paths_accessed.items() 
                                   if not any(auth_path in path for auth_path in auth_paths))
    
    if unauthenticated_attempts > 0:
        print(f"NON-AUTH PATHS: {unauthenticated_attempts:,} operations on non-authentication paths")
        print("   This may indicate:")
        print("   - Token-based authentication without entity mapping")
        print("   - Service accounts that should have entity associations")
        print("   - Potential security policy gaps")
    
    # Check for high-volume paths
    high_volume_paths = [(p, c) for p, c in sorted_paths[:10] if c > 1000]
    if high_volume_paths:
        print("\nHIGH-VOLUME NO-ENTITY PATHS:")
        for path, count in high_volume_paths:
            path_display = path if len(path) <= 65 else path[:62] + "..."
            print(f"   - {path_display}: {count:,} operations")
        print("   Recommendation: Investigate why these operations lack entity association")
    
    # Check for service accounts
    service_account_indicators = ['service', 'svc', 'app', 'bot', 'automation']
    service_accounts = [(name, count) for name, count in sorted_names 
                       if any(indicator in name.lower() for indicator in service_account_indicators)]
    
    if service_accounts and len(service_accounts) > 5:
        print(f"\nSERVICE ACCOUNTS WITHOUT ENTITIES: {len(service_accounts)} detected")
        print("   Top 5:")
        for name, count in service_accounts[:5]:
            name_display = name if len(name) <= 50 else name[:47] + "..."
            print(f"   - {name_display}: {count:,} operations")
        print("   Recommendation: Enable entity aliasing for service accounts")
    
    # Summary recommendation
    print("\n8. RECOMMENDATIONS")
    print("-" * 100)
    print("1. ENABLE ENTITY ALIASING")
    print("   - Configure entity aliases for all authentication methods")
    print("   - Especially critical for service accounts and approles")
    print("   - Expected impact: Better audit trail and entity-based policies")
    print()
    print("2. REVIEW TOKEN POLICIES")
    print(f"   - {len(policies)} distinct policies in use by no-entity operations")
    print("   - Ensure policies are aligned with entity-based access control")
    print()
    print("3. INVESTIGATE HIGH-VOLUME PATHS")
    print(f"   - {len([c for c in paths_accessed.values() if c > 100])} paths with >100 no-entity operations")
    print("   - Review if these should have entity associations")
    
    print("\n" + "=" * 100)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze operations without entity IDs from Vault audit logs'
    )
    parser.add_argument('audit_log', help='Path to Vault audit log file')
    
    args = parser.parse_args()
    analyze_no_entity_operations(args.audit_log)
