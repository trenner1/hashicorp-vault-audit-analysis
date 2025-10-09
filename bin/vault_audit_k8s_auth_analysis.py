#!/usr/bin/env python3
"""
Analyze entity churn patterns from ephemeral workloads in Vault audit logs.

This script performs multi-dimensional analysis of Kubernetes/OpenShift authentication
patterns to identify root causes of entity proliferation and excessive login operations.

Key Analysis Dimensions:
1. Login-to-Entity Ratio: Overall churn indicator per cluster
2. Per-Entity Login Counts: Identifies "chatty" entities (caching issues)
3. Per-Service-Account Entity Counts: Identifies ephemeral entity churn
4. Singleton Ratio: Percentage of entities with only 1 login (disposable entities)
5. P95 Logins/Entity: Detects high-frequency authentication patterns

High login-to-entity ratios combined with high singleton ratios indicate ephemeral
workloads creating new entities on each pod restart due to entity alias misconfiguration.
"""

import json
import re
import argparse
from collections import defaultdict, Counter

# Configuration thresholds
ENTITY_LOGIN_THRESHOLD = 200      # Flag entity if logins >= this (chatty entity)
SA_ENTITY_THRESHOLD = 50           # Flag service account if distinct entities >= this (churn)
SINGLETON_RATIO_THRESHOLD = 0.80   # Flag SA if >=80% of entities have exactly 1 login
P95_LOGIN_THRESHOLD = 10           # Flag SA if p95 logins/entity >= this
TOP_N = 15                         # Number of top results to display

# Regex patterns
JSON_START_RE = re.compile(r'(\{.*)')
TRAILING_SLASH_RE = re.compile(r'/+$')
LOGIN_TAIL_RE = re.compile(r'/+login$')
K8S_WORDS = ('kubernetes', 'openshift')


def coerce_json(line: str):
    """Extract JSON from line that may have docker/k8s prefixes."""
    m = JSON_START_RE.search(line)
    if not m:
        raise ValueError("no json start")
    return json.loads(m.group(1))


def norm_path(p: str) -> str:
    """Normalize path by removing trailing slashes."""
    return '' if not p else TRAILING_SLASH_RE.sub('', p)


def is_k8s_login(path: str, mount_type: str = None) -> bool:
    """Check if path is a K8s/OpenShift login operation."""
    p = norm_path(path)
    if not p:
        return False
    if LOGIN_TAIL_RE.search(p) and any(w in p for w in K8S_WORDS):
        return True
    if LOGIN_TAIL_RE.search(p) and (mount_type in ('kubernetes', 'openshift')):
        return True
    return False


def status_ok(entry: dict) -> bool:
    """Check if response entry indicates successful authentication."""
    if entry.get('type') != 'response':
        return False
    if entry.get('error') not in (None, False, ''):
        return False
    resp = entry.get('response') or {}
    st = resp.get('status', resp.get('http_status'))
    try:
        return (st is None) or int(st) == 200
    except:
        return False


def safe_get(d, *keys, default=None):
    """Safely get nested dictionary value."""
    cur = d or {}
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return default if cur is None else cur


def extract_sa_label(entry: dict):
    """Extract service account label from auth metadata."""
    md = safe_get(entry, 'auth', 'metadata', default={}) or {}
    sa = (md.get('service_account_name') or '').strip()
    ns = (md.get('service_account_namespace') or 
          md.get('kubernetes_namespace') or 
          md.get('namespace') or '').strip()
    
    if not sa and not ns:
        # Last resort: display_name as label
        disp = (safe_get(entry, 'auth', 'display_name', default='') or '').strip()
        if not disp:
            return None
        return f'(no-ns)/{disp}'
    
    return f"{(ns or '(no-ns)')}/{(sa or '(no-sa)')}"


def analyze_ephemeral_entity_churn(log_file: str):
    """Perform comprehensive entity churn analysis."""
    
    # Aggregation structures - keyed by mount accessor for stability
    mounts = defaultdict(lambda: {
        'display_mount': None,
        'ok_count': 0,
        'fail_count': 0,
        'entity_ids': set(),
        'per_entity_logins': Counter(),     # entity_id -> ok login count
        'per_sa_logins': Counter(),         # sa_label -> ok login count
        'per_sa_entities': defaultdict(set) # sa_label -> set(entity_id)
    })
    
    totals = dict(lines=0, parsed=0, skipped=0, responses=0, k8s_ok=0)
    
    print(f"Analyzing entity churn patterns in {log_file}...")
    
    # Handle gzipped files
    open_fn = open
    if log_file.endswith('.gz'):
        import gzip, io
        open_fn = lambda p, mode='rb': io.TextIOWrapper(
            gzip.open(p, mode), encoding='utf-8', errors='replace'
        )
    
    # Process audit log
    with open_fn(log_file, 'rb' if log_file.endswith('.gz') else 'r') as f:
        for raw in f:
            line = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else raw
            totals['lines'] += 1
            
            if totals['lines'] % 500000 == 0:
                print(f"  Processed {totals['lines']:,} lines, "
                      f"found {totals['k8s_ok']:,} successful K8s/OpenShift logins...")
            
            try:
                entry = coerce_json(line.strip())
                totals['parsed'] += 1
            except:
                totals['skipped'] += 1
                continue
            
            # Track response entries
            if entry.get('type') == 'response':
                totals['responses'] += 1
            
            # Filter for K8s/OpenShift login operations
            req = entry.get('request') or {}
            path = norm_path(req.get('path', ''))
            if not is_k8s_login(path, req.get('mount_type')):
                continue
            
            # Use mount accessor as stable key
            accessor = req.get('mount_accessor') or path.rsplit('/login', 1)[0]
            disp_mount = path.rsplit('/login', 1)[0] or '(unknown-mount)'
            bucket = mounts[accessor]
            
            if bucket['display_mount'] is None:
                bucket['display_mount'] = disp_mount
            
            # Check if successful response
            if status_ok(entry):
                totals['k8s_ok'] += 1
                bucket['ok_count'] += 1
                
                # Extract entity ID
                eid = safe_get(entry, 'auth', 'entity_id')
                if eid:
                    bucket['entity_ids'].add(eid)
                    bucket['per_entity_logins'][eid] += 1
                
                # Extract service account label
                sa_label = extract_sa_label(entry)
                if sa_label:
                    bucket['per_sa_logins'][sa_label] += 1
                    if eid:
                        bucket['per_sa_entities'][sa_label].add(eid)
            else:
                bucket['fail_count'] += 1
    
    print(f"\nProcessed {totals['lines']:,} total lines")
    print(f"Parsed JSON: {totals['parsed']:,} | Skipped: {totals['skipped']:,}")
    print(f"Response entries seen: {totals['responses']:,}")
    
    # Generate report
    print("\n" + "=" * 120)
    print("EPHEMERAL WORKLOAD ENTITY CHURN ANALYSIS")
    print("=" * 120)
    print(f"File: {log_file}")
    print(f"Successful K8s/OpenShift logins: {totals['k8s_ok']:,}")
    
    # 1. Per-mount summary with distributions
    print("\n1. CLUSTER SUMMARY")
    print("-" * 120)
    print(f"{'Cluster Auth Path':<50} {'Logins(OK)':<12} {'Fails':<8} {'Entities':<10} "
          f"{'SvcAccts':<10} {'Logins/Entity':<15} {'Entities/SvcAcct':<17}")
    print("-" * 120)
    
    rows = []
    for accessor, b in mounts.items():
        ok = b['ok_count']
        ents = len(b['entity_ids'])
        ent_ratio = (ok / ents) if ents else 0.0
        sa_cnt = len(b['per_sa_entities'])
        entities_per_sa = (ents / sa_cnt) if sa_cnt else 0.0
        rows.append((b['display_mount'], ok, b['fail_count'], ents, sa_cnt, 
                    round(ent_ratio, 1), round(entities_per_sa, 1)))
    
    rows.sort(key=lambda r: r[1], reverse=True)
    for r in rows:
        print(f"{r[0]:<50} {r[1]:<12,} {r[2]:<8,} {r[3]:<10,} {r[4]:<10,} "
              f"{r[5]:<15} {r[6]:<17}")
    
    # 2. Top entities by login count (chatty entities)
    print("\n2. TOP ENTITIES BY LOGIN COUNT (Chatty Identities)")
    print("-" * 120)
    
    global_entity_counts = Counter()
    entity_mount = {}
    for accessor, b in mounts.items():
        for eid, c in b['per_entity_logins'].items():
            global_entity_counts[eid] += c
            entity_mount[eid] = b['display_mount']
    
    for eid, c in global_entity_counts.most_common(TOP_N):
        flag = ' 🔴 **OFFENDER**' if c >= ENTITY_LOGIN_THRESHOLD else ''
        print(f"{eid}  logins={c:<8,}  mount={entity_mount.get(eid, '?')}{flag}")
    
    # 3. Top service accounts by distinct entities (ephemeral churn)
    print("\n3. TOP SERVICE ACCOUNTS BY DISTINCT ENTITIES (Ephemeral Churn)")
    print("-" * 120)
    
    global_sa_entities = defaultdict(set)
    global_sa_logins = Counter()
    
    for accessor, b in mounts.items():
        mlabel = b['display_mount']
        for sa, ents in b['per_sa_entities'].items():
            key = (mlabel, sa)
            global_sa_entities[key].update(ents)
        for sa, c in b['per_sa_logins'].items():
            key = (mlabel, sa)
            global_sa_logins[key] += c
    
    top_sa = sorted(global_sa_entities.items(), key=lambda kv: len(kv[1]), reverse=True)[:TOP_N]
    for (mount_label, sa_label), ents in top_sa:
        ent_n = len(ents)
        logins = global_sa_logins.get((mount_label, sa_label), 0)
        flag = ' 🔴 **OFFENDER**' if ent_n >= SA_ENTITY_THRESHOLD else ''
        print(f"{mount_label:<50} {sa_label:<40} distinct_entities={ent_n:<6,} "
              f"logins={logins:<8,}{flag}")
    
    # 4. Per-SA distribution diagnostics (singletons & p95)
    print("\n4. DISTRIBUTION DIAGNOSTICS (High-Signal Patterns Only)")
    print("-" * 120)
    
    diagnostic_count = 0
    for accessor, b in mounts.items():
        mlabel = b['display_mount']
        for sa, ents in b['per_sa_entities'].items():
            counts = [b['per_entity_logins'][eid] for eid in ents 
                     if eid in b['per_entity_logins']]
            if not counts:
                continue
            
            counts_sorted = sorted(counts)
            singletons = sum(1 for x in counts if x == 1)
            singleton_ratio = singletons / len(counts)
            
            # Calculate p95
            idx = max(0, min(len(counts_sorted) - 1, 
                           int(round(0.95 * (len(counts_sorted) - 1)))))
            p95 = counts_sorted[idx]
            
            # Flag only if noteworthy
            offenders = []
            if singleton_ratio >= SINGLETON_RATIO_THRESHOLD:
                offenders.append('SINGLETON_HEAVY')
            if p95 >= P95_LOGIN_THRESHOLD:
                offenders.append('HIGH_P95')
            
            if len(offenders) == 0:
                continue
            
            diagnostic_count += 1
            print(f"{mlabel:<50} {sa:<40} entities={len(counts):<6,} "
                  f"singletons={singletons:<6,} singleton_ratio={singleton_ratio:>5.1%} "
                  f"p95_logins/entity={p95:<5}  FLAGS={','.join(offenders)}")
    
    if diagnostic_count == 0:
        print("No high-signal distribution anomalies detected.")
    
    # 5. Interpretation guide
    print("\n5. INTERPRETATION GUIDE")
    print("-" * 120)
    print("📊 **Logins/Entity Ratio:**")
    print("   - Low (1-5): Healthy entity reuse, persistent identities")
    print("   - Medium (5-50): Mixed pattern, some churn")
    print("   - High (50-100): Significant churn, investigate")
    print("   - Critical (100+): Severe misconfiguration")
    print()
    print("🔍 **Top Entities by Login Count:**")
    print("   - Identifies 'chatty' entities repeatedly authenticating")
    print("   - Root causes: Token caching broken, short TTLs, authentication loops")
    print()
    print("⚠️  **Top Service Accounts by Distinct Entities:**")
    print("   - Identifies ephemeral entity churn (many entities per SA)")
    print("   - Root cause: Entity alias misconfiguration causing pod → new entity")
    print()
    print("🚨 **SINGLETON_HEAVY Flag:**")
    print("   - 80%+ of entities have exactly 1 login (disposable entities)")
    print("   - Strong indicator: Pods creating new entity on each restart")
    print("   - Fix: Set alias_name_source='serviceaccount_uid' in kubernetes auth config")
    print()
    print("🔄 **HIGH_P95 Flag:**")
    print("   - Top 5% of entities have 10+ logins")
    print("   - Indicates mixture of churn + high-frequency authentication")
    print("   - May compound with singleton issue")
    
    # 6. Thresholds and next steps
    print("\n6. CONFIGURATION")
    print("-" * 120)
    print(f"Thresholds: ENTITY_LOGIN_THRESHOLD={ENTITY_LOGIN_THRESHOLD}, "
          f"SA_ENTITY_THRESHOLD={SA_ENTITY_THRESHOLD}, "
          f"SINGLETON_RATIO_THRESHOLD={SINGLETON_RATIO_THRESHOLD:.0%}, "
          f"P95_LOGIN_THRESHOLD={P95_LOGIN_THRESHOLD}")
    
    print("\n" + "=" * 120)
    
    # Return summary data
    return {
        'total_logins': totals['k8s_ok'],
        'total_entities': len(set().union(*[b['entity_ids'] for b in mounts.values()])),
        'total_clusters': len(mounts),
        'total_service_accounts': len(global_sa_entities)
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze Kubernetes/OpenShift entity churn patterns from Vault audit logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python vault_audit_k8s_auth_analysis.py vault_audit.2025-10-07.log
  python vault_audit_k8s_auth_analysis.py vault_audit.2025-10-07.log.gz  # Supports .gz files
        '''
    )
    parser.add_argument('audit_log', help='Path to Vault audit log file (.log or .log.gz)')
    
    args = parser.parse_args()
    analyze_ephemeral_entity_churn(args.audit_log)
