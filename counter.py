#!/usr/bin/env python3
"""
Vault recursive client count & usage reporter.

Features:
- Recursively enumerate namespaces (Enterprise). Falls back to single root namespace on OSS or when listing is disallowed.
- Collect auth mounts (path, type, accessor).
- Query activity counters for a date window (Enterprise) and aggregate unique client counts per auth mount accessor.
- Optional: export identity entities/aliases (for offline app/env mapping).

Outputs:
- vault_client_counts_by_auth.csv
- vault_identity_alias_export.csv (only if --include-entities)
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timedelta, timezone
import requests

try:
    import hvac
except ImportError:
    print("Please install hvac:  pip install hvac", file=sys.stderr)
    sys.exit(1)

# ---------- Helpers ----------

def iso(dt: datetime) -> str:
    # RFC3339/ISO8601 with 'Z'
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def list_namespaces(client, ns_path=""):
    """
    Recursively list namespaces (Enterprise).
    Returns list of namespace strings suitable for X-Vault-Namespace ('' for root).
    """
    namespaces = []

    def _list_under(prefix):
        # LIST sys/namespaces/<prefix>  (prefix '' means top)
        path = "sys/namespaces"
        if prefix:
            path = f"{path}/{prefix.strip('/')}"
        try:
            resp = client.adapter.list(path)  # hvac sends LIST
            keys = resp.get("data", {}).get("keys", []) if resp else []
        except Exception:
            # Not Enterprise or no permission
            return []
        return keys

    def _recurse(prefix):
        children = _list_under(prefix)
        if not children:
            return
        for k in children:
            # Keys may include trailing '/' to indicate folder
            full = f"{prefix}/{k}".strip("/")
            namespaces.append(full)
            # Recurse if folder-like
            if k.endswith("/"):
                _recurse(full)

    # Try to list top-level; if it fails, we’re likely OSS or no perms
    try:
        top = _list_under("")
    except Exception:
        top = []

    if top:
        # Root itself is a valid namespace
        all_ns = ['']  # include root
        _recurse("")
        # Clean trailing slashes
        all_ns.extend([ns.rstrip('/') for ns in namespaces if ns != '/'])
        # Deduplicate
        uniq = []
        for n in all_ns:
            if n not in uniq:
                uniq.append(n)
        return uniq
    else:
        # Fall back to root only
        return ['']

def get_auth_mounts(client):
    """
    Returns tuple: (mounts_by_accessor, mounts_by_path)
    - mounts_by_accessor: dict accessor -> { 'path': 'oidc/', 'type': 'oidc' }
    - mounts_by_path: dict 'auth/oidc/' -> accessor (for mapping activity data)
    Uses a requests.Session (constructed in main) to call the Vault API directly to avoid hvac adapter/UI issues.
    Expects client to be a tuple (session, base_url, debug) when called from main.
    """
    mounts_by_accessor = {}
    mounts_by_path = {}
    debug = False
    try:
        session, base_url, debug = client
        url = f"{base_url.rstrip('/')}/v1/sys/auth"
        r = session.get(url, timeout=15)
        if r is None or r.status_code >= 400:
            if debug:
                print(f"[DEBUG] GET {url} status={getattr(r,'status_code',None)} body={repr(getattr(r,'text',None))}", file=sys.stderr)
            return {}, {}
        payload = r.json() or {}
        data = payload.get("data", {})
        for path, cfg in data.items():
            acc = cfg.get("accessor")
            typ = cfg.get("type")
            if acc:
                mounts_by_accessor[acc] = {"path": path, "type": typ}
                # Normalize path for activity mapping (Enterprise uses auth/mount/ format)
                normalized_path = f"auth/{path.rstrip('/')}/" if not path.startswith("auth/") else path.rstrip("/") + "/"
                mounts_by_path[normalized_path] = acc
    except Exception:
        try:
            if debug:
                import traceback
                traceback.print_exc(file=sys.stderr)
        except Exception:
            pass
        return {}, {}
    return mounts_by_accessor, mounts_by_path

def get_activity_by_accessor(client, start_time, end_time, granularity="daily", mounts_by_path=None):
    """
    Calls sys/internal/counters/activity and aggregates unique client counts by accessor.
    Returns dict accessor -> unique_client_count (sum over returned buckets).
    If the endpoint is unavailable (OSS), returns {}.
    
    mounts_by_path: dict of mount_path -> accessor for mapping mount_path to accessor
    
    Note: Enterprise may ignore start_time/end_time if they don't align with billing periods.
    For current billing period data, we query without date params.
    """
    debug = False
    try:
        session, base_url, debug = client
        url = f"{base_url.rstrip('/')}/v1/sys/internal/counters/activity"
        # Query without date params to get current billing period (Enterprise often ignores custom dates)
        resp = session.get(url, timeout=20)
        if resp is None or resp.status_code >= 400:
            if debug:
                try:
                    print(f"[DEBUG] GET {url} status={getattr(resp,'status_code',None)} body={repr(getattr(resp,'text',None))}", file=sys.stderr)
                except Exception:
                    pass
            return {}
        payload = resp.json() or {}
        data = payload.get("data", {})
        agg = {}
        
        # Try legacy by_accessor format first
        by_accessor = data.get("by_accessor") or data.get("accessors") or []
        for row in by_accessor:
            acc = row.get("accessor")
            cnt = row.get("client_count") or row.get("count") or 0
            if not acc:
                continue
            agg[acc] = agg.get(acc, 0) + int(cnt)
        
        # Try buckets format
        if not agg and "buckets" in data:
            for bucket in data["buckets"]:
                for row in bucket.get("by_accessor", []):
                    acc = row.get("accessor")
                    cnt = row.get("client_count") or row.get("count") or 0
                    if acc:
                        agg[acc] = agg.get(acc, 0) + int(cnt)
        
        # Try Enterprise format: by_namespace -> mounts (uses mount_path, not accessor)
        if not agg and "by_namespace" in data:
            for ns in data.get("by_namespace", []):
                for mount in ns.get("mounts", []):
                    mount_path = mount.get("mount_path", "").rstrip("/") + "/"
                    cnt = mount.get("counts", {}).get("clients", 0)
                    # Map mount_path to accessor if we have the mapping
                    if mounts_by_path and mount_path in mounts_by_path:
                        acc = mounts_by_path[mount_path]
                        agg[acc] = agg.get(acc, 0) + int(cnt)
        
        # Also try months -> namespaces -> mounts format
        if not agg and "months" in data:
            for month in data.get("months", []):
                for ns in month.get("namespaces", []):
                    for mount in ns.get("mounts", []):
                        mount_path = mount.get("mount_path", "").rstrip("/") + "/"
                        cnt = mount.get("counts", {}).get("clients", 0)
                        if mounts_by_path and mount_path in mounts_by_path:
                            acc = mounts_by_path[mount_path]
                            agg[acc] = agg.get(acc, 0) + int(cnt)
        
        return agg
    except Exception:
        # Likely OSS or insufficient perms
        try:
            if debug:
                import traceback
                traceback.print_exc(file=sys.stderr)
        except Exception:
            pass
        return {}

def list_entities_and_aliases(client, page_size=200):
    """
    Returns list of dicts with entity_id, entity_name, alias_id, alias_name, alias_mount_accessor, alias_metadata
    Uses LIST identity/entity/id (paged via 'list=true' + after key).
    """
    out = []
    base = "identity/entity/id"
    # Paging via 'list=true' with marker 'after' is supported on newer versions;
    # if not available, we’ll best-effort.
    # First list:
    next_key = None
    debug = False
    while True:
        params = {"list": "true"}
        if next_key:
            params["after"] = next_key
        try:
            session, base_url, debug = client
            url = f"{base_url.rstrip('/')}/v1/{base}"
            resp = session.get(url, params=params, timeout=15)
            if resp is None or resp.status_code >= 400:
                if debug:
                    try:
                        print(f"[DEBUG] LIST {url} status={getattr(resp,'status_code',None)} body={repr(getattr(resp,'text',None))}", file=sys.stderr)
                    except Exception:
                        pass
                break
            keys = resp.json().get("data", {}).get("keys", [])
            if not keys:
                break
            for eid in keys:
                # Read entity
                er = session.get(f"{base_url.rstrip('/')}/v1/{base}/{eid}", timeout=10)
                e = er.json().get("data", {}) if er is not None else {}
                ent_id = e.get("id")
                ent_name = e.get("name")
                aliases = e.get("aliases", []) or []
                for a in aliases:
                    out.append({
                        "entity_id": ent_id,
                        "entity_name": ent_name,
                        "alias_id": a.get("id"),
                        "alias_name": a.get("name"),
                        "alias_mount_accessor": a.get("mount_accessor"),
                        "alias_metadata": json.dumps(a.get("metadata") or {}, separators=(',', ':'))
                    })
            # Advance paging
            if len(keys) < page_size:
                break
            next_key = keys[-1]
        except Exception:
            break
    return out


def set_namespace_header(client, ns: str | None):
    """
    Safely set or clear the X-Vault-Namespace header for different hvac versions.
    Tries client.set_namespace(ns) if available; otherwise sets header on adapter.session
    or adapter._session if present.
    """
    # Prefer documented API if present
    try:
        if hasattr(client, "set_namespace") and callable(getattr(client, "set_namespace")):
            # hvac v1.4+ exposes set_namespace
            client.set_namespace(ns if ns else None)
            return
    except Exception:
        # Fall through to manual header set
        pass

    # Fallback: set header on adapter session object (different hvac versions expose 'session' or '_session')
    try:
        sess = None
        if hasattr(client, "adapter"):
            adapter = client.adapter
            # prefer public attribute
            if hasattr(adapter, "session"):
                sess = adapter.session
            elif hasattr(adapter, "_session"):
                sess = adapter._session

        if sess is not None and hasattr(sess, "headers"):
            if ns:
                sess.headers["X-Vault-Namespace"] = ns
            else:
                sess.headers.pop("X-Vault-Namespace", None)
            return
    except Exception:
        # give up silently; the caller will still try operations which may fail clearly
        return

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(description="Vault client count & auth usage reporter (recursive across namespaces).")
    ap.add_argument("--addr", default=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"), help="Vault address (default: env VAULT_ADDR or http://127.0.0.1:8200)")
    ap.add_argument("--token", default=os.getenv("VAULT_TOKEN"), help="Vault token (default: env VAULT_TOKEN)")
    ap.add_argument("--verify", default=os.getenv("VAULT_CACERT") or os.getenv("VAULT_SKIP_VERIFY") not in ("1", "true", "TRUE", "True"), action="store_true",
                    help="Verify TLS cert (default: True unless VAULT_SKIP_VERIFY is set). Use --no-verify to disable.")
    ap.add_argument("--no-verify", dest="verify", action="store_false")
    ap.add_argument("--days", type=int, default=30, help="Window size for activity counters (Enterprise). Default: 30")
    ap.add_argument("--granularity", choices=["hourly","daily","monthly"], default="daily", help="Aggregation granularity. Default: daily")
    ap.add_argument("--include-entities", action="store_true", help="Also export identity entities/aliases to CSV")
    ap.add_argument("--namespace", action="append", default=None,
                    help="Limit to specific namespace(s). Can be repeated. If omitted, will attempt to enumerate all (Enterprise) or use root.")
    ap.add_argument("--debug", action="store_true", help="Enable verbose HTTP debug output to stderr")
    args = ap.parse_args()

    if not args.token:
        print("Error: provide a token via --token or VAULT_TOKEN.", file=sys.stderr)
        sys.exit(2)

    client = hvac.Client(url=args.addr, token=args.token, verify=args.verify)
    DEBUG = bool(args.debug)

    # Create a requests session for direct API calls (avoids hvac adapter routing to UI)
    session = requests.Session()
    session.headers.update({"X-Vault-Token": args.token})
    session.verify = args.verify
    api_client = (session, args.addr, DEBUG)

    # Determine namespaces
    if args.namespace:
        namespaces = [n.strip("/") for n in args.namespace]
    else:
        namespaces = list_namespaces(client)

    # Time window: compute per-namespace right before calling the activity API so the end time is 'now'
    # (previous behavior computed a single end_time at script start)

    # Output CSVs
    auth_csv = open("vault_client_counts_by_auth.csv", "w", newline="", encoding="utf-8")
    auth_writer = csv.writer(auth_csv)
    auth_writer.writerow(["namespace", "auth_accessor", "auth_path", "auth_type", "unique_clients_in_window", "window_start_utc", "window_end_utc", "granularity"])

    # Use correct attribute name (argparse dest uses underscore)
    ent_csv = None
    if args.include_entities:
        ent_csv = open("vault_identity_alias_export.csv", "w", newline="", encoding="utf-8")
        ent_writer = csv.writer(ent_csv)
        ent_writer.writerow(["namespace", "entity_id", "entity_name", "alias_id", "alias_name", "alias_mount_accessor", "alias_metadata"])
    else:
        ent_writer = None

    for ns in namespaces:
        # Switch namespace via header
        # hvac supports set_namespace on client in newer versions; we’ll set per-request with a cloned adapter header.
        # Easiest: set client.namespace property if available; otherwise add header on adapter (works in hvac>=1.0).
        # Set namespace/header in a way compatible with different hvac versions
        # Set namespace on both hvac client (for backwards compat) and the requests session used for API calls
        try:
            set_namespace_header(client, ns if ns else None)
        except Exception:
            pass
        # set on session
        if ns:
            session.headers["X-Vault-Namespace"] = ns
        else:
            session.headers.pop("X-Vault-Namespace", None)

        # Get auth mounts (returns tuple: by_accessor, by_path)
        try:
            mounts, mounts_by_path = get_auth_mounts(api_client)
        except Exception as e:
            print(f"[WARN] Failed to read sys/auth in ns '{ns}': {e}", file=sys.stderr)
            mounts, mounts_by_path = {}, {}

        # Time window for this namespace (end is now)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=args.days)

        # Get activity counts by accessor (Enterprise)
        counts = get_activity_by_accessor(api_client, start_time, end_time, granularity=args.granularity, mounts_by_path=mounts_by_path)

        if not counts:
            # Still write zero counts for visibility
            for acc, meta in mounts.items():
                auth_writer.writerow([ns or "", acc, meta.get("path"), meta.get("type"), 0, iso(start_time), iso(end_time), args.granularity])
        else:
            for acc, total in counts.items():
                meta = mounts.get(acc, {"path": "", "type": ""})
                auth_writer.writerow([ns or "", acc, meta.get("path"), meta.get("type"), total, iso(start_time), iso(end_time), args.granularity])

            # Also record mounts that had zero activity in window
            for acc, meta in mounts.items():
                if acc not in counts:
                    auth_writer.writerow([ns or "", acc, meta.get("path"), meta.get("type"), 0, iso(start_time), iso(end_time), args.granularity])

        # Optional: export entities/aliases for offline mapping (app/env tags etc.)
        if ent_writer:
            try:
                rows = list_entities_and_aliases(api_client)
                for r in rows:
                    ent_writer.writerow([ns or "", r["entity_id"], r["entity_name"], r["alias_id"], r["alias_name"], r["alias_mount_accessor"], r["alias_metadata"]])
            except Exception as e:
                print(f"[WARN] Failed to export identity in ns '{ns}': {e}", file=sys.stderr)

    # Ensure files are closed (they were opened above). Using explicit close to preserve behavior.
    try:
        auth_csv.close()
    except Exception:
        pass
    if ent_writer and ent_csv is not None:
        try:
            ent_csv.close()
        except Exception:
            pass

    print("Done.")
    print("• vault_client_counts_by_auth.csv")
    if args.include_entities:
        print("• vault_identity_alias_export.csv")
    print("Tip: Join alias_mount_accessor (from alias export) to auth_accessor (from counts) to map aliases/entities to mounts. "
          "If your alias/entity metadata includes app/env tags, you can pivot by app/env.")

if __name__ == "__main__":
    main()
