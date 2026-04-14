#!/bin/bash
set -e

# Setup script to create test auth mounts with roles and users
# Requires VAULT_ADDR and VAULT_TOKEN to be set
# This demonstrates the maximum depth for auth mounts (mount → roles/users)

echo "Setting up test auth mounts in Vault..."
echo "Vault Address: ${VAULT_ADDR:-http://127.0.0.1:8200}"

# Enable userpass auth
echo ""
echo "=== Setting up userpass auth ==="
vault auth enable -path=userpass-test userpass 2>/dev/null || echo "userpass-test already enabled"

# Create userpass users with varying policies and TTLs
vault write auth/userpass-test/users/alice \
    password=alice123 \
    policies=default,admin,security-audit \
    token_ttl=1h \
    token_max_ttl=24h

vault write auth/userpass-test/users/bob \
    password=bob123 \
    policies=default,read-only \
    token_ttl=30m \
    token_max_ttl=8h

vault write auth/userpass-test/users/charlie \
    password=charlie123 \
    policies=default,developer,database-write \
    token_ttl=2h \
    token_max_ttl=12h

vault write auth/userpass-test/users/diana \
    password=diana123 \
    policies=default,ops,monitoring \
    token_ttl=4h \
    token_max_ttl=24h

echo "Created 4 userpass users: alice, bob, charlie, diana"

# Enable approle auth
echo ""
echo "=== Setting up approle auth ==="
vault auth enable -path=approle-test approle 2>/dev/null || echo "approle-test already enabled"

# Create approle roles with different configurations
vault write auth/approle-test/role/web-app \
    token_policies=default,web-policy,cache-read \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true \
    secret_id_ttl=24h \
    token_num_uses=0

vault write auth/approle-test/role/api-service \
    token_policies=default,api-policy,database-read \
    token_ttl=30m \
    token_max_ttl=2h \
    bind_secret_id=true \
    secret_id_ttl=12h \
    token_num_uses=10

vault write auth/approle-test/role/batch-job \
    token_policies=default,batch-policy \
    token_ttl=15m \
    token_max_ttl=1h \
    bind_secret_id=true \
    secret_id_ttl=6h \
    token_num_uses=1

vault write auth/approle-test/role/ci-cd-pipeline \
    token_policies=default,deployment,secrets-read \
    token_ttl=20m \
    token_max_ttl=1h \
    bind_secret_id=true \
    secret_id_ttl=8h \
    token_num_uses=5

vault write auth/approle-test/role/monitoring-agent \
    token_policies=default,metrics-read,logs-read \
    token_ttl=6h \
    token_max_ttl=48h \
    bind_secret_id=false

echo "Created 5 approle roles: web-app, api-service, batch-job, ci-cd-pipeline, monitoring-agent"

# Enable kubernetes auth (if not already enabled)
echo ""
echo "=== Setting up kubernetes auth ==="
vault auth enable -path=kubernetes-test kubernetes 2>/dev/null || echo "kubernetes-test already enabled"

# Configure kubernetes auth (using dummy config for testing)
vault write auth/kubernetes-test/config \
    kubernetes_host="https://kubernetes.default.svc:443" \
    disable_local_ca_jwt=true 2>/dev/null || echo "kubernetes-test config already set"

# Create kubernetes roles with service account bindings
vault write auth/kubernetes-test/role/frontend \
    bound_service_account_names=frontend-sa,web-sa \
    bound_service_account_namespaces=production,staging \
    policies=default,frontend-policy,cdn-access \
    token_ttl=1h \
    token_max_ttl=8h

vault write auth/kubernetes-test/role/backend \
    bound_service_account_names=backend-sa,api-sa,worker-sa \
    bound_service_account_namespaces=production \
    policies=default,backend-policy,database-read,cache-write \
    token_ttl=2h \
    token_max_ttl=12h

vault write auth/kubernetes-test/role/monitoring \
    bound_service_account_names=prometheus-sa,grafana-sa,alertmanager-sa \
    bound_service_account_namespaces=monitoring,default,kube-system \
    policies=default,metrics-read,alerts-write \
    token_ttl=4h \
    token_max_ttl=24h

vault write auth/kubernetes-test/role/data-pipeline \
    bound_service_account_names=spark-sa,airflow-sa \
    bound_service_account_namespaces=data-platform \
    policies=default,data-read,data-write,s3-access \
    token_ttl=3h \
    token_max_ttl=16h

vault write auth/kubernetes-test/role/admin-tools \
    bound_service_account_names=kubectl-sa,helm-sa \
    bound_service_account_namespaces=admin,ops \
    policies=default,admin,cluster-admin \
    token_ttl=30m \
    token_max_ttl=4h

echo "Created 5 kubernetes roles: frontend, backend, monitoring, data-pipeline, admin-tools"

# Enable JWT/OIDC auth
echo ""
echo "=== Setting up JWT auth ==="
vault auth enable -path=jwt-test jwt 2>/dev/null || echo "jwt-test already enabled"

# Configure JWT auth (using dummy config for testing)
vault write auth/jwt-test/config \
    oidc_discovery_url="https://example.com" \
    default_role="default-jwt" 2>/dev/null || echo "jwt-test config already set"

# Create JWT roles for CI/CD systems
vault write auth/jwt-test/role/github-actions \
    role_type=jwt \
    bound_audiences=vault,github \
    user_claim=sub \
    policies=default,ci-cd-policy,deploy-prod \
    token_ttl=15m \
    token_max_ttl=30m

vault write auth/jwt-test/role/gitlab-ci \
    role_type=jwt \
    bound_audiences=vault,gitlab \
    user_claim=sub \
    policies=default,deployment-policy,secrets-read \
    token_ttl=20m \
    token_max_ttl=1h

vault write auth/jwt-test/role/jenkins \
    role_type=jwt \
    bound_audiences=vault,jenkins \
    user_claim=sub \
    policies=default,build-policy,artifact-write \
    token_ttl=10m \
    token_max_ttl=45m

echo "Created 3 JWT roles: github-actions, gitlab-ci, jenkins"

# Enable LDAP auth
echo ""
echo "=== Setting up LDAP auth ==="
vault auth enable -path=ldap-test ldap 2>/dev/null || echo "ldap-test already enabled"

# Configure LDAP (dummy config)
vault write auth/ldap-test/config \
    url="ldap://ldap.example.com" \
    userdn="ou=users,dc=example,dc=com" \
    groupdn="ou=groups,dc=example,dc=com" 2>/dev/null || echo "ldap-test config already set"

echo "LDAP auth enabled (users/groups would be managed in LDAP server)"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Auth mounts created with maximum depth (mount → roles/users):"
echo "  - userpass-test/ (4 users with policies and TTLs)"
echo "  - approle-test/ (5 roles with varying configurations)"
echo "  - kubernetes-test/ (5 roles with service account bindings)"
echo "  - jwt-test/ (3 roles for CI/CD systems)"
echo "  - ldap-test/ (configured, users managed externally)"
echo ""
echo "Test the auth-mounts command:"
echo "  vault-audit auth-mounts --depth=0  # Mounts only (no API calls)"
echo "  vault-audit auth-mounts --depth=1  # Mounts + roles with full metadata"
echo ""
echo "Example with specific mount:"
echo "  vault-audit auth-mounts --depth=1 --format=json -o auth-mounts.json"

# Made with Bob
