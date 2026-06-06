#!/bin/sh
# deploy/vault-seed.sh
# Seeds HashiCorp Vault with real SSH keys and AppRole credentials for ZTTP dev environment.
# Called by the vault-seed Docker Compose service after Vault is healthy.
#
# In production: replace the generated keys here with the actual server host keys,
# or use a secrets management pipeline to push them from your PKI.
set -e
set -x

export VAULT_SKIP_VERIFY=true

echo "==> Enabling KV v2 secrets engine..."
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "(already enabled)"

echo "==> Generating and seeding SSH keys for all servers..."

for server in dev-app-01 dev-db-01 stage-web-01 stage-db-01 prod-app-01 prod-db-01; do
    # Generate a real 4096-bit RSA key pair in memory (no passphrase)
    # In production, these would come from your CA/PKI, not generated here.
    tmpkey="/tmp/zttp_${server}_key"
    ssh-keygen -t rsa -b 4096 -f "$tmpkey" -N "" -q 2>/dev/null

    PRIVATE_KEY=$(cat "$tmpkey")
    FINGERPRINT=$(ssh-keygen -lf "${tmpkey}.pub" -E sha256 | awk '{print $2}')

    vault kv put "secret/ssh/${server}" \
        private_key="$PRIVATE_KEY" \
        fingerprint="$FINGERPRINT"

    # Secure delete the temp files
    rm -f "$tmpkey" "${tmpkey}.pub"

    echo "  ✓ Seeded: $server (fingerprint: $FINGERPRINT)"
done

echo ""
echo "==> Enabling AppRole auth method..."
vault auth enable approle 2>/dev/null || echo "(already enabled)"

echo "==> Writing ZTTP proxy policy (read-only on ssh/*)..."
vault policy write zttp-proxy-policy - <<'POLICY'
path "secret/data/ssh/*" {
  capabilities = ["read"]
}
path "secret/metadata/ssh/*" {
  capabilities = ["list", "read"]
}
POLICY

echo "==> Creating AppRole for zttp-proxy..."
vault write auth/approle/role/zttp-proxy \
    token_policies="zttp-proxy-policy" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0  # non-expiring for dev

ROLE_ID=$(vault read -field=role_id auth/approle/role/zttp-proxy/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/zttp-proxy/secret-id)

echo ""
echo "=========================================="
echo "  VAULT SEEDING COMPLETE"
echo "  VAULT_ROLE_ID:   $ROLE_ID"
echo "  VAULT_SECRET_ID: $SECRET_ID"
echo "  (Save these as env vars for AppRole auth)"
echo "=========================================="
