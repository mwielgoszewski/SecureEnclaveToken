#!/bin/sh
# Creates only a new disposable key and an isolated local PKI. Does not change trust settings.
set -eu
umask 077
if [ "$#" -ne 2 ]; then
    echo 'Usage: prepare-mtls.sh EMPTY_FIXTURE_DIRECTORY NEW_KEY_TAG' >&2
    exit 64
fi
fixtures=$1
tag=$2
cli=${SETOKEN_CLI:-setoken}
mkdir -p "$fixtures"
fixtures=$(CDPATH= cd "$fixtures" && pwd)
if [ -n "$(ls -A "$fixtures")" ]; then
    echo 'Use an empty fixture directory.' >&2
    exit 1
fi
chmod 700 "$fixtures"
# new refuses to replace an existing key. Keep no-auth limited to this disposable test.
"$cli" new "$tag" --require none --available whenUnlocked
printf '%s' "$tag" > "$fixtures/key-tag"
"$cli" req "$tag" -cn 'Example Client' -o 'Example Organization' -c US > "$fixtures/client.csr"
cat > "$fixtures/ca.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = ca_ext
[dn]
CN = SecureEnclaveToken Local Test CA
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
cat > "$fixtures/server.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
[dn]
CN = localhost
EOF
cat > "$fixtures/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
cat > "$fixtures/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 2 -config "$fixtures/ca.cnf" -keyout "$fixtures/ca.key" -out "$fixtures/ca.pem"
openssl req -new -newkey rsa:2048 -nodes -sha256 -config "$fixtures/server.cnf" -keyout "$fixtures/server.key" -out "$fixtures/server.csr"
openssl x509 -req -in "$fixtures/server.csr" -CA "$fixtures/ca.pem" -CAkey "$fixtures/ca.key" -CAcreateserial -days 1 -sha256 -extfile "$fixtures/server.ext" -out "$fixtures/server.pem"
openssl x509 -req -in "$fixtures/client.csr" -CA "$fixtures/ca.pem" -CAkey "$fixtures/ca.key" -CAcreateserial -days 1 -sha256 -extfile "$fixtures/client.ext" -out "$fixtures/client.pem"
"$cli" token import "$tag" - < "$fixtures/client.pem"
openssl x509 -in "$fixtures/server.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A > "$fixtures/server-spki.txt"
printf '\nPrepared test fixtures in %s\n' "$fixtures"
printf 'Disposable key tag: %s (delete this key after the test, even if a later step fails)\n' "$tag"
