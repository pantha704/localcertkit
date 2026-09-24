#!/usr/bin/env bash
# Generate PKCS#12 test fixtures with OpenSSL 3.x
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p fixtures/pem

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

echo "== openssl: $($OPENSSL_BIN version)"

# ---------- modern RSA-2048 leaf (self-signed) ----------
$OPENSSL_BIN req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout fixtures/pem/modern-key.pem -out fixtures/pem/modern-cert.pem \
  -subj "/C=IN/ST=WB/L=Kolkata/O=CertKit Test/OU=Spike/CN=modern.certkit.test" \
  -addext "subjectAltName=DNS:modern.certkit.test,DNS:www.modern.certkit.test" 2>/dev/null

# (i) modern: AES-256-CBC for both key and cert
$OPENSSL_BIN pkcs12 -export -out fixtures/modern-aes256.p12 \
  -inkey fixtures/pem/modern-key.pem -in fixtures/pem/modern-cert.pem \
  -name "modern aes256" -passout pass:modernpass \
  -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# (ii) legacy: RC2-40 cert PBE + 3DES key PBE (needs legacy provider)
$OPENSSL_BIN pkcs12 -export -legacy -out fixtures/legacy-rc2-40.p12 \
  -inkey fixtures/pem/modern-key.pem -in fixtures/pem/modern-cert.pem \
  -name "legacy rc2-40" -passout pass:legacypass \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-RC2-40 -macalg sha1

# (ii-b) legacy: 3DES both sides (works without -legacy provider on openssl 3)
$OPENSSL_BIN pkcs12 -export -out fixtures/legacy-3des.p12 \
  -inkey fixtures/pem/modern-key.pem -in fixtures/pem/modern-cert.pem \
  -name "legacy 3des" -passout pass:legacypass \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1

# (iii) passwordless (empty password)
$OPENSSL_BIN pkcs12 -export -out fixtures/nopass.p12 \
  -inkey fixtures/pem/modern-key.pem -in fixtures/pem/modern-cert.pem \
  -name "nopass" -passout pass: -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# ---------- 4096-bit "typical 4KB" modern file ----------
$OPENSSL_BIN req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout fixtures/pem/big-key.pem -out fixtures/pem/big-cert.pem \
  -subj "/CN=big.certkit.test/O=CertKit Test" 2>/dev/null
$OPENSSL_BIN pkcs12 -export -out fixtures/modern-aes256-rsa4096.p12 \
  -inkey fixtures/pem/big-key.pem -in fixtures/pem/big-cert.pem \
  -name "big" -passout pass:bigpass -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# ---------- chain: root CA -> intermediate -> leaf ----------
for n in root inter leaf; do
  $OPENSSL_BIN req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout fixtures/pem/$n-key.pem -out fixtures/pem/$n-cert.pem \
    -subj "/CN=$n.certkit.test/O=CertKit Test" 2>/dev/null
done
# make a real root->intermediate relationship: self-signed root, intermediate CSR signed by root, leaf signed by intermediate
$OPENSSL_BIN req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout fixtures/pem/inter-key.pem -out fixtures/pem/inter.csr -subj "/CN=inter.certkit.test/O=CertKit Test" 2>/dev/null
$OPENSSL_BIN x509 -req -in fixtures/pem/inter.csr -CA fixtures/pem/root-cert.pem \
  -CAkey fixtures/pem/root-key.pem -CAcreateserial -days 3000 -sha256 \
  -out fixtures/pem/inter-cert.pem 2>/dev/null
$OPENSSL_BIN req -new -newkey rsa:2048 -sha256 -nodes \
  -keyout fixtures/pem/leaf-key.pem -out fixtures/pem/leaf.csr -subj "/CN=leaf.certkit.test/O=CertKit Test" 2>/dev/null
$OPENSSL_BIN x509 -req -in fixtures/pem/leaf.csr -CA fixtures/pem/inter-cert.pem \
  -CAkey fixtures/pem/inter-key.pem -CAcreateserial -days 825 -sha256 \
  -out fixtures/pem/leaf-cert.pem 2>/dev/null
cat fixtures/pem/leaf-cert.pem fixtures/pem/inter-cert.pem > fixtures/pem/chain.pem
$OPENSSL_BIN pkcs12 -export -out fixtures/chain-aes256.p12 \
  -inkey fixtures/pem/leaf-key.pem -in fixtures/pem/chain.pem \
  -name "leaf chain" -passout pass:chainpass \
  -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# ---------- EC P-256 modern (forge support check) ----------
$OPENSSL_BIN ecparam -name prime256v1 -genkey -noout -out fixtures/pem/ec-key.pem
$OPENSSL_BIN req -x509 -key fixtures/pem/ec-key.pem -sha256 -days 825 \
  -out fixtures/pem/ec-cert.pem -subj "/CN=ec.certkit.test/O=CertKit Test" 2>/dev/null
$OPENSSL_BIN pkcs12 -export -out fixtures/ec-p256-aes256.p12 \
  -inkey fixtures/pem/ec-key.pem -in fixtures/pem/ec-cert.pem \
  -name "ec p256" -passout pass:ecpass -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# ---------- no-MAC PKCS#12 (some tools export this) ----------
$OPENSSL_BIN pkcs12 -export -nomac -out fixtures/nomac.p12 \
  -inkey fixtures/pem/modern-key.pem -in fixtures/pem/modern-cert.pem \
  -name "nomac" -passout pass:nomacpass -keypbe AES-256-CBC -certpbe AES-256-CBC

# ---------- diagnostic: RSA key + EC certificate (mixed, should fail on EC cert) ----------
$OPENSSL_BIN pkcs12 -export -out fixtures/mixed-rsa-key-ec-cert.p12 \
  -inkey fixtures/pem/modern-key.pem -in fixtures/pem/ec-cert.pem \
  -name "mixed" -passout pass:mixedpass -keypbe AES-256-CBC -certpbe AES-256-CBC 2>/dev/null || \
  echo "WARN: mixed fixture export failed (openssl refused key/cert mismatch)"

# ---------- inspect with openssl for a ground-truth record ----------
{
  for spec in "modern-aes256.p12:modernpass" "legacy-3des.p12:legacypass" "legacy-rc2-40.p12:legacypass" \
              "nopass.p12:" "nomac.p12:nomacpass" "chain-aes256.p12:chainpass" \
              "modern-aes256-rsa4096.p12:bigpass" "ec-p256-aes256.p12:ecpass"; do
    f="${spec%%:*}"; pw="${spec#*:}"
    echo "### $f"
    $OPENSSL_BIN pkcs12 -in "fixtures/$f" -passin "pass:$pw" -info -noout 2>&1 | \
      grep -Ei "MAC|Encrypted|Keybag|Iteration|Error" | head -10
  done
} > fixtures/openssl-inspect.txt 2>&1

for f in fixtures/*.p12; do
  echo "== $f ($(stat -c%s "$f") bytes)"
done
echo "OK fixtures generated"
