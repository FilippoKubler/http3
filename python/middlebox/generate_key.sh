#!/bin/bash

set -e

cd ./certs

echo "Generating CA key and certificate:"
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 \
  -keyout ca.key -out ca.pem \
  -subj "/O=http3-server Certificate Authority/"

echo "Generating CSR"
openssl req -out cert.csr -new -newkey rsa:2048 -nodes -keyout priv.key \
  -subj "/O=http3-server/"

echo "Sign certificate:"
openssl x509 -req -sha256 -days 3650 -in cert.csr  -out cert.pem \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -extfile <(printf "subjectAltName=IP:192.168.1.123")

# debug output the certificate
openssl x509 -noout -text -in cert.pem

# we don't need the CA key, the serial number and the CSR any more
rm ca.key cert.csr ca.srl
