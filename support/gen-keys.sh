# This script is used to generate a simple private/public key-pair in `der` format.
mkdir -p "support/keys"
openssl genrsa -out "support/keys/private_key.pem" 2048

openssl rsa -in "support/keys/private_key.pem" -outform DER -out "support/keys/private_key.der"
openssl rsa -in "support/keys/private_key.der" -inform DER -RSAPublicKey_out -outform DER -out "support/keys/public_key.der"
