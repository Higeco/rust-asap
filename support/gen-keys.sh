# This script is used to generate a simple private/public key-pair in `der` format.
function gen_keys() {
  key_name=$1;
  openssl genrsa -out "support/keys/$key_name-private.pem" 2048;

  openssl rsa -in "support/keys/$key_name-private.pem" -outform DER -out "support/keys/$key_name-private.der";
  openssl rsa -in "support/keys/$key_name-private.der" -inform DER -RSAPublicKey_out -outform DER -out "support/keys/$key_name-public.der";
}

mkdir -p "support/keys";

gen_keys "01"
gen_keys "02"
