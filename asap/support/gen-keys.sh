# This script is used to generate a simple private/public key-pair in `der` format.
function gen_keys() {
  service=$1;
  key_id=$2;

  mkdir -p "support/keys/$service";
  openssl genrsa -out "support/keys/$service/$key_id-private.pem" 2048;

  openssl rsa -in "support/keys/$service/$key_id-private.pem" -outform DER -out "support/keys/$service/$key_id-private.der";
  openssl rsa -in "support/keys/$service/$key_id-private.der" -inform DER -RSAPublicKey_out -outform DER -out "support/keys/$service/$key_id-public.der";
}

gen_keys "service01" "$(date +%s)"
gen_keys "service02" "$(date +%s)"
