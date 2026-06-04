#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

if [ "$#" -ne 3 ]; then
	echo "usage: $0 <input-pem> <output-der> <output-c>" >&2
	exit 1
fi

input_pem=$1
output_der=$2
output_c=$3
tmp_der=${output_der}.tmp
tmp_c=${output_c}.tmp

if [ ! -f "$input_pem" ]; then
	echo "error: missing kernel attest private key PEM: $input_pem" >&2
	exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
	echo "error: openssl not found in PATH" >&2
	exit 1
fi

if ! command -v xxd >/dev/null 2>&1; then
	echo "error: xxd not found in PATH" >&2
	exit 1
fi

openssl rsa -in "$input_pem" -traditional -outform DER -out "$tmp_der"

{
	echo "/* SPDX-License-Identifier: GPL-2.0 */"
	echo "#include <linux/types.h>"
	echo
	xxd -i "$tmp_der" | sed \
		-e 's/^unsigned char .*\[\] = {/const u8 wx_rsa_priv_key_der[] = {/' \
		-e 's/^unsigned int .*_len = /const unsigned int wx_rsa_priv_key_der_len = /'
} > "$tmp_c"

mv "$tmp_der" "$output_der"
mv "$tmp_c" "$output_c"
