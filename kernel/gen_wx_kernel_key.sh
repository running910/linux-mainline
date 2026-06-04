#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

if [ "$#" -ne 3 ]; then
	echo "usage: $0 <input-pem> <scratch-der> <output-c>" >&2
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

seed_hex=$(openssl rand -hex 4)
openssl rsa -in "$input_pem" -traditional -outform DER -out "$tmp_der"

{
	echo "/* SPDX-License-Identifier: GPL-2.0 */"
	echo "#include <linux/types.h>"
	echo
	od -An -v -tu1 "$tmp_der" | awk -v seed_hex="$seed_hex" '
	function gcd(a, b, t) {
		while (b) {
			t = a % b;
			a = b;
			b = t;
		}
		return a;
	}
	function hex_digit(c) {
		c = tolower(c);
		if (c >= "0" && c <= "9")
			return c + 0;
		return index("abcdef", c) + 9;
	}
	function hex_to_u32(s, i, v) {
		v = 0;
		for (i = 1; i <= length(s); i++)
			v = (v * 16) + hex_digit(substr(s, i, 1));
		return v;
	}
	function mask(seed, idx, x, shift) {
		x = (seed + (idx * 1103515245) + ((idx + 1) * (idx + 17) * 97)) % 4294967296;
		shift = 1;
		if (idx % 4 == 1)
			shift = 256;
		else if (idx % 4 == 2)
			shift = 65536;
		else if (idx % 4 == 3)
			shift = 16777216;
		return int(x / shift) % 256;
	}
	{
		for (i = 1; i <= NF; i++)
			key[n++] = $i;
	}
	END {
		seed = hex_to_u32(seed_hex);
		stride = 257;
		while (gcd(stride, n) != 1)
			stride += 2;
		offset = (seed % n);

		for (i = 0; i < n; i++) {
			pos = (i * stride + offset) % n;
			blob[pos] = xor_byte(key[i], mask(seed, i), i);
		}

		print "const u8 wx_kernel_attest_blob[] = {";
		for (i = 0; i < n; i++) {
			if (i % 12 == 0)
				printf "\t";
			printf "0x%02x", blob[i];
			if (i + 1 < n)
				printf ",";
			if (i % 12 == 11 || i + 1 == n)
				printf "\n";
			else
				printf " ";
		}
		print "};";
		print "const unsigned int wx_kernel_attest_blob_len = " n ";";
		printf "const u32 wx_kernel_attest_blob_seed = 0x%s;\n", seed_hex;
		print "const unsigned int wx_kernel_attest_blob_stride = " stride ";";
		print "const unsigned int wx_kernel_attest_blob_offset = " offset ";";
	}
	function xor_byte(v, m, idx) {
		return xor8(xor8(v, m), ((idx * 31) + 165) % 256);
	}
	function xor8(a, b, r, bit, av, bv) {
		r = 0;
		for (bit = 1; bit < 256; bit *= 2) {
			av = int(a / bit) % 2;
			bv = int(b / bit) % 2;
			if (av != bv)
				r += bit;
		}
		return r;
	}'
} > "$tmp_c"

mv "$tmp_c" "$output_c"
rm -f "$tmp_der" "$output_der"
