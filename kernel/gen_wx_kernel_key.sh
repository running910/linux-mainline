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
salt_hex=$(openssl rand -hex 8)
openssl rsa -in "$input_pem" -traditional -outform DER -out "$tmp_der"

{
	echo "/* SPDX-License-Identifier: GPL-2.0 */"
	echo "#include <linux/types.h>"
	echo
	od -An -v -tu1 "$tmp_der" | awk -v seed_hex="$seed_hex" \
		-v salt_hex="$salt_hex" '
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
	function hex_byte(s, idx) {
		return hex_digit(substr(s, idx * 2 + 1, 1)) * 16 + \
		       hex_digit(substr(s, idx * 2 + 2, 1));
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
	function emit_array(name, values, len, i) {
		print "const u8 " name "[] = {";
		for (i = 0; i < len; i++) {
			if (i % 12 == 0)
				printf "\t";
			printf "0x%02x", values[i];
			if (i + 1 < len)
				printf ",";
			if (i % 12 == 11 || i + 1 == len)
				printf "\n";
			else
				printf " ";
		}
		print "};";
	}
	{
		for (i = 1; i <= NF; i++)
			key[n++] = $i;
	}
	END {
		seed = hex_to_u32(seed_hex);
		for (i = 0; i < 8; i++)
			salt[i] = hex_byte(salt_hex, i);

		stride = 257 + (seed % 509);
		if (stride % 2 == 0)
			stride++;
		while (gcd(stride, n) != 1)
			stride += 2;
		offset = (int(seed / 65536) % n);

		for (slot = 0; slot < n; slot++) {
			idx = (slot * stride + offset) % n;
			part = (slot + mask(seed, idx) + salt[slot % 8]) % 16;
			part_idx = part_len[part]++;
			encoded = key[idx];
			encoded = xor8(encoded, mask(seed, idx));
			encoded = xor8(encoded, ((idx * 31) + 165) % 256);
			encoded = xor8(encoded, ((slot * 17) + salt[(idx + slot) % 8]) % 256);
			part_data[part "," part_idx] = encoded;
		}

		# perm[phys] records which logical lane is stored in each
		# physical vec array.  For example, perm[1] = 9 means vec1
		# carries lane9.  The 16-lane permutation is encoded into
		# meta2 below instead of being emitted as plain numbers.
		for (i = 0; i < 16; i++)
			perm[i] = i;
		for (i = 15; i > 0; i--) {
			j = (mask(seed, i + n) + salt[i % 8]) % (i + 1);
			tmp = perm[i];
			perm[i] = perm[j];
			perm[j] = tmp;
		}

		for (phys = 0; phys < 16; phys++) {
			part = perm[phys];
			phys_len[phys] = part_len[part];
			for (i = 0; i < part_len[part]; i++)
				out[i] = part_data[part "," i];
			emit_array(sprintf("wx_kernel_attest_vec%d", phys), out,
				   part_len[part]);
			for (i in out)
				delete out[i];
			print "";
		}

		print "const unsigned int wx_kernel_attest_vec_len[] = {";
		for (i = 0; i < 16; i++) {
			if (i % 8 == 0)
				printf "\t";
			printf "%u", phys_len[i];
			if (i + 1 < 16)
				printf ",";
			if (i % 8 == 7 || i + 1 == 16)
				printf "\n";
			else
				printf " ";
		}
		print "};";
		print "const unsigned int wx_kernel_attest_key_len = " n ";";

		for (i = 0; i < 4; i++)
			meta0[i] = xor8(hex_byte(seed_hex, 3 - i), salt[i]);
		meta0[4] = xor8(stride % 256, salt[4]);
		meta0[5] = xor8(int(stride / 256) % 256, salt[5]);
		meta0[6] = xor8(offset % 256, salt[6]);
		meta0[7] = xor8(int(offset / 256) % 256, salt[7]);
		for (i = 0; i < 8; i++)
			meta1[i] = xor8(salt[i], (0xa7 + i * 29) % 256);
		# meta2 stores the physical vec -> logical lane mapping after
		# XORing it with salt-derived bytes.  Runtime code rebuilds the
		# inverse lane -> vec map before restoring the key.
		for (i = 0; i < 16; i++)
			meta2[i] = xor8(perm[i], xor8(salt[(i + 3) % 8],
						      (0x3d + i * 41) % 256));

		emit_array("wx_kernel_attest_meta0", meta0, 8);
		print "";
		emit_array("wx_kernel_attest_meta1", meta1, 8);
		print "";
		emit_array("wx_kernel_attest_meta2", meta2, 16);
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
