#include <linux/string.h>   // for memset / memcpy
#include <linux/random.h>
#include <linux/kernel.h>

static unsigned char *tls_put_u16(unsigned char *ptr, u16 value)
{
	*ptr++ = (value >> 8) & 0xff;
	*ptr++ = value & 0xff;
	return ptr;
}

static u16 tls_grease_value(void)
{
	u8 v = (prandom_u32() % 16) * 0x10 + 0x0a;

	return ((u16)v << 8) | v;
}

static void tls_shuffle_u16_pairs(unsigned char *buf, int count)
{
	int i;

	for (i = count - 1; i > 0; i--) {
		int j = prandom_u32() % (i + 1);
		unsigned char tmp0 = buf[2 * i];
		unsigned char tmp1 = buf[2 * i + 1];

		buf[2 * i] = buf[2 * j];
		buf[2 * i + 1] = buf[2 * j + 1];
		buf[2 * j] = tmp0;
		buf[2 * j + 1] = tmp1;
	}
}

inline unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni)
{
	int offset = 0;
	int hello_start;
	int i;
	int j;
	int cipher_suite_len;
	int cipher_suite_count;
	int selected_cipher_suite_count;
	int ext_offset;
	int add_sni;
	int add_padding;
	int sni_first;
	int session_id_len;
	int padding_len;
	int sni_len;
	int ext_len;
	int name_list_len;
	int ext_total_len;
	// Cipher Suites
	static const unsigned char cipher_suites[] = {
		0xc0, 0x2b,     // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x13,     // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x35,     // TLS_RSA_AES128_SHA
		0xc0, 0x2f,     // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xc0, 0x27,     // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x23,     // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0xc0, 0x14,     // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x9c,     // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x00, 0x3c,     // TLS_RSA_WITH_AES_128_SHA256
		0x00, 0x2f,     // TLS_RSA_AES128_SHA
		0xc0, 0x30,     // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
		0xc0, 0x2c,     // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
		0xc0, 0x28,     // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
		0xc0, 0x24,     // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
		0x00, 0x9d,     // TLS_RSA_WITH_AES_256_GCM_SHA384
		0x00, 0x3d,     // TLS_RSA_WITH_AES_256_SHA256
		0x00, 0xff      // Extended Master Secret
	};
	unsigned char shuffled_cipher_suites[sizeof(cipher_suites)];

	// === TLS Record Header (5 bytes) ===
	buf[offset++] = 0x16;                 // content_type: handshake

	buf[offset++] = 0x03;                 // version: TLS 1.2
	buf[offset++] = 0x03;

	buf[offset++] = 0x00;                 // length (placeholder)
	buf[offset++] = 0x00;

	// === Handshake Header (4 bytes) ===
	buf[offset++] = 0x01;                 // msg_type: client_hello

	buf[offset++] = 0x00;                 // handshake message length[3] (placeholder)
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	hello_start = offset;

	// === ClientHello Body ===
	buf[offset++] = 0x03;                // legacy_version (2 bytes)  SSL/TLS version
	buf[offset++] = 0x03;

	// random (32 bytes)   // dummy random value
	for (i = 0; i < 8; i++) {
		*(u32 *)(buf+offset) = prandom_u32(); 
		offset += sizeof(u32);
	}
	
	/* Randomize session_id: choose 0 or 32 bytes */
	session_id_len = (prandom_u32() & 0x1) ? 32 : 0;
	buf[offset++] = session_id_len;
	if (session_id_len) {
		get_random_bytes(buf + offset, session_id_len);
		offset += session_id_len;
	}


	memcpy(shuffled_cipher_suites, cipher_suites, sizeof(cipher_suites));
	cipher_suite_count = sizeof(shuffled_cipher_suites) / 2;
	for (i = cipher_suite_count - 1; i > 0; i--) {
		unsigned char tmp0;
		unsigned char tmp1;

		j = prandom_u32() % (i + 1);

		tmp0 = shuffled_cipher_suites[2 * i];
		tmp1 = shuffled_cipher_suites[2 * i + 1];
		shuffled_cipher_suites[2 * i] = shuffled_cipher_suites[2 * j];
		shuffled_cipher_suites[2 * i + 1] = shuffled_cipher_suites[2 * j + 1];
		shuffled_cipher_suites[2 * j] = tmp0;
		shuffled_cipher_suites[2 * j + 1] = tmp1;
	}

	/* current cipher_suite_count is fixed to 17, so choose 10..17 directly */
	selected_cipher_suite_count = 10 + (prandom_u32() % 8);

	cipher_suite_len = selected_cipher_suite_count * 2;
	buf[offset++] = cipher_suite_len >> 8;
	buf[offset++] = cipher_suite_len & 0xFF;
	memcpy(buf + offset, shuffled_cipher_suites, cipher_suite_len);
	offset += cipher_suite_len;

	// Compression Methods
	buf[offset++] = 0x01;                 // compression_methods length
	buf[offset++] = 0x00;                 // null compression

	/* Extensions are optional in ClientHello.
	 * Randomize low-risk features:
	 * - include server_name when sni is provided
	 * - include RFC 7685 padding extension with random length
	 * - randomize extension order between server_name and padding
	 */
	add_sni = sni && *sni;
	add_padding = prandom_u32() & 0x1;
	if (add_sni || add_padding) {
		ext_offset = offset;
		offset += 2; // extensions length placeholder

		sni_first = prandom_u32() & 0x1;

		if (add_sni && sni_first) {
			sni_len = strlen(sni);

			// Extension Type: server_name (0x0000)
			buf[offset++] = 0x00;
			buf[offset++] = 0x00;

			// Extension Data Length:
			// = 2 (name_list_len) + 1 (name_type) + 2 (host_name_len) + sni_len
			ext_len = 2 + 1 + 2 + sni_len;
			buf[offset++] = (ext_len >> 8) & 0xFF;
			buf[offset++] = ext_len & 0xFF;

			// ServerNameList length
			name_list_len = 1 + 2 + sni_len;
			buf[offset++] = (name_list_len >> 8) & 0xFF;
			buf[offset++] = name_list_len & 0xFF;

			// name_type: host_name (0x00)
			buf[offset++] = 0x00;

			// host_name_len
			buf[offset++] = (sni_len >> 8) & 0xFF;
			buf[offset++] = sni_len & 0xFF;

			// host_name
			memcpy(buf + offset, sni, sni_len);
			offset += sni_len;
		}

		if (add_padding) {
			/* RFC 7685 padding extension (type 0x0015), length 1..32 */
			padding_len = 1 + (prandom_u32() % 32);

			buf[offset++] = 0x00;
			buf[offset++] = 0x15;
			buf[offset++] = (padding_len >> 8) & 0xFF;
			buf[offset++] = padding_len & 0xFF;
			memset(buf + offset, 0x00, padding_len);
			offset += padding_len;
		}

		if (add_sni && !sni_first) {
			sni_len = strlen(sni);

			// Extension Type: server_name (0x0000)
			buf[offset++] = 0x00;
			buf[offset++] = 0x00;

			// Extension Data Length:
			// = 2 (name_list_len) + 1 (name_type) + 2 (host_name_len) + sni_len
			ext_len = 2 + 1 + 2 + sni_len;
			buf[offset++] = (ext_len >> 8) & 0xFF;
			buf[offset++] = ext_len & 0xFF;

			// ServerNameList length
			name_list_len = 1 + 2 + sni_len;
			buf[offset++] = (name_list_len >> 8) & 0xFF;
			buf[offset++] = name_list_len & 0xFF;

			// name_type: host_name (0x00)
			buf[offset++] = 0x00;

			// host_name_len
			buf[offset++] = (sni_len >> 8) & 0xFF;
			buf[offset++] = sni_len & 0xFF;

			// host_name
			memcpy(buf + offset, sni, sni_len);
			offset += sni_len;
		}

		// Write total extensions length
		ext_total_len = offset - ext_offset - 2;
		buf[ext_offset++] = ext_total_len >> 8;
		buf[ext_offset++] = ext_total_len & 0xFF;
	}

	// === 更新握手消息长度 ===
	{
		int handshake_len = offset - hello_start;
		buf[hello_start - 3] = (handshake_len >> 16) & 0xFF;
		buf[hello_start - 2] = (handshake_len >> 8) & 0xFF;
		buf[hello_start - 1] = handshake_len & 0xFF;
	}

	// === 更新 TLS 记录长度 ===
	{
		int record_len = offset;
		buf[3] = (record_len >> 8) & 0xFF;
		buf[4] = record_len & 0xFF;
	}

	*out_len = offset;

	return buf;
}

unsigned char *build_tlsv1_client_hello(unsigned char *buf, int *out_len,
					const char *sni)
{
	int offset = 0;
	int hello_start;
	int ext_offset;
	int ext_total_len;
	int sni_len;
	int name_list_len;
	int ext_len;
	int i;
	int target_len;
	int padding_len;
	int add_extra_ciphers;
	int session_id_len;
	int tls12_cipher_count;
	int selected_tls12_cipher_count;
	int extension_count;
	int ext_order[11];
	int e;
	int j;
	int add_alpn;
	int add_compress_cert;
	int add_psk_modes;
	int add_padding;
	int add_grease_ext;
	int add_group_grease;
	u16 grease = tls_grease_value();
	unsigned char *ptr;
	static const unsigned char tls13_cipher_suites[] = {
		0x13, 0x01,
		0x13, 0x02,
		0x13, 0x03,
	};
	static const unsigned char tls12_cipher_suites[] = {
		0xc0, 0x2b,
		0xc0, 0x2f,
		0xc0, 0x2c,
		0xc0, 0x30,
		0xcc, 0xa9,
		0xcc, 0xa8,
		0xc0, 0x13,
		0xc0, 0x14,
		0x00, 0x9c,
		0x00, 0x9d,
		0x00, 0x2f,
		0x00, 0x35,
	};
	static const unsigned char optional_cipher_suites[] = {
		0xc0, 0x24,
		0xc0, 0x23,
		0xc0, 0x0a,
		0xc0, 0x09,
	};
	unsigned char shuffled_tls12[sizeof(tls12_cipher_suites)];
	unsigned char shuffled_optional[sizeof(optional_cipher_suites)];
	static const unsigned char signature_algorithms[] = {
		0x04, 0x03,
		0x08, 0x04,
		0x04, 0x01,
		0x05, 0x03,
		0x08, 0x05,
		0x05, 0x01,
		0x08, 0x06,
		0x06, 0x01,
	};

	buf[offset++] = 0x16;
	buf[offset++] = 0x03;
	buf[offset++] = 0x01;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	buf[offset++] = 0x01;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	hello_start = offset;

	buf[offset++] = 0x03;
	buf[offset++] = 0x03;
	for (i = 0; i < 8; i++) {
		*(u32 *)(buf + offset) = prandom_u32();
		offset += sizeof(u32);
	}

	switch (prandom_u32() & 0x7) {
	case 0:
		session_id_len = 0;
		break;
	case 1:
		session_id_len = 16;
		break;
	default:
		session_id_len = 32;
		break;
	}
	buf[offset++] = session_id_len;
	if (session_id_len) {
		get_random_bytes(buf + offset, session_id_len);
		offset += session_id_len;
	}

	memcpy(shuffled_tls12, tls12_cipher_suites, sizeof(shuffled_tls12));
	tls12_cipher_count = sizeof(shuffled_tls12) / 2;
	tls_shuffle_u16_pairs(shuffled_tls12, tls12_cipher_count);
	selected_tls12_cipher_count = 8 + (prandom_u32() %
		(tls12_cipher_count - 7));

	memcpy(shuffled_optional, optional_cipher_suites,
	       sizeof(shuffled_optional));
	tls_shuffle_u16_pairs(shuffled_optional, sizeof(shuffled_optional) / 2);
	add_extra_ciphers = (prandom_u32() & 0x3) == 0;

	ptr = buf + offset;
	ptr = tls_put_u16(ptr, 2 + sizeof(tls13_cipher_suites) +
			 selected_tls12_cipher_count * 2 +
			 (add_extra_ciphers ? sizeof(optional_cipher_suites) : 0));
	ptr = tls_put_u16(ptr, grease);
	memcpy(ptr, tls13_cipher_suites, sizeof(tls13_cipher_suites));
	ptr += sizeof(tls13_cipher_suites);
	memcpy(ptr, shuffled_tls12, selected_tls12_cipher_count * 2);
	ptr += selected_tls12_cipher_count * 2;
	if (add_extra_ciphers) {
		memcpy(ptr, shuffled_optional, sizeof(optional_cipher_suites));
		ptr += sizeof(optional_cipher_suites);
	}
	offset = ptr - buf;

	buf[offset++] = 0x01;
	buf[offset++] = 0x00;

	ext_offset = offset;
	offset += 2;

	extension_count = 0;
	add_grease_ext = prandom_u32() & 0x1;
	add_alpn = (prandom_u32() % 4) != 0;
	add_psk_modes = (prandom_u32() % 4) != 0;
	add_compress_cert = prandom_u32() & 0x1;
	add_padding = (prandom_u32() % 4) != 0;

	if (add_grease_ext)
		ext_order[extension_count++] = 0;
	if (sni && *sni)
		ext_order[extension_count++] = 1;
	ext_order[extension_count++] = 2;
	ext_order[extension_count++] = 3;
	ext_order[extension_count++] = 4;
	if (add_alpn)
		ext_order[extension_count++] = 5;
	ext_order[extension_count++] = 6;
	if (add_psk_modes)
		ext_order[extension_count++] = 7;
	ext_order[extension_count++] = 8;
	if (add_compress_cert)
		ext_order[extension_count++] = 9;
	if (add_padding)
		ext_order[extension_count++] = 10;

	for (e = extension_count - 1; e > 0; e--) {
		j = prandom_u32() % (e + 1);
		i = ext_order[e];
		ext_order[e] = ext_order[j];
		ext_order[j] = i;
	}

	for (e = 0; e < extension_count; e++) {
		switch (ext_order[e]) {
		case 0:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, grease);
			ptr = tls_put_u16(ptr, 0);
			offset = ptr - buf;
			break;
		case 1:
			sni_len = strlen(sni);
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x0000);
			ext_len = 2 + 1 + 2 + sni_len;
			ptr = tls_put_u16(ptr, ext_len);
			name_list_len = 1 + 2 + sni_len;
			ptr = tls_put_u16(ptr, name_list_len);
			*ptr++ = 0x00;
			ptr = tls_put_u16(ptr, sni_len);
			memcpy(ptr, sni, sni_len);
			ptr += sni_len;
			offset = ptr - buf;
			break;
		case 2:
			add_group_grease = prandom_u32() & 1;
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x000a);
			ptr = tls_put_u16(ptr, add_group_grease ? 10 : 8);
			if (add_group_grease) {
				ptr = tls_put_u16(ptr, 8);
				ptr = tls_put_u16(ptr, grease);
			} else {
				ptr = tls_put_u16(ptr, 6);
			}
			ptr = tls_put_u16(ptr, 0x001d);
			ptr = tls_put_u16(ptr, 0x0017);
			ptr = tls_put_u16(ptr, 0x0018);
			offset = ptr - buf;
			break;
		case 3:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x000b);
			ptr = tls_put_u16(ptr, 2);
			*ptr++ = 1;
			*ptr++ = 0;
			offset = ptr - buf;
			break;
		case 4:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x000d);
			ptr = tls_put_u16(ptr, 2 + sizeof(signature_algorithms));
			ptr = tls_put_u16(ptr, sizeof(signature_algorithms));
			memcpy(ptr, signature_algorithms,
			       sizeof(signature_algorithms));
			ptr += sizeof(signature_algorithms);
			offset = ptr - buf;
			break;
		case 5:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x0010);
			if (prandom_u32() & 1) {
				ptr = tls_put_u16(ptr, 14);
				ptr = tls_put_u16(ptr, 12);
				*ptr++ = 2;
				memcpy(ptr, "h2", 2);
				ptr += 2;
				*ptr++ = 8;
				memcpy(ptr, "http/1.1", 8);
				ptr += 8;
			} else {
				ptr = tls_put_u16(ptr, 11);
				ptr = tls_put_u16(ptr, 9);
				*ptr++ = 8;
				memcpy(ptr, "http/1.1", 8);
				ptr += 8;
			}
			offset = ptr - buf;
			break;
		case 6:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x002b);
			ptr = tls_put_u16(ptr, 7);
			*ptr++ = 6;
			ptr = tls_put_u16(ptr, grease);
			ptr = tls_put_u16(ptr, 0x0304);
			ptr = tls_put_u16(ptr, 0x0303);
			offset = ptr - buf;
			break;
		case 7:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x002d);
			ptr = tls_put_u16(ptr, 2);
			*ptr++ = 1;
			*ptr++ = 1;
			offset = ptr - buf;
			break;
		case 8:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x0033);
			ptr = tls_put_u16(ptr, 38);
			ptr = tls_put_u16(ptr, 36);
			ptr = tls_put_u16(ptr, 0x001d);
			ptr = tls_put_u16(ptr, 32);
			get_random_bytes(ptr, 32);
			ptr += 32;
			offset = ptr - buf;
			break;
		case 9:
			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x001b);
			ptr = tls_put_u16(ptr, 3);
			*ptr++ = 2;
			*ptr++ = 2;
			*ptr++ = 0;
			offset = ptr - buf;
			break;
		case 10:
			target_len = 260 + (prandom_u32() % 72);
			padding_len = target_len - offset - 4;
			if (padding_len < 0)
				padding_len = prandom_u32() % 16;
			if (padding_len > 96)
				padding_len = 96;

			ptr = buf + offset;
			ptr = tls_put_u16(ptr, 0x0015);
			ptr = tls_put_u16(ptr, padding_len);
			memset(ptr, 0, padding_len);
			ptr += padding_len;
			offset = ptr - buf;
			break;
		default:
			break;
		}
	}

	ext_total_len = offset - ext_offset - 2;
	buf[ext_offset] = (ext_total_len >> 8) & 0xff;
	buf[ext_offset + 1] = ext_total_len & 0xff;

	{
		int handshake_len = offset - hello_start;
		buf[hello_start - 3] = (handshake_len >> 16) & 0xff;
		buf[hello_start - 2] = (handshake_len >> 8) & 0xff;
		buf[hello_start - 1] = handshake_len & 0xff;
	}

	{
		int record_len = offset - 5;
		buf[3] = (record_len >> 8) & 0xff;
		buf[4] = record_len & 0xff;
	}

	*out_len = offset;

	return buf;
}

inline unsigned char *build_dtls_client_hello(unsigned char *buf, int *out_len, const char *sni)
{
	int offset = 0;
	int hello_start;
	int i;
	int cipher_suite_len;
	int ext_offset;
	int sni_len;
	int ext_len;
	int name_list_len;
	int ext_total_len;
	int record_len_offset;
	int handshake_len_offset;
	
	// Cipher Suites (same as TLS)
	static const unsigned char cipher_suites[] = {
		0xc0, 0x2b,     // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x13,     // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x35,     // TLS_RSA_AES128_SHA
		0xc0, 0x2f,     // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xc0, 0x27,     // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc0, 0x23,     // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0xc0, 0x14,     // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x9c,     // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x00, 0x3c,     // TLS_RSA_WITH_AES_128_SHA256
		0x00, 0x2f,     // TLS_RSA_AES128_SHA
		0xc0, 0x30,     // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
		0xc0, 0x2c,     // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
		0xc0, 0x28,     // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
		0xc0, 0x24,     // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
		0x00, 0x9d,     // TLS_RSA_WITH_AES_256_GCM_SHA384
		0x00, 0x3d,     // TLS_RSA_WITH_AES_256_SHA256
		0x00, 0x35,     // TLS_RSA_AES256_SHA
		0x00, 0xff      // Extended Master Secret
	};

	// === DTLS Record Header (13 bytes) ===
	buf[offset++] = 0x16;                 // content_type: handshake
	buf[offset++] = 0xfe;                 // version: DTLS 1.2
	buf[offset++] = 0xfd;

	buf[offset++] = 0x00;                 // epoch (2 bytes)
	buf[offset++] = 0x00;

	buf[offset++] = 0x00;                 // sequence_number (6 bytes)
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	record_len_offset = offset;
	buf[offset++] = 0x00;                 // length (placeholder)
	buf[offset++] = 0x00;

	// === DTLS Handshake Header (12 bytes) ===
	buf[offset++] = 0x01;                 // msg_type: client_hello

	handshake_len_offset = offset;
	buf[offset++] = 0x00;                 // handshake message length (3 bytes, placeholder)
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	buf[offset++] = 0x00;                 // message_seq (2 bytes)
	buf[offset++] = 0x00;

	buf[offset++] = 0x00;                 // fragment_offset (3 bytes)
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	buf[offset++] = 0x00;                 // fragment_length (3 bytes, placeholder, same as message length)
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	hello_start = offset;

	// === ClientHello Body ===
	buf[offset++] = 0xfe;                // client_version: DTLS 1.2
	buf[offset++] = 0xfd;

	// random (32 bytes)
	for (i = 0; i < 8; i++) {
		*(u32 *)(buf+offset) = prandom_u32(); 
		offset += sizeof(u32);
	}

	buf[offset++] = 0x00;                // session_id length

	// cookie (DTLS specific - empty for initial ClientHello)
	buf[offset++] = 0x00;                // cookie length

	cipher_suite_len = sizeof(cipher_suites);
	buf[offset++] = cipher_suite_len >> 8;
	buf[offset++] = cipher_suite_len & 0xFF;
	memcpy(buf + offset, cipher_suites, cipher_suite_len);
	offset += cipher_suite_len;

	// Compression Methods
	buf[offset++] = 0x01;                // compression_methods length
	buf[offset++] = 0x00;                // null compression

	/* Extensions are optional in ClientHello.
	 * Only add server_name when sni is provided and non-empty.
	 */
	if (sni && *sni) {
		ext_offset = offset;
		offset += 2; // extensions length placeholder

		sni_len = strlen(sni);

		// Extension Type: server_name (0x0000)
		buf[offset++] = 0x00;
		buf[offset++] = 0x00;

		// Extension Data Length
		ext_len = 2 + 1 + 2 + sni_len;
		buf[offset++] = (ext_len >> 8) & 0xFF;
		buf[offset++] = ext_len & 0xFF;

		// ServerNameList length
		name_list_len = 1 + 2 + sni_len;
		buf[offset++] = (name_list_len >> 8) & 0xFF;
		buf[offset++] = name_list_len & 0xFF;

		// name_type: host_name (0x00)
		buf[offset++] = 0x00;

		// host_name_len
		buf[offset++] = (sni_len >> 8) & 0xFF;
		buf[offset++] = sni_len & 0xFF;

		// host_name
		memcpy(buf + offset, sni, sni_len);
		offset += sni_len;

		// Write total extensions length
		ext_total_len = offset - ext_offset - 2;
		buf[ext_offset++] = ext_total_len >> 8;
		buf[ext_offset++] = ext_total_len & 0xFF;
	}

	// === 更新握手消息长度 ===
	{
		int handshake_len = offset - hello_start;
		// Write handshake message length at offset 0-2
		buf[handshake_len_offset + 0] = (handshake_len >> 16) & 0xFF;
		buf[handshake_len_offset + 1] = (handshake_len >> 8) & 0xFF;
		buf[handshake_len_offset + 2] = handshake_len & 0xFF;

		// Write fragment_length at offset 8-10 (same as message length)
		buf[handshake_len_offset + 8] = (handshake_len >> 16) & 0xFF;
		buf[handshake_len_offset + 9] = (handshake_len >> 8) & 0xFF;
		buf[handshake_len_offset + 10] = handshake_len & 0xFF;
	}

	// === 更新 DTLS 记录长度 ===
	{
		// Record Length = 从Handshake Type开始到body结束的所有字节数
		// record_len_offset + 2 跳过Length字段本身，从msg_type开始计数
		int total_len = offset - (record_len_offset + 2);
		buf[record_len_offset] = (total_len >> 8) & 0xFF;
		buf[record_len_offset + 1] = total_len & 0xFF;
	}

	*out_len = offset;

	return buf;
}
