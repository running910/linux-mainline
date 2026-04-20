#include <linux/string.h>   // for memset / memcpy
#include <linux/random.h>

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
	
	buf[offset++] = 0x00;                          // session_id (1 byte length + 0 bytes)


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
	 * Only add server_name when sni is provided and non-empty.
	 */
	if (sni && *sni) {
		ext_offset = offset;
		offset += 2; // extensions length placeholder

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
