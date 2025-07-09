#include <linux/string.h>   // for memset / memcpy
#include <linux/random.h>


unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni)
{
	int offset = 0;

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


	int hello_start = offset;

	// === ClientHello Body ===
	buf[offset++] = 0x03;                // legacy_version (2 bytes)  SSL/TLS version
	buf[offset++] = 0x03;

	// random (32 bytes)   // dummy random value
	int i;
	for (i = 0; i < 8; i++) {
		*(u32 *)(buf+offset) = prandom_u32(); 
		offset += sizeof(u32);
	}
	
	buf[offset++] = 0x00;                          // session_id (1 byte length + 0 bytes)

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
		0x00, 0x35,     // TLS_RSA_AES256_SHA
		0x00, 0xff      // Extended Master Secret
	};

	int cipher_suite_len = sizeof(cipher_suites);
	buf[offset++] = cipher_suite_len >> 8;
	buf[offset++] = cipher_suite_len & 0xFF;
	memcpy(buf + offset, cipher_suites, cipher_suite_len);
	offset += cipher_suite_len;

	// Compression Methods
	buf[offset++] = 0x01;                 // compression_methods length
	buf[offset++] = 0x00;                 // null compression

	// Extensions
	int ext_offset = offset;
	offset += 2; // extensions length placeholder

	int sni_len = strlen(sni);

	// Extension Type: server_name (0x0000)
	buf[offset++] = 0x00;
	buf[offset++] = 0x00;

	// Extension Data Length:
	// = 2 (name_list_len) + 1 (name_type) + 2 (host_name_len) + sni_len
	int ext_len = 2 + 1 + 2 + sni_len;
	buf[offset++] = (ext_len >> 8) & 0xFF;
	buf[offset++] = ext_len & 0xFF;

	// ServerNameList length
	int name_list_len = 1 + 2 + sni_len;
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
	int ext_total_len = offset - ext_offset - 2;
	buf[ext_offset++] = ext_total_len >> 8;
	buf[ext_offset++] = ext_total_len & 0xFF;

	// === 更新握手消息长度 ===
	int handshake_len = offset - hello_start;
	buf[hello_start - 3] = (handshake_len >> 16) & 0xFF;
	buf[hello_start - 2] = (handshake_len >> 8) & 0xFF;
	buf[hello_start - 1] = handshake_len & 0xFF;

	// === 更新 TLS 记录长度 ===
	int record_len = offset;
	buf[3] = (record_len >> 8) & 0xFF;
	buf[4] = record_len & 0xFF;

	*out_len = offset;

	return buf;
}