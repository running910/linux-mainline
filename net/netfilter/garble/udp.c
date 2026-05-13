#include <linux/ip.h>
//#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <net/route.h>         
#include <net/ip.h>
//#include <net/tcp.h>
#include <net/checksum.h>

#include "sysctl.h"
#include "stun.h"
#include "sip.h"



#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline unsigned char *build_dtls_client_hello(unsigned char *buf, int *out_len, const char *sni);

#else

extern unsigned char *build_dtls_client_hello(unsigned char *buf, int *out_len, const char *sni);

#endif

inline unsigned char *build_wechat_video_call_msg(unsigned char *buf, int *out_len)
{
	/* 固定头部数据 (54字节) */
	static const unsigned char fixed_header[] = {
		0xD5, 0x68, 0x8D, 0x04, 0x76, 0x0A, 0x19, 0x0A,
		0x07, 0x08, 0x82, 0x20, 0x10, 0x03, 0x18, 0x00,
		0x10, 0x00, 0x18, 0x0A, 0x28, 0x85, 0xF8, 0xB8,
		0x98, 0xA5, 0xCE, 0xF8, 0x89, 0x07, 0x38, 0x00,
		0x10, 0x58, 0x1A, 0x58, 0x40, 0xA7, 0xA8, 0x31,
		0xB5, 0xB2, 0x99, 0x8A, 0x3D, 0xEE, 0x39, 0x47,
		0x52, 0xE6, 0x40, 0x37, 0x74, 0xA7
	};
	int random_len;
	unsigned char *ptr;

	/* 生成随机总长度100-200 (包含边界) */
	get_random_bytes(&random_len, sizeof(random_len));
	random_len = 100 + (abs((int)random_len) % 101); /* 100 + [0,100] */

	/* 复制固定头部 */
	memcpy(buf, fixed_header, sizeof(fixed_header));

	/* 填充随机数据 (剩余部分) */
	ptr = buf + sizeof(fixed_header);
	get_random_bytes(ptr, random_len - sizeof(fixed_header));
	
	/* 返回实际长度 */
	*out_len = random_len;

	return buf;
}

inline unsigned char *build_tftp_rrq_payload(unsigned char *buf, int *out_len)
{
	static const char mode[] = "octet";
	static const char fname_chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	unsigned char *ptr = buf;
	u32 rand_val;
	int filename_len;
	int i;

	ptr[0] = 0x00;
	ptr[1] = 0x01;
	ptr += 2;

	get_random_bytes(&rand_val, sizeof(rand_val));
	filename_len = 4 + (rand_val % 9);

	for (i = 0; i < filename_len; i++) {
		get_random_bytes(&rand_val, sizeof(rand_val));
		ptr[i] = fname_chars[rand_val % (sizeof(fname_chars) - 1)];
	}
	ptr += filename_len;

	*ptr++ = 0x00;
	memcpy(ptr, mode, sizeof(mode));
	ptr += sizeof(mode);

	*out_len = ptr - buf;
	return buf;
}

inline unsigned char *build_xiaomi_camera_handshake(unsigned char *buf, int *out_len)
{
	static const unsigned char handshake[] = { 0xf1, 0xe1, 0x00, 0x00 };

	memcpy(buf, handshake, sizeof(handshake));
	*out_len = sizeof(handshake);

	return buf;
}

static inline u32 garble_rand_u32(void)
{
	u32 val;

	get_random_bytes(&val, sizeof(val));
	return val;
}

static inline int garble_rand_range(int min, int max)
{
	return min + (garble_rand_u32() % (max - min + 1));
}

static inline unsigned char garble_rand_u8(void)
{
	return (unsigned char)garble_rand_u32();
}

static inline unsigned char *garble_write_rand_varint(unsigned char *ptr,
						      int bytes)
{
	int i;

	for (i = 0; i < bytes - 1; i++)
		*ptr++ = 0x80 | (garble_rand_u8() & 0x7f);

	*ptr++ = 1 + (garble_rand_u8() & 0x7f);
	return ptr;
}

static inline unsigned char *build_wechat_video_new_d5(unsigned char *buf, int *out_len)
{
	static const unsigned char body_len_19[] = { 0x28, 0x38, 0x58 };
	static const unsigned char body_len_26[] = { 0x40, 0x48, 0x68 };
	static const unsigned char msg_19[] = { 0x82, 0x84, 0x8a };
	static const unsigned char msg_26[] = { 0x02, 0x04 };
	unsigned char *ptr = buf;
	unsigned char body_len;
	u32 r = garble_rand_u32() % 100;

	*ptr++ = 0xd5;
	get_random_bytes(ptr, 4);
	ptr += 4;

	if (r < 55) {
		body_len = body_len_19[garble_rand_u32() % ARRAY_SIZE(body_len_19)];

		*ptr++ = 0x0a;
		*ptr++ = 0x19;
		*ptr++ = 0x0a;
		*ptr++ = 0x07;
		*ptr++ = 0x08;
		*ptr++ = msg_19[garble_rand_u32() % ARRAY_SIZE(msg_19)];
		*ptr++ = 0x20;
		*ptr++ = 0x10;
		*ptr++ = 0x03;
		*ptr++ = 0x18;
		*ptr++ = 0x00;
		*ptr++ = 0x10;
		*ptr++ = 0x00;
		*ptr++ = 0x18;
		*ptr++ = 0x0a;
		*ptr++ = 0x28;
		ptr = garble_write_rand_varint(ptr, 9);
		*ptr++ = 0x38;
		*ptr++ = 0x00;
		*ptr++ = 0x10;
		*ptr++ = body_len;
		*ptr++ = 0x1a;
		*ptr++ = body_len;
	} else {
		body_len = body_len_26[garble_rand_u32() % ARRAY_SIZE(body_len_26)];

		*ptr++ = 0x0a;
		*ptr++ = 0x26;
		*ptr++ = 0x0a;
		*ptr++ = 0x06;
		*ptr++ = 0x08;
		*ptr++ = msg_26[garble_rand_u32() % ARRAY_SIZE(msg_26)];
		*ptr++ = 0x10;
		*ptr++ = 0x03;
		*ptr++ = 0x18;
		*ptr++ = 0x00;
		*ptr++ = 0x10;
		*ptr++ = 0x00;
		*ptr++ = 0x18;
		*ptr++ = 0x0a;
		*ptr++ = 0x20;
		*ptr++ = 0x00;
		*ptr++ = 0x2a;
		*ptr++ = 0x00;
		*ptr++ = 0x30;
		*ptr++ = 0x00;
		*ptr++ = 0x38;
		*ptr++ = 0x00;
		*ptr++ = 0x40;
		ptr = garble_write_rand_varint(ptr, 5);
		*ptr++ = 0x48;
		ptr = garble_write_rand_varint(ptr, 9);
		*ptr++ = 0x50;
		*ptr++ = 0x00;
		*ptr++ = 0x10;
		*ptr++ = body_len;
		*ptr++ = 0x1a;
		*ptr++ = body_len;
	}

	get_random_bytes(ptr, body_len);
	ptr += body_len;

	*out_len = ptr - buf;

	return buf;
}

inline unsigned char *build_wechat_video_new_payload(unsigned char *buf, int *out_len)
{
	return build_wechat_video_new_d5(buf, out_len);
}

inline unsigned char *build_payload_from_binary(unsigned char *buf, int *out_len)
{
	int len;
	unsigned char *tmp;

	tmp = (unsigned char *)garble_get_udp_payload(&len);
	if (!tmp)
		return NULL;

	memcpy(buf, tmp, len);
	*out_len = len;

	return buf;
}

inline unsigned char *build_udp_payload(unsigned char *buf, int *out_len)
{
	if (garble_check_if_udp_binary_enabled())
		return build_payload_from_binary(buf, out_len);

	switch (garble_get_udp_obf_proto()) {
	case UDP_OBF_TURN_ALLOCATE:
		return build_turn_allocate_payload(buf, out_len);
	case UDP_OBF_TURN_CREATE_PERMISSION:
		return build_turn_create_permission_payload(buf, out_len);
	case UDP_OBF_TURN_ALLOCATE_ERROR_RESPONSE:
		return build_turn_allocate_error_response_payload(buf, out_len);
	case UDP_OBF_TURN_CHANNEL_BIND:
		return build_turn_channel_bind_payload(buf, out_len);
	case UDP_OBF_TFTP_RRQ:
		return build_tftp_rrq_payload(buf, out_len);
	case UDP_OBF_WECHAT_VIDEO_NEW:
		return build_wechat_video_new_payload(buf, out_len);
	case UDP_OBF_XIAOMI_CAMERA:
		return build_xiaomi_camera_handshake(buf, out_len);
	case UDP_OBF_WECHAT_VIDEO:
		return build_wechat_video_call_msg(buf, out_len);
	case UDP_OBF_SIP_INVITE:
		return build_sip_payload(buf, out_len);
	case UDP_OBF_DTLS_CLIENTHELLO:
		return build_dtls_client_hello(buf, out_len, garble_get_random_domain());
	default:
		return NULL;
	}

	return NULL;
}
