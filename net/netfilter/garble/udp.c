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

static inline u32 garble_rand_u32(void)
{
	u32 val;

	get_random_bytes(&val, sizeof(val));
	return val;
}

static inline u8 garble_rand_u8(void)
{
	return (u8)garble_rand_u32();
}

static inline int garble_rand_range(int min, int max)
{
	return min + (garble_rand_u32() % (max - min + 1));
}

static inline int garble_wechat_video_new_len_96(void)
{
	u32 r = garble_rand_u32() % 100;

	if (r < 10)
		return garble_rand_range(64, 221);
	if (r < 25)
		return garble_rand_range(222, 545);
	if (r < 50)
		return garble_rand_range(546, 971);
	if (r < 75)
		return garble_rand_range(972, 1184);
	if (r < 90)
		return garble_rand_range(1185, 1281);

	return garble_rand_range(1282, 1343);
}

static inline int garble_wechat_video_new_len_98(void)
{
	u32 r = garble_rand_u32() % 100;

	if (r < 10)
		return garble_rand_range(60, 90);
	if (r < 25)
		return garble_rand_range(91, 98);
	if (r < 50)
		return garble_rand_range(99, 194);
	if (r < 75)
		return garble_rand_range(195, 231);
	if (r < 90)
		return garble_rand_range(232, 247);

	return garble_rand_range(248, 277);
}

static inline void garble_fill_wechat_video_new_magic(unsigned char *buf)
{
	static const unsigned char magic[] = {
		0x05, 0x3c, 0x0e, 0x53, 0x72, 0xe2, 0x13, 0x07
	};

	memcpy(buf, magic, sizeof(magic));
}

static inline unsigned char *build_wechat_video_new_96(unsigned char *buf, int *out_len)
{
	int len = garble_wechat_video_new_len_96();
	u32 seq = garble_rand_u32() % 0x0b00;
	u32 r = garble_rand_u32() % 100;

	buf[0] = 0x96;
	buf[1] = 0x13;
	garble_fill_wechat_video_new_magic(buf + 2);

	if (r < 1) {
		buf[10] = 0xff;
		buf[11] = 0xff;
	} else {
		buf[10] = (r < 51) ? 0x01 : 0x00;
		buf[11] = 0x00;
	}

	buf[12] = seq & 0xff;
	buf[13] = (seq >> 8) & 0xff;

	r = garble_rand_u32() % 100;
	if (r < 97)
		buf[14] = 0x21;
	else if (r < 99)
		buf[14] = 0x30;
	else
		buf[14] = 0x50;

	buf[15] = garble_rand_u8();
	buf[16] = garble_rand_u32() % 9;
	buf[17] = (garble_rand_u32() % 55 == 0) ? 0x01 : 0x00;
	buf[18] = 0x00;

	get_random_bytes(buf + 19, len - 19);
	*out_len = len;

	return buf;
}

static inline unsigned char *build_wechat_video_new_98(unsigned char *buf, int *out_len)
{
	int len = garble_wechat_video_new_len_98();
	u32 seq = garble_rand_u32() % 0x0b00;
	u32 r = garble_rand_u32() % 100;

	buf[0] = 0x98;
	buf[1] = 0x15;
	garble_fill_wechat_video_new_magic(buf + 2);
	buf[10] = (r < 48) ? 0x01 : 0x00;
	buf[11] = 0x00;
	buf[12] = seq & 0xff;
	buf[13] = (seq >> 8) & 0xff;
	buf[14] = (garble_rand_u32() % 55 == 0) ? 0x21 : 0x10;
	buf[15] = garble_rand_u8();

	r = garble_rand_u32() % 100;
	if (r < 51)
		buf[16] = 0x00;
	else if (r < 97)
		buf[16] = 0x01;
	else
		buf[16] = 0x02;

	buf[17] = 0x00;
	buf[18] = (garble_rand_u32() % 7 == 0) ? 0x04 : 0x00;

	r = garble_rand_u32() % 100;
	if (r < 59)
		buf[19] = 0x00;
	else if (r < 88)
		buf[19] = 0x01;
	else if (r < 93)
		buf[19] = 0x02;
	else
		buf[19] = garble_rand_u32() % 8;

	buf[20] = 0x00;

	get_random_bytes(buf + 21, len - 21);
	*out_len = len;

	return buf;
}

static inline unsigned char *build_wechat_video_new_d5(unsigned char *buf, int *out_len)
{
	static const unsigned char template_26[] = {
		0x0a, 0x26, 0x0a, 0x06, 0x08, 0x02, 0x10, 0x03,
		0x18, 0x00, 0x10, 0x00, 0x18, 0x0a, 0x20, 0x00,
		0x2a, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40
	};
	static const unsigned char template_19[] = {
		0x0a, 0x19, 0x0a, 0x07, 0x08, 0x82, 0x20, 0x10,
		0x03, 0x18, 0x00, 0x10, 0x00, 0x18, 0x0a, 0x28
	};
	int len = garble_rand_range(76, 153);
	unsigned char *ptr = buf;
	bool short_hdr = garble_rand_u32() % 5 == 0;
	u8 body_len;

	*ptr++ = 0xd5;
	get_random_bytes(ptr, 4);
	ptr += 4;

	if (short_hdr) {
		memcpy(ptr, template_19, sizeof(template_19));
		ptr += sizeof(template_19);
	} else {
		memcpy(ptr, template_26, sizeof(template_26));
		ptr += sizeof(template_26);
		*ptr++ = garble_rand_u8();
		*ptr++ = 0xf0 | (garble_rand_u8() & 0x0f);
		*ptr++ = 0xf8;
		*ptr++ = 0x89;
		*ptr++ = 0x01;
		*ptr++ = 0x48;
	}

	*ptr++ = 0x85;
	*ptr++ = 0xf8;
	*ptr++ = 0xb8;
	*ptr++ = 0x98;
	*ptr++ = 0xa5;
	*ptr++ = 0xce;
	*ptr++ = 0xf8;
	*ptr++ = 0x89;
	*ptr++ = 0x07;

	if (!short_hdr) {
		*ptr++ = 0x50;
		*ptr++ = 0x00;
	}

	body_len = len - (ptr - buf) - 4;
	*ptr++ = 0x10;
	*ptr++ = body_len;
	*ptr++ = 0x1a;
	*ptr++ = body_len;

	get_random_bytes(ptr, len - (ptr - buf));
	*out_len = len;

	return buf;
}

inline unsigned char *build_wechat_video_new_payload(unsigned char *buf, int *out_len)
{
	u32 r = garble_rand_u32() % 1000;

	if (r < 697)
		return build_wechat_video_new_96(buf, out_len);
	if (r < 992)
		return build_wechat_video_new_98(buf, out_len);

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
