#include <linux/ip.h>
//#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/route.h>         
#include <net/ip.h>
//#include <net/tcp.h>
#include <net/checksum.h>

#include "sysctl.h"

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