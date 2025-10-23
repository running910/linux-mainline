/*
 * payload_kernel.c - FakeSIP kernel implementation
 *
 * Copyright (C) 2025 MikeWang000000
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>

#define BUFFLEN 1200

static const char *sdp_fmt = 
	"v=0\r\n"
	"o=Admin %lu %lu IN IP4 %s\r\n"
	"s=-\r\n"
	"c=IN IP4 %s\r\n"
	"t=0 0\r\n"
	"m=audio 6000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n";

static const char *sip_fmt = 
	"INVITE %s SIP/2.0\r\n"
	"Via: SIP/2.0/UDP %s;branch=%lx\r\n"
	"From: <sip:%s>;tag=%lx\r\n"
	"To: \"%s\" <%s>\r\n"
	"Call-ID: %lx@%s\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:%s>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length: %lu\r\n"
	"\r\n"
	"%s";

/**
 * make_sip_invite - Generate SIP INVITE message
 * @buffer: output buffer for SIP message
 * @len: input - buffer size, output - actual message length
 * @sip_uri: SIP URI string (optional, if NULL, random URI will be generated)
 *
 * Return: 0 on success, negative error code on failure
 */
inline int build_sip_payload_msg(unsigned char *buffer, int *len, const char *sip_uri)
{
	char sip_uri_random[64];
	char local[64];
	char sdp_buf[180];
	char username[5];	/* 4 characters + null terminator */
	const char *username_ptr;
	unsigned long rand_ul[5];
	int len_, buffsize;
	unsigned long content_length;
	u8 random_bytes[2];
	u8 random_byte;
	int i;
	const char char_set[] = "abcdefghijklmnopqrstuvwxyz"
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "0123456789";

	/* Generate random values */
	get_random_bytes(rand_ul, sizeof(rand_ul));

	/* Handle SIP URI */
	if (sip_uri) {
		if (strncmp("sip:", sip_uri, 4) != 0) {
			pr_err("ERROR: Invalid SIP URI (should start with `sip:`): %s\n",
			       sip_uri);
			return -EINVAL;
		}
		username_ptr = sip_uri + 4;
	} else {
		/* Generate random username (4 characters: letters and numbers) */
		for (i = 0; i < 4; i++) {
			get_random_bytes(&random_byte, sizeof(random_byte));
			username[i] = char_set[random_byte % (sizeof(char_set) - 1)];
		}
		username[4] = '\0';
		
		/* Generate SIP URI with last byte in range 1-254 */
		get_random_bytes(&random_byte, sizeof(random_byte));
		random_byte = (random_byte % 254) + 1;	/* 1-254 range */
		
		len_ = snprintf(sip_uri_random, sizeof(sip_uri_random), 
			       "sip:%s@113.240.%d.%u", username, 
			       (unsigned int)random_bytes[0] % 256, 
			       (unsigned int)random_byte);
		if (len_ < 0 || len_ >= sizeof(sip_uri_random)) {
			pr_err("ERROR: snprintf failed for SIP URI\n");
			return -EINVAL;
		}
		sip_uri = sip_uri_random;
		username_ptr = username;
	}

	/* Generate local IP address with last byte in range 1-254 */
	get_random_bytes(random_bytes, sizeof(random_bytes));
	random_bytes[1] = (random_bytes[1] % 254) + 1;	/* 1-254 range */
	
	len_ = snprintf(local, sizeof(local), "192.168.%u.%u", 
		       (unsigned int)random_bytes[0], (unsigned int)random_bytes[1]);
	if (len_ < 0 || len_ >= sizeof(local)) {
		pr_err("ERROR: snprintf failed for local IP\n");
		return -EINVAL;
	}

	/* Generate SDP content */
	len_ = snprintf(sdp_buf, sizeof(sdp_buf), sdp_fmt, 
		       rand_ul[0] & 0xFFFFFFFF, 
		       rand_ul[1] & 0xFFFFFFFF, 
		       local, local);
	if (len_ < 0 || len_ >= sizeof(sdp_buf)) {
		pr_err("ERROR: snprintf failed for SDP\n");
		return -EINVAL;
	}

	content_length = len_;

	/* Generate final SIP INVITE message */
	buffsize = *len;
	len_ = snprintf((char *)buffer, buffsize, sip_fmt,
		       sip_uri, local, rand_ul[2], 
		       local, rand_ul[3], 
		       username_ptr, sip_uri, 
		       rand_ul[4], local, local, 
		       content_length, sdp_buf);
	
	if (len_ < 0) {
		pr_err("ERROR: snprintf failed for SIP message\n");
		return -EINVAL;
	} else if (len_ >= buffsize) {
		pr_err("ERROR: Buffer too small for SIP message\n");
		return -EMSGSIZE;
	}

	*len = len_;
	return 0;
}

inline unsigned char *build_sip_payload(unsigned char *buf, int *out_len)
{
	if (build_sip_payload_msg(buf, out_len, NULL) == 0)
		return buf;
	else
		return NULL;
}