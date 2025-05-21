#include <linux/skbuff.h>

#include "common.h"

struct dns_header {
	u16 id;
	u8 flags[2];
	u16 question_num;
	u16 answer_rps_num;
	u16 auth_rps_num;
	u16 add_rps_num;
	u8 data[0];
};

#define isprint(a) ((a >=' ')&&(a <= '~'))

// refer to the reference rfc1035 & rfc3425

#define DNS_FLAG_BIT_QR		(0x80)	/* 0 means query, 1 means reply */
#define DNS_FLAG_BIT_OPCODE	(0x78)	/* 0 means normal query, 1 means inverse query, 2 means status */

#define DNS_QUERY_TYPE_A	(1)	/* IP address */  
#define DNS_QUERY_TYPE_AAAA	(28)	/* IPv6 address */

#define DNS_QUERY_CLASS_IN	(1)	/* Internet(IN) */

#if 0
static void nf_hexdump(const void *data, unsigned int len)
{
	const unsigned char *ptr = data;
	unsigned int i = 0;
	unsigned int j = 0;
	int col = 0;
	int row = 0;

	printk("============== data ptr %p, size %u ============== \n", data, len);

	printk("         0  1  2  3  4  5  6  7     8  9  a  b  c  d  e  f\n");
	printk("        -- -- -- -- -- -- -- --    -- -- -- -- -- -- -- --\n");

	while (i < len) {
		printk(KERN_CONT "0x%04x ", row << 4);
		for (col = 0; col < 16 && i < len; col++, i++) {
			if (((col) % 8) == 0 && ((col) % 16) != 0) {
				printk(KERN_CONT "   ");
			}
			printk(KERN_CONT " %02x", ptr[i]);
		}

		if (col != 16) {
			//padding space
			for (j = col; j < 16; j++) {
				if (((j) % 8) == 0 && ((j) % 16) != 0) {
					printk(KERN_CONT "   ");
				}                
				printk(KERN_CONT "   ");
			}
		}

		printk(KERN_CONT "  ");
		for (j = i - col; j < i; j++) {
			if (((j + 1) % 8) == 0 && ((j + 1) % 16) != 0) {
				printk(KERN_CONT "   ");
			}              
			if (isprint(ptr[j])) {
				printk(KERN_CONT "%c", ptr[j]);
			} else {
				printk(KERN_CONT ".");
			}
		}

		printk(KERN_CONT "\n");
		row++;
	}
	printk(KERN_CONT "\n");
}
#endif

static int obtain_query_name(const u8 *data, char *domain, size_t length)
{
	int i = 0;
	int j = 0;

	/*
	 * data is actually one byte longer than the domain name and
	 * domain buffer needs to reserve one byte to save '\0'
	 */
	if ((strlen(data) - 1) > (length - 1))
		return -1;

	/* 
	 * data format is soemthing like: '\3'www'\5'baidu'\3'com'\0'
	 * domain format expected is something like: www.baidu.com'\0'
	 */
	while (data[i]) {

		memcpy(domain+j, data+i+1, data[i]);
		j += data[i];

		i += data[i] + 1;
	
		if (data[i] > 0) {
			domain[j] = '.';
			j++;
		} else {
			domain[j] = '\0';
			break;
		}

	}

#if 0
	printk("final domain: %s", domain);
	printk("orignal data: %s", data);
#endif

	return i;
}

#if 0
static void dump_dns_header(struct dns_header *dns)
{
	__log("id		: %d", ntohs(dns->id));
	__log("flags[0]		: %d", dns->flags[0]);
	__log("flags[1]		: %d", dns->flags[1]);
	__log("question_num	: %d", ntohs(dns->question_num));
	__log("answer_rps_num	: %d", ntohs(dns->answer_rps_num));
	__log("auth_rps_num	: %d", ntohs(dns->auth_rps_num));
	__log("add_rps_num	: %d", ntohs(dns->add_rps_num));

	nf_hexdump(dns->data, sizeof(struct dns_header));
}
#endif

const char *parse_domain_name(const char *data, char *buf, int length)
{
	struct dns_header *dns = (struct dns_header *)data;
	u16 *pos;
	int offset;
	
	//dump_dns_header(dns);

	if (dns->flags[0] & DNS_FLAG_BIT_QR)
		return NULL;

	if (dns->flags[0] & DNS_FLAG_BIT_OPCODE)
		return NULL;

	if (ntohs(dns->question_num) != 1)
		return NULL;

	if (dns->answer_rps_num || dns->auth_rps_num || dns->add_rps_num)
		return NULL;

	if ((offset = obtain_query_name(dns->data, buf, length)) <= 0)
		return NULL;

	pos = (u16 *)(dns->data + offset + 1);

	//__log("query type:%d query_class:%d", ntohs(*pos), ntohs(*(pos + 1)));

	if (ntohs(*pos) != DNS_QUERY_TYPE_A)
		return NULL;

	if (ntohs(*(pos + 1)) != DNS_QUERY_CLASS_IN)
		return NULL;

	return buf;
}
