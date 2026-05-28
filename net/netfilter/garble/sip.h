#ifndef __GARBLE_SIP_H__
#define __GARBLE_SIP_H__

#include <linux/version.h>

#include "packet.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline unsigned char *build_sip_payload(unsigned char *buf, int *out_len,
					garble_tuple_t *tuple,
					garble_tuple_v6_t *tuple6);
inline int build_sip_payload_msg(unsigned char *buffer, int *len,
				 const char *sip_host,
				 garble_tuple_t *tuple,
				 garble_tuple_v6_t *tuple6);

#else

extern unsigned char *build_sip_payload(unsigned char *buf, int *out_len,
					garble_tuple_t *tuple,
					garble_tuple_v6_t *tuple6);
extern int build_sip_payload_msg(unsigned char *buffer, int *len,
				 const char *sip_host,
				 garble_tuple_t *tuple,
				 garble_tuple_v6_t *tuple6);

#endif

#endif // __GARBLE_SIP_H__
