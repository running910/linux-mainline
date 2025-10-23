#ifndef __GARBLE_SIP_H__
#define __GARBLE_SIP_H__

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline unsigned char *build_sip_payload(unsigned char *buf, int *out_len);

#else

extern unsigned char *build_sip_payload(unsigned char *buf, int *out_len);

#endif

#endif // __GARBLE_SIP_H__