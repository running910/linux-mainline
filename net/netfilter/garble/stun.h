#ifndef __GARBLE_STUN_H__
#define __GARBLE_STUN_H__

void stun_crypto_cleanup(void);
int stun_crypto_init(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline unsigned char *build_turn_allocate_payload(unsigned char *buf, int *out_len);
inline unsigned char *build_turn_create_permission_payload(unsigned char *buf, int *out_len);
inline unsigned char *build_turn_allocate_error_response_payload(unsigned char *buf, int *out_len);

#else

extern unsigned char *build_turn_allocate_payload(unsigned char *buf, int *out_len);
extern unsigned char *build_turn_create_permission_payload(unsigned char *buf, int *out_len);
extern unsigned char *build_turn_allocate_error_response_payload(unsigned char *buf, int *out_len);

#endif

#endif // __GARBLE_STUN_H__