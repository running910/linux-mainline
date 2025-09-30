#include <linux/version.h>


int garble_sysctl_init(void);
void garble_sysctl_exit(void);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
inline const char *garble_get_random_domain(void);
inline bool garble_check_if_tcp_enabled(void);
inline bool garble_check_if_tcp_aggressive(void);
inline bool garble_check_if_http_enabled(void);
inline bool garble_check_if_tls_enabled(void);
inline bool garble_check_if_tcp_double_enabled(void);
inline bool garble_check_if_tcp_disabled(void);
inline bool garble_check_if_udp_enabled(void);
inline bool garble_check_if_udp_aggressive(void);
inline bool garble_check_if_tcp_client_enabled(void);
inline int garble_get_udp_avg_pkt(void);
inline int garble_get_tcp_avg_pkt(void);
inline const char *garble_get_udp_payload(size_t *len);
inline bool garble_check_if_udp_binary_enabled(void);


#else
extern const char *garble_get_random_domain(void);
extern bool garble_check_if_tcp_enabled(void);
extern bool garble_check_if_tcp_aggressive(void);
extern bool garble_check_if_http_enabled(void);
extern bool garble_check_if_tls_enabled(void);
extern bool garble_check_if_tcp_double_enabled(void);
extern bool garble_check_if_tcp_disabled(void);
extern bool garble_check_if_udp_enabled(void);
extern bool garble_check_if_udp_aggressive(void);
extern bool garble_check_if_tcp_client_enabled(void);
extern int garble_get_udp_avg_pkt(void);
extern int garble_get_tcp_avg_pkt(void);
extern const char *garble_get_udp_payload(size_t *len);
extern bool garble_check_if_udp_binary_enabled(void);

#endif