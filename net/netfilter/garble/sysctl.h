#ifndef __GARBLE_SYSCTL_H__
#define __GARBLE_SYSCTL_H__


#include <linux/version.h>
#include <linux/types.h>

#define GARBLE_MAX_TCP_PAYLOAD (1452) // 1500 - 20 (IP) - 20 (TCP) - 8 (ppp header) 
#define GARBLE_MAX_UDP_PAYLOAD (1464) // 1500 - 20 (IP) - 8 (UDP) - 8 (ppp header)

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
inline bool garble_check_if_local_obf_enabled(void);
inline bool garble_check_if_wellknown_port_obf_enabled(void);
inline bool garble_check_if_routing_enabled(void);
inline int garble_get_udp_avg_pkt(void);
inline int garble_get_tcp_avg_pkt(void);
inline int garble_get_tcp_repeat_pkt(void);
inline int garble_get_udp_repeat_pkt(void);
inline const char *garble_get_udp_payload(int *len);
inline const char *garble_get_tcp_payload(int *len);
inline bool garble_check_if_tcp_binary_enabled(void);
inline bool garble_check_if_udp_binary_enabled(void);
inline int garble_get_udp_ttl(void);
inline int garble_get_tcp_ttl(void);
inline int garble_get_udp_obf_proto(void);
inline const char *garble_get_udp_extra(void);
inline int garble_check_if_lan_nic(const char *nic);
inline void garble_stats_account_tcp_v4(u32 bytes);
inline void garble_stats_account_tcp_v6(u32 bytes);
inline void garble_stats_account_udp_v4(u32 bytes);
inline void garble_stats_account_udp_v6(u32 bytes);

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
extern bool garble_check_if_local_obf_enabled(void);
extern bool garble_check_if_wellknown_port_obf_enabled(void);
extern bool garble_check_if_routing_enabled(void);
extern int garble_get_udp_avg_pkt(void);
extern int garble_get_tcp_avg_pkt(void);
extern int garble_get_tcp_repeat_pkt(void);
extern int garble_get_udp_repeat_pkt(void);
extern const char *garble_get_udp_payload(int *len);
extern const char *garble_get_tcp_payload(int *len);
extern bool garble_check_if_tcp_binary_enabled(void);
extern bool garble_check_if_udp_binary_enabled(void);
extern int garble_get_udp_ttl(void);
extern int garble_get_tcp_ttl(void);
extern int garble_get_udp_obf_proto(void);
extern const char *garble_get_udp_extra(void);
extern int garble_check_if_lan_nic(const char *nic);
extern void garble_stats_account_tcp_v4(u32 bytes);
extern void garble_stats_account_tcp_v6(u32 bytes);
extern void garble_stats_account_udp_v4(u32 bytes);
extern void garble_stats_account_udp_v6(u32 bytes);

#endif

enum udp_obf_proto {
	UDP_OBF_STUN_REQUEST = 0,
	UDP_OBF_WECHAT_VIDEO = 1,
	UDP_OBF_SIP_INVITE = 2,
	UDP_OBF_DTLS_CLIENTHELLO = 3,

	UDP_OBF_PROTO_MAX
};

#endif // __GARBLE_SYSCTL_H__