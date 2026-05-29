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
inline bool garble_check_if_tcp_obf_enabled(void);
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
inline unsigned char *garble_get_udp_payload_file(unsigned char *buf, int *len);
inline unsigned char *garble_get_tcp_payload_file(unsigned char *buf, int *len);
inline bool garble_check_if_tcp_binary_enabled(void);
inline bool garble_check_if_udp_binary_enabled(void);
inline int garble_get_udp_ttl(void);
inline int garble_get_tcp_ttl(void);
inline int garble_estimate_hops(u8 ttl);
inline int garble_calc_udp_ttl(u8 src_ttl);
inline int garble_calc_tcp_ttl(u8 src_ttl);
inline int garble_get_udp_obf_proto(void);
inline int garble_get_tcp_obf_proto(void);
inline const char *garble_get_udp_obf_proto_name(int proto);
inline const char *garble_get_tcp_obf_proto_name(int proto);
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
extern bool garble_check_if_tcp_obf_enabled(void);
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
extern unsigned char *garble_get_udp_payload_file(unsigned char *buf, int *len);
extern unsigned char *garble_get_tcp_payload_file(unsigned char *buf, int *len);
extern bool garble_check_if_tcp_binary_enabled(void);
extern bool garble_check_if_udp_binary_enabled(void);
extern int garble_get_udp_ttl(void);
extern int garble_get_tcp_ttl(void);
extern int garble_estimate_hops(u8 ttl);
extern int garble_calc_udp_ttl(u8 src_ttl);
extern int garble_calc_tcp_ttl(u8 src_ttl);
extern int garble_get_udp_obf_proto(void);
extern int garble_get_tcp_obf_proto(void);
extern const char *garble_get_udp_obf_proto_name(int proto);
extern const char *garble_get_tcp_obf_proto_name(int proto);
extern const char *garble_get_udp_extra(void);
extern int garble_check_if_lan_nic(const char *nic);
extern void garble_stats_account_tcp_v4(u32 bytes);
extern void garble_stats_account_tcp_v6(u32 bytes);
extern void garble_stats_account_udp_v4(u32 bytes);
extern void garble_stats_account_udp_v6(u32 bytes);

#endif

enum udp_obf_proto {
	UDP_OBF_TURN_ALLOCATE = 0,
	UDP_OBF_WECHAT_VIDEO = 1,
	UDP_OBF_SIP_INVITE = 2,
	UDP_OBF_DTLS_CLIENTHELLO = 3,
	UDP_OBF_TURN_CREATE_PERMISSION = 4,
	UDP_OBF_TURN_ALLOCATE_ERROR_RESPONSE = 5,
	UDP_OBF_TURN_CHANNEL_BIND = 6,
	UDP_OBF_TFTP_RRQ = 7,
	UDP_OBF_WECHAT_VIDEO_NEW = 8,
	UDP_OBF_XIAOMI_CAMERA = 9,
	UDP_OBF_BILIBILI_LIVE = 10,
	UDP_OBF_PAYLOAD_FILE = 11,

	UDP_OBF_PROTO_MAX
};

enum tcp_obf_proto {
	TCP_OBF_HTTP = 0,
	TCP_OBF_TLS_CLIENTHELLO = 1,
	TCP_OBF_SSH_BANNER = 2,
	TCP_OBF_RTMP_HANDSHAKE = 3,
	TCP_OBF_POSTGRES_STARTUP = 4,
	TCP_OBF_MQTT_CONNECT = 5,
	TCP_OBF_FTP_USER = 6,
	TCP_OBF_PAYLOAD_FILE = 7,
	TCP_OBF_VNC = 8,
	TCP_OBF_THRIFT = 9,
	TCP_OBF_SIP_INVITE = 10,
	TCP_OBF_HTTP_SEARCH_TIEBA = 11,
	TCP_OBF_HTTP_SEARCH_C_TIEBA = 12,
	TCP_OBF_HTTP_SEARCH_DEEPSEEK_SCHOLAR = 13,
	TCP_OBF_HTTP_SEARCH_DEEPSEEK_KNS = 14,
	TCP_OBF_HTTP_SEARCH_ICOURSE163 = 15,
	TCP_OBF_HTTP_SEARCH_MOOC_STUDY_163 = 16,
	TCP_OBF_HTTP_SEARCH_KE_QQ = 17,
	TCP_OBF_HTTP_SEARCH_H5_KE_QQ = 18,
	TCP_OBF_HTTP_SEARCH_XHS_WWW = 19,
	TCP_OBF_HTTP_SEARCH_XHS_API = 20,
	TCP_OBF_HTTP_SEARCH_XHS_CREATOR = 21,
	TCP_OBF_HTTP_SEARCH_XIMALAYA_MOBILE = 22,
	TCP_OBF_HTTP_SEARCH_XIMALAYA_API = 23,
	TCP_OBF_HTTP_SEARCH_OPEN_163 = 24,
	TCP_OBF_HTTP_SEARCH_VOD_OPEN_163 = 25,
	TCP_OBF_HTTP_SEARCH_IMOOC = 26,
	TCP_OBF_HTTP_SEARCH_CODING_IMOOC = 27,
	TCP_OBF_HTTP_DOWNLOAD = 28,
	TCP_OBF_TLSV1_CLIENTHELLO = 29,

	TCP_OBF_PROTO_MAX
};

#endif // __GARBLE_SYSCTL_H__
