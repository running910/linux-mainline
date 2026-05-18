#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/route.h>         
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/kernel.h>


#include "sysctl.h"
#include "packet.h"
#include "stun.h"


#define LOOPBACK_MASK           0Xff000000
#define LOOPBACK_ADDR		0x7f000000

// Class A network private IP range (10.0.0.0/8)
#define A_PRIVATE_START         0x0a000000  // 10.0.0.0
#define A_PRIVATE_END           0x0affffff  // 10.255.255.255

// Class B network private IP range 
#define B_PRIVATE_START         0xAC100000  // 172.16.0.0 (0xAC = 172)
#define B_PRIVATE_END           0xAC1FFFFF  // 172.31.255.255

// Class C network private IP range
#define C_PRIVATE_START         0xC0A80000  // 192.168.0.0
#define C_PRIVATE_END           0xC0A8FFFF  // 192.168.255.255


#define IPV6_LOOPBACK_0         0x00000000
#define IPV6_LOOPBACK_1         0x00000000  
#define IPV6_LOOPBACK_2         0x00000000
#define IPV6_LOOPBACK_3         0x00000001

#define IPV6_ULA_MASK_0         0xfe000000
#define IPV6_ULA_NET_0          0xfc000000

#define IPV6_LINK_LOCAL_MASK_0  0xffc00000
#define IPV6_LINK_LOCAL_NET_0   0xfe800000

#define IPV6_MULTICAST_MASK_0   0xff000000
#define IPV6_MULTICAST_NET_0    0xff000000


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni);
inline unsigned char *build_http_request(unsigned char *buf, int *len, const char *host);
inline unsigned char *build_udp_payload(unsigned char *buf, int *out_len,
					garble_tuple_t *tuple,
					garble_tuple_v6_t *tuple6);

#else

extern unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni);
extern unsigned char *build_http_request(unsigned char *buf, int *len, const char *host);
extern unsigned char *build_udp_payload(unsigned char *buf, int *out_len,
					garble_tuple_t *tuple,
					garble_tuple_v6_t *tuple6);

#endif

int check_local_ipaddr(u32 ipaddr)
{
	u32 local_order_ipaddr = ntohl(ipaddr);

	if ((local_order_ipaddr & LOOPBACK_MASK) == LOOPBACK_ADDR) {
		//__log("garble: loopback ipaddr %pI4", &ipaddr);
		return true;
	}

	if ((local_order_ipaddr >= A_PRIVATE_START) && (local_order_ipaddr <= A_PRIVATE_END)) {
		//__log("garble: Class A private ipaddr %pI4", &ipaddr);
		return true;
	}

	if ((local_order_ipaddr >= B_PRIVATE_START) && (local_order_ipaddr <= B_PRIVATE_END)) {
		//__log("garble: Class B private ipaddr %pI4", &ipaddr);
		return true;
	}

	if ((local_order_ipaddr >= C_PRIVATE_START) && (local_order_ipaddr <= C_PRIVATE_END)) {
		//__log("garble: Class C private ipaddr %pI4", &ipaddr);
		return true;
	}

	return false;
}

static bool check_local_traffic(u32 sip, u32 dip)
{
	//return false;

	if (sip == dip) {
		return true;
	}

	// Check if destination is local/private address
	if (check_local_ipaddr(dip)) {
		//pr_info("garble: local/private destination traffic, sip=%pI4 dip=%pI4\n", &sip, &dip);
		return true;
	}

	return false;
}

static int check_local_ipaddr_v6(const struct in6_addr *ipaddr)
{
	u32 *addr = (u32 *)ipaddr->s6_addr32;
	u32 addr0 = ntohl(addr[0]);
	u32 addr1 = ntohl(addr[1]);
	u32 addr2 = ntohl(addr[2]);
	u32 addr3 = ntohl(addr[3]);

	//return false;

	/* Check loopback address (::1/128) */
	if (addr0 == IPV6_LOOPBACK_0 && addr1 == IPV6_LOOPBACK_1 && 
		addr2 == IPV6_LOOPBACK_2 && addr3 == IPV6_LOOPBACK_3) {
		//__log("garble: IPv6 loopback address %pI6c", ipaddr);
		return true;
	}

	/* Check unique local address (FC00::/7) */
	if ((addr0 & IPV6_ULA_MASK_0) == IPV6_ULA_NET_0) {
		//__log("garble: IPv6 unique local address (ULA) %pI6c", ipaddr);
		return true;
	}

	/* Check link-local address (FE80::/10) */
	if ((addr0 & IPV6_LINK_LOCAL_MASK_0) == IPV6_LINK_LOCAL_NET_0) {
		//__log("garble: IPv6 link-local address %pI6c", ipaddr);
		return true;
	}

	/* Check multicast address (FF00::/8) */
	if ((addr0 & IPV6_MULTICAST_MASK_0) == IPV6_MULTICAST_NET_0) {
		//__log("garble: IPv6 multicast address %pI6c", ipaddr);
		return true;
	}

	/* Check IPv4-mapped IPv6 address (::FFFF:0:0/96) */
	if (addr0 == 0x00000000 && addr1 == 0x00000000 && addr2 == 0xffff0000) {
		//__log("garble: IPv4-mapped IPv6 address %pI6c", ipaddr);
		/* Check embedded IPv4 address */
		return check_local_ipaddr(addr3);
	}

	return false;
}

static bool check_local_traffic_v6(const struct in6_addr *sip, const struct in6_addr *dip)
{
	return check_local_ipaddr_v6(dip);
}

static inline bool check_if_well_known_tcp_port(__be16 port)
{
	u16 nport = ntohs(port);	/* 网络字节序转主机字节序 */

	/* 检查内核中已明确定义的TCP端口 */
	switch (nport) {
	case 20:	/* FTP 数据 */
	case 21:	/* FTP 控制 */
	case 22:	/* SSH */
	case 23:	/* Telnet */
	case 25:	/* SMTP */
	case 53:	/* DNS */
	case 80:	/* HTTP */
	case 110:	/* POP3 */
	case 143:	/* IMAP */
	case 443:	/* HTTPS */
	case 465:	/* SMTPS */
	case 587:	/* SMTP 提交 */
	case 993:	/* IMAPS */
	case 995:	/* POP3S */
	//case 3306:	/* MySQL */
	case 5432:	/* PostgreSQL */
	//case 8080:	/* HTTP 备用 */
		return true;
	default:
		return false;
	}
}

static inline bool check_if_well_known_udp_port(__be16 port)
{
	u16 nport = ntohs(port); // 网络字节序转主机字节序

	/* 检查内核中已明确定义的UDP端口 */
	switch (nport) {
	case 53:    // DNS 
	case 67:    // DHCP服务器
	case 68:    // DHCP客户端
	case 69:    // TFTP
	case 123:   // NTP
	case 161:   // SNMP 
	case 162:   // SNMP Trap
	case 500:   // ISAKMP/IKE
	case 514:   // Syslog
	case 520:   // RIP
	case 1900:  // UPnP SSDP
	case 5353:  // mDNS
	case 5355:  // LLMNR
//	case 3478:  // STUN
//		__log("well known port %d! ignore", nport);
		return true;
	default:
		return false;
	}
}

inline unsigned char *build_tcp_payload_from_binary(unsigned char *buf, int *out_len)
{
	int len;
	unsigned char *tmp;

	tmp = (unsigned char *)garble_get_tcp_payload(&len);
	if (!tmp)
		return NULL;

	memcpy(buf, tmp, len);
	*out_len = len;

	return buf;
}

static inline unsigned char *garble_tcp_put_be16(unsigned char *ptr, u16 val)
{
	*ptr++ = val >> 8;
	*ptr++ = val;
	return ptr;
}

static inline unsigned char *garble_tcp_put_be32(unsigned char *ptr, u32 val)
{
	*ptr++ = val >> 24;
	*ptr++ = val >> 16;
	*ptr++ = val >> 8;
	*ptr++ = val;
	return ptr;
}

static inline char garble_rand_alnum(void)
{
	static const char chars[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789";

	return chars[prandom_u32() % (sizeof(chars) - 1)];
}

static inline unsigned char *build_ssh_banner_payload(unsigned char *buf,
						      int *out_len)
{
	static const unsigned char banner_openssh_74[] = {
		0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d,
		0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f,
		0x37, 0x2e, 0x34, 0x0d, 0x0a,
	};
	static const unsigned char banner_openssh_89_ubuntu[] = {
		0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d,
		0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f,
		0x38, 0x2e, 0x39, 0x70, 0x31, 0x20, 0x55, 0x62,
		0x75, 0x6e, 0x74, 0x75, 0x2d, 0x33, 0x75, 0x62,
		0x75, 0x6e, 0x74, 0x75, 0x30, 0x2e, 0x34, 0x0d,
		0x0a,
	};
	const unsigned char *banner;
	int len;

	if (prandom_u32() & 1) {
		banner = banner_openssh_74;
		len = sizeof(banner_openssh_74);
	} else {
		banner = banner_openssh_89_ubuntu;
		len = sizeof(banner_openssh_89_ubuntu);
	}

	if (*out_len < len)
		return NULL;

	memcpy(buf, banner, len);
	*out_len = len;
	return buf;
}

static inline unsigned char *build_rtmp_handshake_payload(unsigned char *buf,
							  int *out_len)
{
	int len = min_t(int, *out_len, GARBLE_MAX_TCP_PAYLOAD);

	if (len < 9)
		return NULL;

	buf[0] = 0x03;
	garble_tcp_put_be32(buf + 1, prandom_u32());
	memset(buf + 5, 0, 4);
	get_random_bytes(buf + 9, len - 9);

	*out_len = len;
	return buf;
}

static inline unsigned char *build_mqtt_connect_payload(unsigned char *buf,
							int *out_len)
{
	unsigned char *ptr = buf;
	char client_id[18];
	int i;
	int client_id_len;
	int remaining_len;

	memcpy(client_id, "mqttx_", 7);
	for (i = 7; i < sizeof(client_id) - 1; i++)
		client_id[i] = garble_rand_alnum();
	client_id[sizeof(client_id) - 1] = '\0';
	client_id_len = strlen(client_id);
	remaining_len = 10 + 2 + client_id_len;

	if (*out_len < remaining_len + 2)
		return NULL;

	*ptr++ = 0x10;
	*ptr++ = remaining_len;
	*ptr++ = 0x00;
	*ptr++ = 0x04;
	memcpy(ptr, "MQTT", 4);
	ptr += 4;
	*ptr++ = 0x04;
	*ptr++ = 0x02;
	ptr = garble_tcp_put_be16(ptr, 60 + (prandom_u32() % 300));
	ptr = garble_tcp_put_be16(ptr, client_id_len);
	memcpy(ptr, client_id, client_id_len);
	ptr += client_id_len;

	*out_len = ptr - buf;
	return buf;
}

static inline unsigned char *build_postgres_startup_payload(unsigned char *buf,
							    int *out_len)
{
	static const char *users[] = { "postgres", "app", "admin" };
	static const char *dbs[] = { "postgres", "live", "app" };
	unsigned char *ptr = buf + 8;
	const char *user = users[prandom_u32() % ARRAY_SIZE(users)];
	const char *db = dbs[prandom_u32() % ARRAY_SIZE(dbs)];
	int len;

	if (*out_len < 96)
		return NULL;

	memcpy(ptr, "user", 5);
	ptr += 5;
	memcpy(ptr, user, strlen(user) + 1);
	ptr += strlen(user) + 1;
	memcpy(ptr, "database", 9);
	ptr += 9;
	memcpy(ptr, db, strlen(db) + 1);
	ptr += strlen(db) + 1;
	memcpy(ptr, "application_name", 17);
	ptr += 17;
	memcpy(ptr, "psql", 5);
	ptr += 5;
	*ptr++ = '\0';

	len = ptr - buf;
	garble_tcp_put_be32(buf, len);
	garble_tcp_put_be32(buf + 4, 0x00030000);

	*out_len = len;
	return buf;
}

static inline unsigned char *build_ftp_user_payload(unsigned char *buf,
						    int *out_len)
{
	static const char *users[] = {
		"anonymous",
		"ftp",
		"admin",
		"user",
		"upload",
	};
	const char *user = users[prandom_u32() % ARRAY_SIZE(users)];
	int len;

	len = scnprintf((char *)buf, *out_len, "USER %s\r\n", user);
	if (len <= 0 || len >= *out_len)
		return NULL;

	*out_len = len;
	return buf;
}

static inline unsigned char *generate_tcp_payload(unsigned char *buf, int *out_len,
						  garble_tuple_t *tuple,
						  garble_tuple_v6_t *tuple6)
{
        int proto;
        const char *domain = NULL;

	if (garble_check_if_tcp_binary_enabled()) {
		return build_tcp_payload_from_binary(buf, out_len);
        }

	(void)tuple6;

        if (garble_check_if_tcp_double_enabled()) {
                proto = (prandom_u32() % 2) ? TCP_OBF_TLS_CLIENTHELLO : TCP_OBF_HTTP;
	
        } else if (garble_check_if_tls_enabled()) {
                proto = TCP_OBF_TLS_CLIENTHELLO;
        } else if (garble_check_if_http_enabled()) {
                proto = TCP_OBF_HTTP;
        } else if (garble_check_if_tcp_obf_enabled()) {
                proto = garble_get_tcp_obf_proto();
		
        // this is impossible
        } else {
                return NULL;
        }

	if (tuple)
		log_ipaddr(tuple->daddr,
			   "garble: selected tcp obf proto id=%d name=%s",
			   proto, garble_get_tcp_obf_proto_name(proto));

	switch (proto) {
	case TCP_OBF_HTTP:
		domain = garble_get_random_domain();
		if (!domain)
			return NULL;
		return build_http_request(buf, out_len, domain);
	case TCP_OBF_TLS_CLIENTHELLO:
		domain = garble_get_random_domain();
		if (!domain)
			return NULL;
		return build_tls_client_hello(buf, out_len, domain);
	case TCP_OBF_SSH_BANNER:
		return build_ssh_banner_payload(buf, out_len);
	case TCP_OBF_RTMP_HANDSHAKE:
		return build_rtmp_handshake_payload(buf, out_len);
	case TCP_OBF_POSTGRES_STARTUP:
		return build_postgres_startup_payload(buf, out_len);
	case TCP_OBF_MQTT_CONNECT:
		return build_mqtt_connect_payload(buf, out_len);
	case TCP_OBF_FTP_USER:
		return build_ftp_user_payload(buf, out_len);
	case TCP_OBF_PAYLOAD_FILE:
		return garble_get_tcp_payload_file(buf, out_len);
	default:
		return NULL;
	}
}

void garble_insert_tcp_packet(__be32 saddr, __be32 daddr, __be16 sport,
			      __be16 dport, u32 seq, u32 ack_seq,
			      const struct net *net)
{
        unsigned char payload[GARBLE_MAX_TCP_PAYLOAD];
	garble_tuple_t tuple;
        int payload_len = sizeof(payload);
	int i;

	//__log("obvious new connection is comming saddr %x daddr %x sport %d dport %d net %x", saddr, daddr, sport, dport, net);

	if (!saddr || !daddr || !sport || !dport || !net)
                return;	

        if (garble_check_if_tcp_disabled())
                return;

	if (!garble_check_if_local_obf_enabled() && check_local_traffic(saddr, daddr))
		return;

	if (!garble_check_if_wellknown_port_obf_enabled() && check_if_well_known_tcp_port(dport))
                return;

	tuple.saddr = saddr;
	tuple.daddr = daddr;
	tuple.sport = sport;
	tuple.dport = dport;
	tuple.protocol = IPPROTO_TCP;

        if (!generate_tcp_payload(payload, &payload_len, &tuple, NULL))
                return;

	for (i = 0; i < garble_get_tcp_repeat_pkt(); i++)
		generate_and_send_tcp_packet(saddr, daddr, sport, dport, seq, ack_seq,
				     net, payload, payload_len);
}

void garble_insert_tcp_packet_v6(const struct in6_addr *saddr,
				 const struct in6_addr *daddr,
				 __be16 sport, __be16 dport,
				 u32 seq, u32 ack_seq,
				 const struct net *net)
{
	unsigned char payload[GARBLE_MAX_TCP_PAYLOAD];
	garble_tuple_v6_t tuple6;
	int payload_len = sizeof(payload);
	int i;

	if (!saddr || !daddr || !sport || !dport || !net)
		return;

        if (garble_check_if_tcp_disabled())
                return;

	// it shows correct ip and port info
	//__log("**** ipv6 tcp syn arrives remote %pI6c[port:%u] local %pI6c[port:%u] ******", daddr, ntohs(dport), saddr, ntohs(sport));

	if (!garble_check_if_local_obf_enabled() && check_local_traffic_v6(saddr, daddr)) {
		//__log("local traffic");
		return;
	}

	if (!garble_check_if_wellknown_port_obf_enabled() && check_if_well_known_tcp_port(dport))
                return;

	tuple6.saddr = *saddr;
	tuple6.daddr = *daddr;
	tuple6.sport = sport;
	tuple6.dport = dport;
	tuple6.protocol = IPPROTO_TCP;

        if (!generate_tcp_payload(payload, &payload_len, NULL, &tuple6))
                return;

	for (i = 0; i < garble_get_tcp_repeat_pkt(); i++)
		generate_and_send_tcp_packet_v6(saddr, daddr, sport, dport, seq,
					ack_seq, net, payload, payload_len);
}

void garble_insert_udp_packet(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const struct net *net)
{
	unsigned char payload[GARBLE_MAX_UDP_PAYLOAD];
	garble_tuple_t tuple;
	int payload_len;
	int i;

	if (!saddr || !daddr || !sport || !dport || !net)
		return;

	if (!garble_check_if_udp_enabled())
		return;

	if (!garble_check_if_local_obf_enabled() && check_local_traffic(saddr, daddr))
		return;

	if (!garble_check_if_wellknown_port_obf_enabled() && check_if_well_known_udp_port(dport))
		return;

	tuple.saddr = saddr;
	tuple.daddr = daddr;
	tuple.sport = sport;
	tuple.dport = dport;
	tuple.protocol = IPPROTO_UDP;

	payload_len = sizeof(payload);
	if (!build_udp_payload(payload, &payload_len, &tuple, NULL))
		return;

	for (i = 0; i < garble_get_udp_repeat_pkt(); i++)
		generate_and_send_udp_packet(saddr, daddr, sport, dport, net, payload, payload_len);

}
EXPORT_SYMBOL(garble_insert_udp_packet);

void garble_insert_udp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr, __be16 sport, __be16 dport, const struct net *net)
{
	unsigned char payload[GARBLE_MAX_UDP_PAYLOAD];
	garble_tuple_v6_t tuple6;
	int payload_len = sizeof(payload);
	int i;

	if (!saddr || !daddr || !sport || !dport || !net)
		return;

        if (!garble_check_if_udp_enabled())
		return;

	if (!garble_check_if_local_obf_enabled() && check_local_traffic_v6(saddr, daddr)) {
		return;
	}

	if (!garble_check_if_wellknown_port_obf_enabled() && check_if_well_known_udp_port(dport))
                return;

	tuple6.saddr = *saddr;
	tuple6.daddr = *daddr;
	tuple6.sport = sport;
	tuple6.dport = dport;
	tuple6.protocol = IPPROTO_UDP;

 	payload_len = sizeof(payload);
	if (!build_udp_payload(payload, &payload_len, NULL, &tuple6))
		return;

	for (i = 0; i < garble_get_udp_repeat_pkt(); i++)
		generate_and_send_udp_packet_v6(saddr, daddr, sport, dport, net, payload, payload_len);
}

void insert_packet_with_skb(struct sk_buff *skb, const struct net *net,
			    int reverse, u32 seq, u32 ack_seq)
{
	garble_tuple_t tuple;
	garble_tuple_v6_t tuple6;

	if (!skb || !net)
		return;

	if (skb->protocol == htons(ETH_P_IP)) {

	        if (!extract_tuple_info(skb, &tuple))
		        return;

		if (tuple.protocol == IPPROTO_TCP) {

			if (reverse) {
				garble_insert_tcp_packet(tuple.daddr, tuple.saddr,
							 tuple.dport, tuple.sport,
							 seq, ack_seq, net);
			} else {
				garble_insert_tcp_packet(tuple.saddr, tuple.daddr,
							 tuple.sport, tuple.dport,
							 seq, ack_seq, net);
			}
		} else if (tuple.protocol == IPPROTO_UDP) {

			if (reverse) {
				garble_insert_udp_packet(tuple.daddr, tuple.saddr, tuple.dport, tuple.sport, net);
			} else {
				garble_insert_udp_packet(tuple.saddr, tuple.daddr, tuple.sport, tuple.dport, net);
			}
		}

        } else if (skb->protocol == htons(ETH_P_IPV6)) {

	        if (!extract_tuple_info_v6(skb, &tuple6))
		        return;

		if (tuple6.protocol == IPPROTO_TCP) {

			if (reverse)
				garble_insert_tcp_packet_v6(&tuple6.daddr, &tuple6.saddr,
							    tuple6.dport,
							    tuple6.sport,
							    seq, ack_seq, net);
			else
				garble_insert_tcp_packet_v6(&tuple6.saddr, &tuple6.daddr,
							    tuple6.sport,
							    tuple6.dport,
							    seq, ack_seq, net);
		} else if (tuple6.protocol == IPPROTO_UDP) {

			if (reverse)				
				garble_insert_udp_packet_v6(&tuple6.daddr, &tuple6.saddr, tuple6.dport, tuple6.sport, net);
			else			
				garble_insert_udp_packet_v6(&tuple6.saddr, &tuple6.daddr, tuple6.sport, tuple6.dport, net);
		
		}
        }
}

void garble_insert_udp_packet_aggressive(struct sk_buff *skb, __be16 protocol, struct net *net)
{
        if (!garble_check_if_udp_enabled())
		return;

        if (!garble_check_if_udp_aggressive())
		return;

        if (unlikely(!garble_get_udp_avg_pkt()))
                return;

        if (prandom_u32() % garble_get_udp_avg_pkt() != 0)
                return;

	if (protocol == ETH_P_IP)
		insert_packet_with_skb(skb, net, 0, 0, 0);
	else if (protocol == ETH_P_IPV6)
		insert_packet_with_skb(skb, net, 0, 0, 0);
}

// calling path:
// case1: tcp_rcv_state_process => case TCP_SYN_SENT: => tcp_rcv_synsent_state_process => after tcp_send_ack()
void garble_insert_tcp_packet_client(struct sk_buff *skb, u32 seq,
				     u32 ack_seq, const struct net *net)
{
	if (!garble_check_if_tcp_client_enabled())
		return;

	insert_packet_with_skb(skb, net, 1, seq, ack_seq);
}

// calling path
// case 1: tcp_transmit_skb => __tcp_transmit_skb before return
void garble_insert_tcp_packet_aggressive(struct sk_buff *skb, const struct net *net)
{

	//log_skb(skb, "garble: aggressive tcp packet insert, skb %p", skb);

	if (!garble_check_if_tcp_aggressive())
		return;

	if (unlikely(!garble_get_tcp_avg_pkt()))
                return;

	if (prandom_u32() % garble_get_tcp_avg_pkt() != 0)
                return;

	//log_skb(skb, "garble: aggressive tcp packet insert!!!!!!!!!!!!!");

	insert_packet_with_skb(skb, net, 0, 0, 0);
}
