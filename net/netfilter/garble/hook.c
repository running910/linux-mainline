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


#include "sysctl.h"
#include "packet.h"

#define GARBLE_MAX_TCP_PAYLOAD (512)

#define GARBLE_MAX_UDP_PAYLOAD (512)


// 127.0.0.0 -> 127.255.255.255
#define LOOPBACK_MASK    0xff000000
#define LOOPBACK_NETWORK 0x7f000000

#define IN6_IS_ADDR_LOOPBACK(a) \
        (__extension__                                                        \
        ({ const struct in6_addr *__a = (const struct in6_addr *) (a);        \
        __a->s6_addr32[0] == 0                                                \
        && __a->s6_addr32[1] == 0                                                     \
        && __a->s6_addr32[2] == 0                                                     \
        && __a->s6_addr32[3] == htonl (1); }))

#define IN6_IS_ADDR_V4MAPPED_LOOPBACK(a) \
        (__extension__({ const struct in6_addr *__a = (const struct in6_addr *) (a);          \
        __a->s6_addr32[0] == 0                                        \
        && __a->s6_addr32[1] == 0                                     \
        && __a->s6_addr32[2] == htonl (0xffff)        \
        && __a->s6_addr32[3] == htonl (0x7f000001); }))

#define IN6_IS_CONN_LOCAL(source, dest) \
        (__extension__({ const struct in6_addr *__s = (const struct in6_addr *) (source);             \
        const struct in6_addr *__d = (const struct in6_addr *) (dest);        \
        __s->s6_addr32[0] == __d->s6_addr32[0]                  \
        && __s->s6_addr32[1] == __d->s6_addr32[1]                       \
        && __s->s6_addr32[2] == __d->s6_addr32[2]                       \
        && __s->s6_addr32[3] == __d->s6_addr32[3]; }))

#define IN6_IS_ADDR_V4MAPPED(a) \
        (__extension__({ const struct in6_addr *__a = (const struct in6_addr *) (a);          \
        __a->s6_addr32[0] == 0                                        \
        && __a->s6_addr32[1] == 0                                     \
        && __a->s6_addr32[2] == htonl (0xffff); }))


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni);
inline unsigned char *build_http_request(unsigned char *buf, int *len, const char *host);
inline unsigned char *build_wechat_video_call_msg(unsigned char *buf, int *out_len);

#else

extern unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni);
extern unsigned char *build_http_request(unsigned char *buf, int *len, const char *host);
extern unsigned char *build_wechat_video_call_msg(unsigned char *buf, int *out_len);

#endif

garble_tuple_t *extract_tuple_info(struct sk_buff *skb, garble_tuple_t *tuple)
{
	struct iphdr *iph;
        struct tcphdr *tcph;
	struct udphdr *udph;

        // skb->network_header 应该已经指向 IP 头（由协议栈设置）
        iph = ip_hdr(skb);
        if (!iph)
        	return NULL;

        // 协议号
        tuple->protocol = iph->protocol;

        // IP 地址
        tuple->saddr = iph->saddr;
        tuple->daddr = iph->daddr;

        if (tuple->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return NULL;

		tuple->sport = tcph->source;
		tuple->dport = tcph->dest;

        } else if (tuple->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return NULL;

		tuple->sport = udph->source;
		tuple->dport = udph->dest;
        } else {
		return NULL;
	}

	return tuple;
}


static bool check_local_traffic(u32 sip, u32 dip)
{
	if ((ntohl(sip) & LOOPBACK_MASK) == LOOPBACK_NETWORK)
		return true;

	if ((ntohl(dip) & LOOPBACK_MASK) == LOOPBACK_NETWORK)
		return true;

	if (sip == dip) {
		return true;
	}

	return false;
}

static bool check_local_traffic_v6(const struct in6_addr *sip, const struct in6_addr *dip)
{

        if (IN6_IS_ADDR_LOOPBACK(sip) || IN6_IS_ADDR_LOOPBACK(dip))
                return true;
#if 0
        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(sip) || IN6_IS_ADDR_V4MAPPED_LOOPBACK(dip))
                return true;
#endif
        if (IN6_IS_CONN_LOCAL(sip, dip))
                return true;
#if 0
        // something needs to be paied attention here
        if (IN6_IS_ADDR_V4MAPPED(sip) || IN6_IS_ADDR_V4MAPPED(dip))
                return false;
#endif

        return false;
}

static inline unsigned char *generate_tcp_payload(unsigned char *buf, int *out_len)
{
        int mode;
        const char *domain = NULL;

        if (garble_check_if_tcp_double_enabled()) {
                mode = prandom_u32() % 2;
        } else if (garble_check_if_tls_enabled()) {
                mode = 1;
        } else if (garble_check_if_http_enabled()) {
                mode = 0;

        // this is impossible
        } else {
                return NULL;
        }

        domain = garble_get_random_domain();
        if (!domain)
                return NULL;

        if (mode) {
                if (!build_tls_client_hello(buf, out_len, domain))
                        return NULL;
        } else {
                if (!build_http_request(buf, out_len, domain))
                        return NULL;
        }

        return buf;
}


void garble_insert_tcp_packet(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const struct sock *sk)
{
        garble_tuple_t tuple;
        unsigned char payload[GARBLE_MAX_TCP_PAYLOAD];
        int payload_len = sizeof(payload);
        //__log("obvious new connection is comming saddr %x daddr %x sport %d dport %d sk %x",saddr, daddr, sport, dport, sk);

	 if (!saddr || !daddr || !sport || !dport || !sk)
                return;

        if (garble_check_if_tcp_disabled())
                return;

        // 与5.10内核的garble模块保持兼容，这里指的是
        // 远端发来的包的五元组，因此IP地址与端口对调
        tuple.daddr = saddr;
        tuple.saddr = daddr;
        tuple.dport = sport;
        tuple.sport = dport;

        if (check_local_traffic(tuple.saddr, tuple.daddr))
                return;


        if (!generate_tcp_payload(payload, &payload_len))
                return;

	generate_and_send_tcp_packet(&tuple, sk, NULL, payload, payload_len);
}

void garble_insert_tcp_packet_v6(const struct in6_addr *local, const struct in6_addr *remote, __be16 sport, __be16 dport, const struct sock *sk)
{
	unsigned char payload[GARBLE_MAX_TCP_PAYLOAD];
	int payload_len = sizeof(payload);

	if (!local || !remote)
		return;

        if (garble_check_if_tcp_disabled())
                return;

	// it shows correct ip and port info
	//__log("**** ipv6 tcp syn arrives remote %pI6c[port:%u] local %pI6c[port:%u] ******", remote, ntohs(dport), local, ntohs(sport));

	if (check_local_traffic_v6(local, remote)) {
		//__log("local traffic");
		return;
	}

        if (!generate_tcp_payload(payload, &payload_len))
                return;

        generate_and_send_tcp_packet_v6(local, remote, sport, dport, sk, payload, payload_len);
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
	case 3478:  // STUN
//		__log("well known port %d! ignore", nport);
		return true;
	default:
		return false;
	}
}

void insert_udp_packet(struct sk_buff *skb)
{
	garble_tuple_t tuple;	
	unsigned char payload[GARBLE_MAX_UDP_PAYLOAD];
	int payload_len;

	if (!extract_tuple_info(skb, &tuple))
		return;

        if (tuple.protocol != IPPROTO_UDP)
                return;

	if (check_local_traffic(tuple.saddr, tuple.daddr))
		return;

	if (check_if_well_known_udp_port(tuple.dport))
		return;

	if (!build_wechat_video_call_msg(payload, &payload_len))
		return;

	generate_and_send_udp_packet(&tuple, skb, payload, payload_len);
}

garble_tuple_v6_t *extract_tuple_info_v6(struct sk_buff *skb, garble_tuple_v6_t *tuple)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;

	ip6h = ipv6_hdr(skb);
	if (!ip6h)
		return NULL;

	tuple->protocol = ip6h->nexthdr;
	tuple->saddr = ip6h->saddr;
	tuple->daddr = ip6h->daddr;

	switch (tuple->protocol) {
	case IPPROTO_TCP:
		tcph = tcp_hdr(skb);
		if (!tcph)
			return NULL;
		tuple->sport = tcph->source;
		tuple->dport = tcph->dest;
		break;
		
	case IPPROTO_UDP:
		udph = udp_hdr(skb);
		if (!udph)
			return NULL;
		tuple->sport = udph->source;
		tuple->dport = udph->dest;
		break;
		
	default:
		return NULL;
	}

	return tuple;
}

void insert_udp_packet_v6(struct sk_buff *skb)
{
        garble_tuple_v6_t tuple;
        unsigned char payload[GARBLE_MAX_UDP_PAYLOAD];
	int payload_len;

        if (!extract_tuple_info_v6(skb, &tuple))
		return;

        if (tuple.protocol != IPPROTO_UDP)
                return;

        if (check_local_traffic_v6(&tuple.saddr, &tuple.daddr)) {
		return;
	}

        if (check_if_well_known_udp_port(tuple.dport))
		return;

	if (!build_wechat_video_call_msg(payload, &payload_len))
		return;

	generate_and_send_udp_packet_v6(&tuple, skb, payload, payload_len);
}

void garble_insert_udp_packet(struct sk_buff *skb)
{
	if (!garble_check_if_udp_enabled())
		return;

	if (skb->protocol == htons(ETH_P_IP))
		insert_udp_packet(skb);
        else if (skb->protocol == htons(ETH_P_IPV6))
		insert_udp_packet_v6(skb);
}

void garble_insert_udp_packet_aggressive(struct sk_buff *skb, __be16 protocol)
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
		insert_udp_packet(skb);
        else if (protocol == ETH_P_IPV6)
		insert_udp_packet_v6(skb);
}