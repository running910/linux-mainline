#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/route.h>         
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>

#include "garble_sysctl.h"


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


typedef struct tcp_tuple_type {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
} tcp_tuple_t;

inline unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni);

inline unsigned char *build_http_request(unsigned char *buf, int *len, const char *host);

tcp_tuple_t *extract_tuple_info(struct sk_buff *skb, tcp_tuple_t *tuple)
{
	struct iphdr *iph;
        struct tcphdr *tcph;
	struct udphdr *udph;


        // skb->network_header 应该已经指向 IP 头（由协议栈设置）
        iph = ip_hdr(skb);
        if (!iph)
        	return NULL;

        // 协议号
        u8 protocol = iph->protocol;

        // IP 地址
        __be32 saddr = iph->saddr;
        __be32 daddr = iph->daddr;

        // 端口号
        __be16 sport = 0, dport = 0;

        if (protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (!tcph)
			return NULL;

		sport = tcph->source;
		dport = tcph->dest;

        } else if (protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (!udph)
			return NULL;

		sport = tcph->source;
		dport = tcph->dest;
        }

        printk(KERN_INFO "5-tuple: tcp %pI4:%u -> %pI4:%u proto=%u\n",
       &saddr, ntohs(sport), &daddr, ntohs(dport), protocol);

	tuple->daddr = daddr;
	tuple->saddr = saddr;
	tuple->dport = dport;
	tuple->sport = sport;

	return tuple;
}

struct sk_buff *generate_and_send_packet(tcp_tuple_t *tuple, const struct sock *sk, struct sk_buff *in_skb, char *payload, int payload_len)
{
	int tcp_hdr_len = sizeof(struct tcphdr);
	int ip_hdr_len = sizeof(struct iphdr);
	int total_len = ip_hdr_len + tcp_hdr_len + payload_len;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	u8 *data;
	struct net *net = sock_net(sk);

	//__log("before send tuple: %x sk: %x in_skb: %x", tuple, sk, in_skb);

	//printk(KERN_INFO "********* 5-tuple: tcp %pI4:%u -> %pI4:%u\n",
	//	&tuple->saddr, ntohs(tuple->sport), &tuple->daddr, ntohs(tuple->dport));

	// 分配 skb
	skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, LL_MAX_HEADER);  // 预留链路层头部空间
	skb_reset_network_header(skb);
	iph = (struct iphdr *)skb_put(skb, ip_hdr_len);  // 分配 IP 头空间
	tcph = (struct tcphdr *)skb_put(skb, tcp_hdr_len);  // 分配 TCP 头空间
	data = skb_put(skb, payload_len);  // 添加 payload 空间

	// 填充 payload
	memcpy(data, payload, payload_len);

	// 构造 TCP 头
	memset(tcph, 0, sizeof(struct tcphdr));
	tcph->source = tuple->dport;
	tcph->dest = tuple->sport;
	tcph->seq = htonl(1);  // 随便填个非零
	tcph->ack_seq = htonl(1);
	tcph->doff = tcp_hdr_len >> 2;
	tcph->ack = 1;
	tcph->psh = 1;
	tcph->window = htons(65535);
	tcph->check = 0;  // 先设为 0，稍后计算

	// 构造 IP 头
	memset(iph, 0, sizeof(struct iphdr));
	iph->version = 4;
	iph->ihl = ip_hdr_len >> 2;
	iph->tos = 0;
	iph->tot_len = htons(total_len);
	iph->id = htons(0);
	iph->frag_off = htons(IP_DF);
	iph->ttl = 3;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = tuple->daddr;  // 注意：对调，伪装为对方发出的方向
	iph->daddr = tuple->saddr;

	// 设置 skb 元数据
	skb->protocol = htons(ETH_P_IP);
	//skb->dev = in_skb->dev;    // NULL pointer
	skb->mark = in_skb->mark;
	skb->priority = 0;
	//skb->skb_iif = skb->dev->ifindex;  // 必炸

	// 校验 TCP checksum（需要伪首部）
	tcph->check = tcp_v4_check(tcp_hdr_len + payload_len,
	                           iph->saddr, iph->daddr,
	                           csum_partial(tcph, tcp_hdr_len + payload_len, 0));

	ip_send_check(iph);  // 计算 IP checksum

	struct rtable *rt;
	struct flowi4 fl4 = {
		.daddr = iph->daddr,
		.saddr = iph->saddr,
		.flowi4_proto = IPPROTO_TCP,
		.flowi4_tos = iph->tos,
	};

	rt = ip_route_output_key(net, &fl4); // 用 init_net 即可
	if (IS_ERR(rt)) {
		pr_err("ip_route_output_key failed: %ld\n", PTR_ERR(rt));
		kfree_skb(skb);
		return NULL;
	}

	//skb_dst_set(skb, &rt->dst);
	skb_dst_set(skb, &rt->dst);

	int ret = ip_local_out(net, (struct sock *)sk, skb);

	//__log("do really send ret %d", ret);

	//kfree_skb(skb);
	return NULL;
}

struct sk_buff *generate_and_send_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr, 
                                          __be16 sport, __be16 dport, const struct sock *sk, 
                                          char *payload, int payload_len)
{
	int tcp_hdr_len = sizeof(struct tcphdr);
	int ip6_hdr_len = sizeof(struct ipv6hdr);
	int total_len = ip6_hdr_len + tcp_hdr_len + payload_len;
	struct sk_buff *skb;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	u8 *data;
	struct net *net = sock_net(sk);
	struct flowi6 fl6;
	struct dst_entry *dst;
	int err;

	//__log("**** ipv6 tcp tls hello packet src %pI6c[port:%u] dst %pI6c[port:%u] ******", saddr, ntohs(sport), daddr, ntohs(dport));

	// Allocate skb
	skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, LL_MAX_HEADER);  // Reserve space for link layer header
	skb_reset_network_header(skb);
    
	// Add IPv6 header
	ip6h = (struct ipv6hdr *)skb_put(skb, ip6_hdr_len);
	// Add TCP header
	tcph = (struct tcphdr *)skb_put(skb, tcp_hdr_len);
	// Add payload
	data = skb_put(skb, payload_len);

	// Fill payload
	if (payload && payload_len > 0)
		memcpy(data, payload, payload_len);

	// Construct TCP header
	memset(tcph, 0, sizeof(struct tcphdr));
	tcph->source = sport; 
	tcph->dest = dport;
	tcph->seq = htonl(1);
	tcph->ack_seq = htonl(1);
	tcph->doff = tcp_hdr_len >> 2;
	tcph->ack = 1;
	tcph->psh = 1;
	tcph->window = htons(65535);
	tcph->check = 0;  // Will be calculated later

	// Construct IPv6 header
	memset(ip6h, 0, sizeof(struct ipv6hdr));
	ip6h->version = 6;
	ip6h->payload_len = htons(tcp_hdr_len + payload_len);
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->hop_limit = 3;
	ip6h->saddr = *saddr; 
	ip6h->daddr = *daddr;

	// Set skb metadata
	skb->protocol = htons(ETH_P_IPV6);
	skb->priority = 0;
	skb->mark = sk->sk_mark;

	// Calculate TCP checksum (with pseudo header)
	tcph->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
		tcp_hdr_len + payload_len,
		IPPROTO_TCP,
		csum_partial(tcph, tcp_hdr_len + payload_len, 0));

	// Set up flow for routing
	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_TCP;
	fl6.daddr = ip6h->daddr;
	fl6.saddr = ip6h->saddr;
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.flowi6_mark = sk->sk_mark;
	fl6.fl6_sport = tcph->source;
	fl6.fl6_dport = tcph->dest;

	// Get route
	dst = ip6_dst_lookup_flow(net, sk, &fl6, NULL);
	if (IS_ERR(dst)) {
		pr_err("ip6_dst_lookup_flow failed: %ld\n", PTR_ERR(dst));
		kfree_skb(skb);
		return NULL;
	}

	skb_dst_set(skb, dst);

	// Send the packet
	err = ip6_local_out(net, sk, skb);
	if (err) {
		pr_err("ip6_local_out failed: %d\n", err);
		return NULL;
	}

	return NULL;
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

static bool check_local_traffic_v6(struct in6_addr *sip, struct in6_addr *dip)
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

void response_tls_client_hello(struct sk_buff *skb, const struct sock *sk)
{
	tcp_tuple_t tuple;
	int mode;

	log_skb(skb, "helloooooooooooooo");

	if (garble_check_if_double_enabled()) {
		mode = prandom_u32() % 2;
	} else if (garble_check_if_tls_enabled()) {
		mode = 1;
	} else if (garble_check_if_http_enabled()) {
		mode = 0;
	// garble_check_if_enabled() must be true
	} else {
		return;
	}

	log_skb(skb, "helloooooooooooooo moddddd %d", mode);

	if (!skb || !sk)
		return;

	if (!extract_tuple_info(skb, &tuple))
		return;

	if (check_local_traffic(tuple.saddr, tuple.daddr))
		return;

	const char *sni = garble_get_random_domain();
	if (!sni)
		return;

	unsigned char payload[512];
	int payload_len;

	if (mode) {
		if (!build_tls_client_hello(payload, &payload_len, sni))
			return;
	} else {
		payload_len = sizeof(payload);
		if (!build_http_request(payload, &payload_len, sni))
			return;
	}

	__log("**** build tls success ******");

	generate_and_send_packet(&tuple, sk, skb, payload, payload_len);
}

void response_tls_client_hello_v6(const struct in6_addr *local, const struct in6_addr *remote, __be16 sport, __be16 dport, const struct sock *sk)
{
	if (!garble_check_if_enabled())
		return;

	if (!local || !remote)
		return;

	// it shows correct ip and port info
	//__log("**** ipv6 tcp syn arrives remote %pI6c[port:%u] local %pI6c[port:%u] ******", remote, ntohs(dport), local, ntohs(sport));

	if (check_local_traffic_v6(local, remote)) {
		//__log("local traffic");
		return;
	}

	const char *sni = garble_get_random_domain();
	if (!sni)
		return;

	unsigned char payload[512];
	int payload_len;

	if (!build_tls_client_hello(payload, &payload_len, sni))
		return;

	//__log("everything is all right");

	generate_and_send_packet_v6(local, remote, sport, dport, sk, payload, payload_len);
}

struct sk_buff *generate_and_send_udp_packet(struct sk_buff *skb, char *payload, int payload_len);



struct sk_buff *generate_and_send_udp_packet_v4(tcp_tuple_t *tuple, struct sk_buff *skb, char *payload, int payload_len)
{
	struct sk_buff *new_skb;
	//struct iphdr *iph;
	//struct udphdr *udph;
	struct iphdr *new_iph;
	struct udphdr *new_udph;
	u8 *data;
	int udp_hdr_len = sizeof(struct udphdr);
	int ip_hdr_len = sizeof(struct iphdr);
	int total_len;
	struct net *net;
	struct rtable *rt;
	struct flowi4 fl4;
	int ret;

	log_tuple_info(skb, "nothing.....");

	net = sock_net(skb->sk);
	if (!net)
		return NULL;

	//__log("great markkkkkkmark skb->sk 0x%p", skb->sk);

	//ip_hdr_len = iph->ihl * 4;
	total_len = ip_hdr_len + udp_hdr_len + payload_len;
//	net = dev_net(skb->dev);
	//__log("mark");
	/* Allocate new skb */
	new_skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!new_skb) {
		return NULL;
	}
	//__log("mark");
	/* Reserve space for link layer header */
	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_reset_network_header(new_skb);
	//__log("mark");
	/* Add IP header space */
	new_iph = (struct iphdr *)skb_put(new_skb, ip_hdr_len);
	
	/* Add UDP header space */
	new_udph = (struct udphdr *)skb_put(new_skb, udp_hdr_len);
	
	/* Add payload space */
	data = skb_put(new_skb, payload_len);

	/* Copy new payload */
	memcpy(data, payload, payload_len);

	/* Build UDP header - use same src/dst as original packet */
	memset(new_udph, 0, sizeof(struct udphdr));
	new_udph->source = tuple->saddr; 
	new_udph->dest = tuple->daddr;
	new_udph->len = htons(udp_hdr_len + payload_len);
	new_udph->check = 0;			/* Will be calculated later */

	/* Build IP header - use same src/dst as original packet */
	memset(new_iph, 0, sizeof(struct iphdr));
	new_iph->version = 4;
	new_iph->ihl = ip_hdr_len >> 2;
	new_iph->tos = 0;
	new_iph->tot_len = htons(total_len);
	new_iph->id = htons(0);
	new_iph->frag_off = htons(IP_DF);
	new_iph->ttl = 3;
	new_iph->protocol = IPPROTO_UDP;
	new_iph->saddr = tuple->saddr;
	new_iph->daddr = tuple->daddr;

	/* Set skb metadata */
	new_skb->protocol = htons(ETH_P_IP);
	new_skb->mark = skb->mark;
	new_skb->priority = skb->priority;

	/* Calculate UDP checksum (with pseudo-header) */
	new_udph->check = csum_tcpudp_magic(new_iph->saddr, new_iph->daddr,
					    udp_hdr_len + payload_len,
					    IPPROTO_UDP,
					    csum_partial(new_udph, udp_hdr_len + payload_len, 0));

	new_skb->cb[47] = 0xff;

	/* Calculate IP checksum */
	ip_send_check(new_iph);

	/* Prepare route */
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = new_iph->daddr;
	fl4.saddr = new_iph->saddr;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.flowi4_tos = new_iph->tos;

	/* Find route */
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(new_skb);
		return NULL;
	}

	skb_dst_set(new_skb, &rt->dst);

	new_skb->cb[47] = 147;

	log_skb(skb, "new packet skb %p", new_skb);

	/* Send packet */
	ret = ip_local_out(net, NULL, new_skb);
	if (ret < 0) {
	//	kfree_skb(new_skb);
		return NULL;
	}

	return new_skb;
}



void insert_udp_packet(struct sk_buff *skb)
{
	tcp_tuple_t tuple;

	if (!extract_tuple_info(skb, &tuple))
		return;

	if (check_local_traffic(tuple.saddr, tuple.daddr))
		return;


	generate_and_send_udp_packet(skb, "world", strlen("world"));
}

void garble_insert_udp_packet(struct sk_buff *skb)
{


	__log("protocollllllllllllllll: %d", ntohs(skb->protocol));

	if (skb->protocol == htons(ETH_P_IP))
		insert_udp_packet(skb);
        else if (skb->protocol == htons(ETH_P_IPV6))
		generate_and_send_udp_packet(skb, "world", strlen("world"));

}
