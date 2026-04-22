#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/route.h>         
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/random.h>
#include <linux/version.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_garble.h>


#include "sysctl.h"
#include "packet.h"


#define GARBLE_PACKET_TTL (3)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
extern __sum16
csum_ipv6_magic(const struct in6_addr *saddr, const struct in6_addr *daddr,
		__u32 len, __u8 proto, __wsum sum);
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

struct sk_buff *generate_and_send_tcp_packet(__be32 saddr, __be32 daddr,
					     __be16 sport, __be16 dport,
					     u32 seq, u32 ack_seq,
					     const struct net *net, char *payload,
					     int payload_len)
{
	int tcp_hdr_len = sizeof(struct tcphdr);
	int ip_hdr_len = sizeof(struct iphdr);
	int total_len = ip_hdr_len + tcp_hdr_len + payload_len;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	u8 *data;
	struct rtable *rt;
	struct flowi4 fl4;

	//__log("before send tuple: %x sk: %x in_skb: %x", tuple, sk, in_skb);

	//printk(KERN_INFO "********* 5-tuple: tcp %pI4:%u -> %pI4:%u\n", &saddr, ntohs(sport), &daddr, ntohs(dport));

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
	tcph->source = sport;
	tcph->dest = dport;
	tcph->seq = htonl(seq ? seq : get_random_u32());
	tcph->ack_seq = htonl(ack_seq ? ack_seq : get_random_u32());
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
	iph->ttl = garble_get_tcp_ttl();
	iph->protocol = IPPROTO_TCP;
	iph->saddr = saddr;
	iph->daddr = daddr;

	// 设置 skb 元数据
	skb->protocol = htons(ETH_P_IP);
	//skb->dev = in_skb->dev;    // NULL pointer
	//skb->mark = in_skb->mark;
	skb->priority = 0;
	//skb->skb_iif = skb->dev->ifindex;  // 必炸

	// 校验 TCP checksum（需要伪首部）
	tcph->check = tcp_v4_check(tcp_hdr_len + payload_len,
	                           iph->saddr, iph->daddr,
	                           csum_partial(tcph, tcp_hdr_len + payload_len, 0));

	ip_send_check(iph);  // 计算 IP checksum

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = iph->daddr;
	fl4.saddr = iph->saddr;
	fl4.flowi4_proto = IPPROTO_TCP;
	fl4.flowi4_tos = iph->tos;

	rt = ip_route_output_key((struct net *)net, &fl4); 
	if (IS_ERR(rt)) {
		pr_err("ip_route_output_key failed: %ld\n", PTR_ERR(rt));
		kfree_skb(skb);
		return NULL;
	}

	//skb_dst_set(skb, &rt->dst);
	skb_dst_set(skb, &rt->dst);

	garble_mark_obfuscation_packet(skb);

	//ip_local_out(net, (struct sock *)sk, skb);
	ip_local_out((struct net *)net, NULL, skb);

	//kfree_skb(skb);
	return NULL;
}

struct sk_buff *generate_and_send_tcp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr,
						__be16 sport, __be16 dport,
						u32 seq, u32 ack_seq,
						const struct net *net,
						char *payload, int payload_len)
{
	int tcp_hdr_len = sizeof(struct tcphdr);
	int ip6_hdr_len = sizeof(struct ipv6hdr);
	int total_len = ip6_hdr_len + tcp_hdr_len + payload_len;
	struct sk_buff *skb;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	u8 *data;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int err;

	if (!net) {
		return NULL;
	}

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
	tcph->seq = htonl(seq ? seq : get_random_u32());
	tcph->ack_seq = htonl(ack_seq ? ack_seq : get_random_u32());
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
	ip6h->hop_limit = garble_get_tcp_ttl();
	ip6h->saddr = *saddr; 
	ip6h->daddr = *daddr;

	// Set skb metadata
	skb->protocol = htons(ETH_P_IPV6);
	skb->priority = 0;
	skb->mark = 0;

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
	fl6.flowi6_oif = 0;
	fl6.flowi6_mark = 0;
	fl6.fl6_sport = tcph->source;
	fl6.fl6_dport = tcph->dest;

	// Get route
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	dst = ip6_dst_lookup_flow(NULL, &fl6, NULL);
#else
	dst = ip6_dst_lookup_flow((struct net *)net, NULL, &fl6, NULL);
#endif
	if (IS_ERR(dst)) {
		pr_err("ip6_dst_lookup_flow failed: %ld\n", PTR_ERR(dst));
		kfree_skb(skb);
		return NULL;
	}

	skb_dst_set(skb, dst);

	garble_mark_obfuscation_packet(skb);

	// Send the packet
	err = ip6_local_out((struct net *)net, NULL, skb);
	if (err) {
		pr_err("ip6_local_out failed: %d\n", err);
		return NULL;
	}

	return NULL;
}

struct sk_buff *generate_and_send_udp_packet(__be32 saddr, __be32 daddr, __be16 sport, 
					     __be16 dport, const struct net *net, 
					     char *payload, int payload_len)
{
	struct sk_buff *new_skb;
	struct iphdr *new_iph;
	struct udphdr *new_udph;
	u8 *data;
	int udp_hdr_len = sizeof(struct udphdr);
	int ip_hdr_len = sizeof(struct iphdr);
	int total_len;
	struct rtable *rt;
	struct flowi4 fl4;
	int ret;

	total_len = ip_hdr_len + udp_hdr_len + payload_len;

	/* Allocate new skb */
	new_skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!new_skb) {
		return NULL;
	}

	/* Reserve space for link layer header */
	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_reset_network_header(new_skb);

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
	new_udph->source = sport; 
	new_udph->dest = dport;
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
	new_iph->ttl = garble_get_udp_ttl();
	new_iph->protocol = IPPROTO_UDP;
	new_iph->saddr = saddr;
	new_iph->daddr = daddr;

	/* Set skb metadata */
	new_skb->protocol = htons(ETH_P_IP);
	new_skb->mark = 0;
	new_skb->priority = 0;

	/* Calculate UDP checksum (with pseudo-header) */
	new_udph->check = csum_tcpudp_magic(new_iph->saddr, new_iph->daddr,
					    udp_hdr_len + payload_len,
					    IPPROTO_UDP,
					    csum_partial(new_udph, udp_hdr_len + payload_len, 0));

	/* Calculate IP checksum */
	ip_send_check(new_iph);

	/* Prepare route */
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = new_iph->daddr;
	fl4.saddr = new_iph->saddr;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.flowi4_tos = new_iph->tos;

	/* Find route */
	rt = ip_route_output_key((struct net *)net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(new_skb);
		return NULL;
	}

	skb_dst_set(new_skb, &rt->dst);

	garble_mark_obfuscation_packet(new_skb);

	/* Send packet */
	ret = ip_local_out((struct net *)net, NULL, new_skb);
	if (ret < 0) {
	//	kfree_skb(new_skb);
		return NULL;
	}

	return new_skb;
}

struct sk_buff *generate_and_send_udp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr,
					        __be16 sport, __be16 dport, const struct net *net, 
						char *payload, int payload_len)
{
	int udp_hdr_len = sizeof(struct udphdr);
	int ip6_hdr_len = sizeof(struct ipv6hdr);
	int total_len = ip6_hdr_len + udp_hdr_len + payload_len;
	struct sk_buff *new_skb;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	u8 *data;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int err;

	/* Allocate new skb */
	new_skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC);
	if (!new_skb) {
		return NULL;
	}

	/* Reserve space for link layer header */
	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_reset_network_header(new_skb);

	/* Add IPv6 header */
	ip6h = (struct ipv6hdr *)skb_put(new_skb, ip6_hdr_len);
	/* Add UDP header */
	udph = (struct udphdr *)skb_put(new_skb, udp_hdr_len);
	/* Add payload */
	data = skb_put(new_skb, payload_len);

	/* Fill payload */
	if (payload && payload_len > 0) {
		memcpy(data, payload, payload_len);
	}

	/* Set transport header AFTER building the packet */
	/* so that log_tuple_info6 could display port info*/
	skb_set_transport_header(new_skb, ip6_hdr_len);

	/* Build UDP header */
	memset(udph, 0, sizeof(struct udphdr));
	udph->source = sport;
	udph->dest = dport;
	udph->len = htons(udp_hdr_len + payload_len);
	udph->check = 0;  /* Will be calculated later */

	/* Build IPv6 header */
	memset(ip6h, 0, sizeof(struct ipv6hdr));
	ip6h->version = 6;
	ip6h->payload_len = htons(udp_hdr_len + payload_len);
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = garble_get_udp_ttl();
	ip6h->saddr = *saddr;
	ip6h->daddr = *daddr;

	/* Set skb metadata */
	new_skb->protocol = htons(ETH_P_IPV6);
	new_skb->priority = 0;
	new_skb->mark = 0;

	/* Calculate UDP checksum */
	udph->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
				     udp_hdr_len + payload_len,
				     IPPROTO_UDP,
				     csum_partial(udph, udp_hdr_len + payload_len, 0));

	/* Set up flow for routing */
	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_UDP;
	fl6.daddr = ip6h->daddr;
	fl6.saddr = ip6h->saddr;
	//if (skb->sk)
	//	fl6.flowi6_oif = skb->sk->sk_bound_dev_if;
	fl6.flowi6_mark = 0;
	fl6.fl6_sport = udph->source;
	fl6.fl6_dport = udph->dest;

	/* Get route */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
        dst = ip6_dst_lookup_flow(skb->sk, &fl6, NULL);
#else
        dst = ip6_dst_lookup_flow((struct net *)net, NULL, &fl6, NULL);
#endif

	if (IS_ERR(dst)) {
		pr_err("ip6_dst_lookup_flow failed: %ld\n", PTR_ERR(dst));
		kfree_skb(new_skb);
		return NULL;
	}

	skb_dst_set(new_skb, dst);

	garble_mark_obfuscation_packet(new_skb);

	/* Send packet */
	err = ip6_local_out((struct net *)net, NULL, new_skb);
	if (err) {
		pr_err("ip6_local_out failed: %d\n", err);
		return NULL;
	}

	return NULL;
}