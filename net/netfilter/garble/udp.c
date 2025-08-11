#include <linux/ip.h>
//#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <net/route.h>         
#include <net/ip.h>
//#include <net/tcp.h>
#include <net/checksum.h>

#include "garble_sysctl.h"

//void log_tuple_info(const struct sk_buff *skb, const char *extra);

struct sk_buff *generate_and_send_udp_packet(struct sk_buff *skb, char *payload, int payload_len)
{
	struct sk_buff *new_skb;
	struct iphdr *iph;
	struct udphdr *udph;
	struct iphdr *new_iph;
	struct udphdr *new_udph;
	u8 *data;
	int udp_hdr_len = sizeof(struct udphdr);
	int ip_hdr_len;
	int total_len;
	struct net *net;
	struct rtable *rt;
	struct flowi4 fl4;
	int ret;


	log_tuple_info(skb, "nothing.....");

	//__log("mark");

	//log_skb(skb, "mark");


	/* Get IP header from original skb */
	iph = ip_hdr(skb);
	if (!iph) {
		return NULL;
	}
	//__log("mark");

	/* Check if this is an IPv4 packet */
	if (iph->version != 4) {
		return NULL;
	}
	//__log("mark");

	/* Get UDP header from original skb */
	if (iph->protocol != IPPROTO_UDP) {
		return NULL;
	}
	//	__log("mark");

	udph = udp_hdr(skb);
	if (!udph) {
		return NULL;
	}
	//__log("mark devvvv 0x%p", skb->dev);

	if (!skb->sk) {
		return NULL;
	}

	net = sock_net(skb->sk);

	if (!net)
		return NULL;

	//__log("great markkkkkkmark skb->sk 0x%p", skb->sk);

	ip_hdr_len = iph->ihl * 4;
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
	new_udph->source = udph->source;
	new_udph->dest = udph->dest;
	new_udph->len = htons(udp_hdr_len + payload_len);
	new_udph->check = 0;			/* Will be calculated later */

	/* Build IP header - use same src/dst as original packet */
	memset(new_iph, 0, sizeof(struct iphdr));
	new_iph->version = 4;
	new_iph->ihl = ip_hdr_len >> 2;
	new_iph->tos = iph->tos;
	new_iph->tot_len = htons(total_len);
	new_iph->id = htons(0);
	new_iph->frag_off = htons(IP_DF);
	new_iph->ttl = iph->ttl;
	new_iph->protocol = IPPROTO_UDP;
	new_iph->saddr = iph->saddr;
	new_iph->daddr = iph->daddr;

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
