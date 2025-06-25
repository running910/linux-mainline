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


typedef struct tcp_tuple_type {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
} tcp_tuple_t;

unsigned char *build_tls_client_hello(unsigned char *buf, int *out_len, const char *sni);

tcp_tuple_t *extract_tuple_info(struct sk_buff *skb, tcp_tuple_t *tuple)
{
	struct iphdr *iph;
        struct tcphdr *tcph;

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

        } else {
		return NULL;
        }

      //  printk(KERN_INFO "5-tuple: tcp %pI4:%u -> %pI4:%u proto=%u\n",
      //  &saddr, ntohs(sport), &daddr, ntohs(dport), protocol);

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
//	skb->mark = in_skb->mark;
	skb->mark = sk->sk_mark;
	skb->priority = sk->sk_priority;

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

void response_tls_client_hello(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const struct sock *sk)
{
	tcp_tuple_t tuple;

	//__log("obvious new connection is comming saddr %x daddr %x sport %d dport %d sk %x",saddr, daddr, sport, dport, sk);

	if (!garble_check_if_enabled())
		return;

	if (!saddr || !daddr || !sport || !dport || !sk)
		return;

	// 与5.10内核的garble模块保持兼容，这里指的是
	// 远端发来的包的五元组，因此IP地址与端口对调
	tuple.daddr = saddr;
	tuple.saddr = daddr;
	tuple.dport = sport;
	tuple.sport = dport;

//	if (!extract_tuple_info(skb, &tuple))
//		return;

	if (check_local_traffic(tuple.saddr, tuple.daddr))
		return;

	const char *sni = garble_get_random_domain();
	if (!sni)
		return;

	unsigned char payload[512];
	int payload_len;

	//__log("**** build tls starts ******");

	if (!build_tls_client_hello(payload, &payload_len, sni))
		return;

	//__log("**** build tls success ******");

	generate_and_send_packet(&tuple, sk, NULL, payload, payload_len);
}
