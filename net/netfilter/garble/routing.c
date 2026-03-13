#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_garble.h>

#include "sysctl.h"
#include "packet.h"

extern void insert_packet_with_skb(struct sk_buff *skb, const struct net *net, int reverse);

const char *garble_get_nf_hook_point(enum nf_inet_hooks hook)
{
	switch (hook) {
	case NF_INET_PRE_ROUTING:
		return "PRE_ROUTING";
	case NF_INET_LOCAL_IN:
		return "LOCAL_IN";
	case NF_INET_FORWARD:
		return "FORWARD";
	case NF_INET_LOCAL_OUT:
		return "LOCAL_OUT";
	case NF_INET_POST_ROUTING:
		return "POST_ROUTING";
	default:
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL(garble_get_nf_hook_point);

__u8 garble_get_trans_proto(struct sk_buff *skb)
{
        if (skb->protocol == htons(ETH_P_IP)) {
                const struct iphdr *iph = ip_hdr(skb);
                if (!iph)
                        return 0;
                return iph->protocol;

        // 暂不考虑扩展头的情况，因为连接首包通常不会携带扩展头
        } else if (skb->protocol == htons(ETH_P_IPV6)) {
                const struct ipv6hdr *ip6h = ipv6_hdr(skb);
                if (!ip6h)
                        return 0;
                return ip6h->nexthdr;
        } else {
                return 0;
        }
}

// 处理该路径首包：[outer -> wan -> lan -> inner]路径的连接首包
// 因为尚未知SNAT后的地址，无法处理该路径首包：[inner -> lan -> wan -> outer]
static unsigned int garble_forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
        enum ip_conntrack_info ctinfo;
        const struct nf_conntrack_tuple *otuple;
        struct nf_conn *ct;

        if (!garble_check_if_routing_enabled())
		return NF_ACCEPT;

        // 该hook只处理路径[outer -> wan -> lan -> inner]的连接首包，因此必须是root网络命名空间
        if (state->net != &init_net)
                return NF_ACCEPT;

#if 0
        // 需要结合网卡名判断，无法获取网卡名直接放行，避免误伤
        if (!skb->dev) {
                __log("skb->dev is NULL, bypass routing hook");
                return NF_ACCEPT;
        }
#endif
        // 只对新连接的首包感兴趣
        if (!garble_check_if_conn_first_packet(skb)) {
                return NF_ACCEPT;
        }

        // 必须不能是从LAN网卡发出的包，因为LAN网卡发出的包会在post routing hook处理
        if (state->in && garble_check_if_lan_nic(state->in->name)) {
                __log("first packet of new connection from lan nic %s, should be handle in post routing", state->in->name);
                return NF_ACCEPT;
        }

#if 0 
        if (garble_check_if_lan_nic(skb->dev->name)) {
                __log("first packet of new connection from lan nic %s, should be handle in post routing", skb->dev->name);
                return NF_ACCEPT;
        }
#endif

	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);

                if (!iph)
                        return NF_ACCEPT;

                ct = nf_ct_get(skb, &ctinfo);
                if (!ct) {
                        __log("no ct found for skb %p, dev %s", skb, skb->dev ? skb->dev->name : "-");
                        return NF_ACCEPT;
                }

                otuple = nf_ct_tuple(ct, IP_CT_DIR_ORIGINAL);
                if (!otuple) {
                        __log("has ct %p but no orig tuple", ct);
                        return NF_ACCEPT;
                }

                __log("ORIG tuple: %pI4:%u -> %pI4:%u", &otuple->src.u3.ip, ntohs(otuple->src.u.tcp.port), &otuple->dst.u3.ip, ntohs(otuple->dst.u.tcp.port));

                if (iph->protocol == IPPROTO_TCP) {
                        __log("first packet protocol: TCP (IPv4) in=%s out=%s skb=%s",
                                state->in ? state->in->name : "-",
                                state->out ? state->out->name : "-",
                                skb->dev ? skb->dev->name : "-");

                        __log("now insert obfuscation packet for this new connection tuple: %pI4:%u -> %pI4:%u",
                                &otuple->dst.u3.ip, ntohs(otuple->dst.u.tcp.port),
                                &otuple->src.u3.ip, ntohs(otuple->src.u.tcp.port));

                        garble_insert_tcp_packet(otuple->dst.u3.ip, otuple->src.u3.ip, otuple->dst.u.tcp.port, otuple->src.u.tcp.port, state->net);

                } else if (iph->protocol == IPPROTO_UDP) {
                        __log("first packet protocol: UDP (IPv4) in=%s out=%s skb=%s",
                                state->in ? state->in->name : "-",
                                state->out ? state->out->name : "-",
                                skb->dev ? skb->dev->name : "-");

                        __log("now insert obfuscation packet for this new connection tuple: %pI4:%u -> %pI4:%u",
                                &otuple->dst.u3.ip, ntohs(otuple->dst.u.tcp.port),
                                &otuple->src.u3.ip, ntohs(otuple->src.u.tcp.port)); 

                        garble_insert_udp_packet(otuple->dst.u3.ip, otuple->src.u3.ip, otuple->dst.u.tcp.port, otuple->src.u.tcp.port, state->net);

                } else {
                        return NF_ACCEPT;
                }

        } else if (state->pf == NFPROTO_IPV6) {
                const struct ipv6hdr *ip6h = ipv6_hdr(skb);

                if (!ip6h)
                        return NF_ACCEPT;

                if (ip6h->nexthdr == IPPROTO_TCP) {
                        __log("first packet protocol: TCP (IPv6) in=%s out=%s skb=%s",
                                state->in ? state->in->name : "-",
                                state->out ? state->out->name : "-",
                                skb->dev ? skb->dev->name : "-");
                } else if (ip6h->nexthdr == IPPROTO_UDP) {
                        __log("first packet protocol: UDP (IPv6) in=%s out=%s skb=%s",
                                state->in ? state->in->name : "-",
                                state->out ? state->out->name : "-",
                                skb->dev ? skb->dev->name : "-");
                } else {
                        return NF_ACCEPT;
                }
        }

        return NF_ACCEPT;
}

// 处理该路径的udp首包：[outer -> wan -> local]
static unsigned int garble_local_in_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
        // 只对新连接的首包感兴趣
        if (!garble_check_if_conn_first_packet(skb)) {
                return NF_ACCEPT;
        }

        // TCP交由TCP模块处理，UDP直接插入混淆包
        if (garble_get_trans_proto(skb) != IPPROTO_UDP) {
                return NF_ACCEPT;
        }

        __log("######### first packet of new udp connection!!!!!!!!! hook point: %s", garble_get_nf_hook_point(state->hook));
        log_tuple_info(skb, "now insert obfuscation packet for this packet of new connection with reversing src and dst");
        __log("in=%s out=%s skb=%s", state->in ? state->in->name : "-", state->out ? state->out->name : "-", skb->dev ? skb->dev->name : "-");

        insert_packet_with_skb(skb, state->net, 1);

        return NF_ACCEPT;
}

// 处理该路径的udp首包：[local -> wan -> outer]
static unsigned int garble_local_out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
        // 只对新连接的首包感兴趣
        if (!garble_check_if_conn_first_packet(skb)) {
                return NF_ACCEPT;
        }

        // TCP交由TCP模块处理，UDP直接插入混淆包
        if (garble_get_trans_proto(skb) != IPPROTO_UDP) {
                return NF_ACCEPT;
        }

	__log("######### first packet of new connection!!!!!!!!! hook point: %s", garble_get_nf_hook_point(state->hook));

        log_tuple_info(skb, "now insert obfuscation packet for this packet of new connection without reversing");
        __log("in=%s out=%s skb=%s", state->in ? state->in->name : "-", state->out ? state->out->name : "-", skb->dev ? skb->dev->name : "-");

        insert_packet_with_skb(skb, state->net, 0);

        // 避免后续hook重复处理
        garble_clear_packet_mark(skb);

	return NF_ACCEPT;
}

// 处理该路径的udp首包：[inner -> lan -> wan -> outer]
static unsigned int garble_post_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
        __u8 proto;

        // 只对新连接的首包感兴趣
        if (!garble_check_if_conn_first_packet(skb)) {
                return NF_ACCEPT;
        }

        // 该hook只处理路径[inner -> lan -> wan -> outer]的连接首包，因此必须是root网络命名空间
        if (state->net != &init_net)
                return NF_ACCEPT;

        // 只处理lan nic发出的连接首包
        if (!state->in || !garble_check_if_lan_nic(state->in->name)) {
                __log("first packet of new connection not from lan nic, should have been handled !in nic:%s", state->in ? state->in->name : "-");
                return NF_ACCEPT;
        } 

        __log("######### first packet of new connection!!!!!!!!! hook point: %s", garble_get_nf_hook_point(state->hook));

        __log("in=%s out=%s skb=%s", state->in ? state->in->name : "-", state->out ? state->out->name : "-", skb->dev ? skb->dev->name : "-");

        if ((garble_get_trans_proto(skb) == IPPROTO_TCP) && (!garble_check_if_tcp_client_enabled())) {
                return NF_ACCEPT;
        }   
        
        proto = garble_get_trans_proto(skb);
        if (proto != IPPROTO_UDP && proto != IPPROTO_TCP) {
                return NF_ACCEPT;
        }

        if ((proto == IPPROTO_TCP) && !garble_check_if_tcp_client_enabled()) {
                return NF_ACCEPT;
        }

        log_tuple_info(skb, "now insert obfuscation packet for this packet of new connection with SNATed src");
        insert_packet_with_skb(skb, state->net, 0);

	return NF_ACCEPT;
}
static struct nf_hook_ops garble_forward_ops[] = {
	{
		.hook		= garble_forward_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_FILTER,
	},
	{
		.hook		= garble_forward_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP6_PRI_FILTER,
	},
	{
		.hook		= garble_local_in_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_FILTER,
	},
	{
		.hook		= garble_local_in_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP6_PRI_FILTER,
	},
	{
		.hook		= garble_local_out_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FILTER,  // must be after NF_IP_PRI_CONNTRACK
	},
	{
		.hook		= garble_local_out_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_FILTER,
	},
	{
		.hook		= garble_post_routing_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_LAST,   // must be after NF_IP_PRI_NAT_SRC
	},
	{
		.hook		= garble_post_routing_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_FILTER,
	},
};

int garble_routing_init(void)
{
	return nf_register_net_hooks(&init_net, garble_forward_ops, ARRAY_SIZE(garble_forward_ops));
}

void garble_routing_exit(void)
{
	nf_unregister_net_hooks(&init_net, garble_forward_ops, ARRAY_SIZE(garble_forward_ops));
}
