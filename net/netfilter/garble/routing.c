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

static unsigned int garble_forward_hook(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
        if (!garble_check_if_routing_enabled())
		return NF_ACCEPT;

        if (state->net != &init_net)
                return NF_ACCEPT;

        // 需要结合网卡名判断，无法获取网卡名直接放行，避免误伤
        if (!skb->dev) {
                __log("skb->dev is NULL, bypass routing hook");
                return NF_ACCEPT;
        }

        // 只对新连接的首包感兴趣
        if (!garble_check_if_conn_first_packet(skb)) {
                return NF_ACCEPT;
        }

        // 这里只处理路径[outer -> wan -> lan -> inner]的连接首包
        // 路径[inner -> lan -> wan -> outer]的连接首包在postrouting处理，因为尚无SNAT地址
        if (garble_check_if_lan_nic(skb->dev->name)) {
                __log("first packet of new connection from lan nic %s, should be handle in post routing", skb->dev->name);
                return NF_ACCEPT;
        }

	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);

                if (!iph)
                        return NF_ACCEPT;

                        
                enum ip_conntrack_info ctinfo;
                struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
                if (!ct) {
                        __log("no ct found for skb %p, dev %s", skb, skb->dev ? skb->dev->name : "-");
                        return NF_ACCEPT;
                }

                const struct nf_conntrack_tuple *otuple = nf_ct_tuple(ct, IP_CT_DIR_ORIGINAL);

                if (otuple) {
                        __log("ORIG tuple: %pI4:%u -> %pI4:%u", 
                                &otuple->src.u3.ip, ntohs(otuple->src.u.tcp.port),
                                &otuple->dst.u3.ip, ntohs(otuple->dst.u.tcp.port));
                } else {
                        __log("has ct %p but no orig tuple", ct);
                        return NF_ACCEPT;
                }

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

static unsigned int garble_local_in_hook(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	if (garble_check_if_conn_first_packet(skb)) {
		__log("######### first packet of new connection!!!!!!!!! hook point: %s",
		      garble_get_nf_hook_point(state->hook));
                log_tuple_info(skb, "first packet of new connection");
                __log("in=%s out=%s skb=%s", state->in ? state->in->name : "-", state->out ? state->out->name : "-", skb->dev ? skb->dev->name : "-");
	}

	return NF_ACCEPT;
}

static unsigned int garble_local_out_hook(void *priv, struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	if (garble_check_if_conn_first_packet(skb)) {
		__log("######### first packet of new connection!!!!!!!!! hook point: %s",
		      garble_get_nf_hook_point(state->hook));

                log_tuple_info(skb, "first packet of new connection");
                __log("in=%s out=%s skb=%s", state->in ? state->in->name : "-", state->out ? state->out->name : "-", skb->dev ? skb->dev->name : "-");	

                garble_clear_packet_mark(skb);

        }

	return NF_ACCEPT;
}
static unsigned int garble_post_routing_hook(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	if (garble_check_if_conn_first_packet(skb)) {
		__log("######### first packet of new connection!!!!!!!!! hook point: %s",
		      garble_get_nf_hook_point(state->hook));

                log_tuple_info(skb, "first packet of new connection");
                __log("in=%s out=%s skb=%s", state->in ? state->in->name : "-", state->out ? state->out->name : "-", skb->dev ? skb->dev->name : "-");	
        }

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
	return nf_register_net_hooks(&init_net, garble_forward_ops,
				ARRAY_SIZE(garble_forward_ops));
}

void garble_routing_exit(void)
{
	nf_unregister_net_hooks(&init_net, garble_forward_ops,
				  ARRAY_SIZE(garble_forward_ops));
}
