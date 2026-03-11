#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/net_namespace.h>

#include "sysctl.h"
#include "packet.h"

extern void insert_tcp_packet_with_skb(struct sk_buff *skb, const struct net *net, int reverse);

static unsigned int garble_forward_hook(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
        int reverse = 1;
        garble_tuple_t tuple;

        if (!garble_check_if_routing_enabled())
		return NF_ACCEPT;

        if (!skb->dev)
                return NF_ACCEPT;

	if (state->pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);
		const struct tcphdr *tcph;

		if (!iph || iph->protocol != IPPROTO_TCP)
			return NF_ACCEPT;

		tcph = tcp_hdr(skb);
		if (!tcph)
			return NF_ACCEPT;

                if (!tcph->syn || tcph->ack)
                        return NF_ACCEPT;

                // if it reaches here, it must be the first packet of the TCP three-way handshake

		__log("FORWARD TCP SYN %pI4:%u -> %pI4:%u in=%s out=%s skb=%s",
			      &iph->saddr, ntohs(tcph->source),
			      &iph->daddr, ntohs(tcph->dest),
			      state->in ? state->in->name : "-",
			      state->out ? state->out->name : "-",
			      skb->dev ? skb->dev->name : "-");

                if (!extract_tuple_info(skb, &tuple))
                        return NF_ACCEPT;

                __log("FORWARD TCP SYN %pI4:%u -> %pI4:%u", &tuple.saddr, ntohs(tuple.sport), &tuple.daddr, ntohs(tuple.dport));

                // packet sent from lan nic
                if (garble_check_if_lan_nic(skb->dev->name)) {

                        // unless tcp_client is enabled, we do obfuscation
                        if (garble_check_if_tcp_client_enabled()) {
                                reverse = 0;
                                __log("TCP syn packet from lan nic %s and tcp_client is enabled! do obfuscate %d", skb->dev->name, reverse);

                        // otherwise, we do nothing
                        } else {
                                __log("TCP syn packet from lan nic %s, and tcp_client is not enabled, do nothing", skb->dev->name);
                                return NF_ACCEPT;
                        }

                }

                insert_tcp_packet_with_skb(skb, state->net, reverse);
                
		return NF_ACCEPT;
	}

	if (state->pf == NFPROTO_IPV6) {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb); 
		const struct tcphdr *tcph;

		if (!ip6h || ip6h->nexthdr != IPPROTO_TCP)
			return NF_ACCEPT;

		tcph = tcp_hdr(skb);
		if (!tcph)
			return NF_ACCEPT;

		if (tcph->syn && !tcph->ack)
			__log("FORWARD TCP SYN %pI6c:%u -> %pI6c:%u in=%s out=%s skb=%s",
			      &ip6h->saddr, ntohs(tcph->source),
			      &ip6h->daddr, ntohs(tcph->dest),
			      state->in ? state->in->name : "-",
			      state->out ? state->out->name : "-",
			      skb->dev ? skb->dev->name : "-");
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
