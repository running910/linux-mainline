#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "genl.h"
#include "proc_ctrl.h"
#include "parse.h"
#include "common.h"


int nf_dnslisten_enable = 0;
int nf_dnslisten_mod = 10;

static unsigned int nf_dnslisten(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	static unsigned int count = 0;
	const struct iphdr *iph;
	const struct udphdr *uh;
	unsigned int offset;
	struct udphdr _udph;
	const char *dnsdata;
	const char *domain;
	struct sock_cgroup_data *skcd;
	char buf[512] = {0};


	if (!nf_dnslisten_enable)
		return NF_ACCEPT;

	iph = skb_header_pointer(skb, 0, sizeof(iph), &iph);
	if (unlikely(!iph))
		return NF_ACCEPT;

//	if ((count++ % 10000) == 0) {
//		__log("do something");
//		__log("protocol is:%d", iph->protocol);
//	}

	if ((nf_dnslisten_mod <= 0) || (nf_dnslisten_mod > 100))
		return NF_ACCEPT;

	if (iph->protocol == IPPROTO_UDP) {

		//offset = ntohs(iph->frag_off) & IP_OFFSET;
		offset = iph->ihl*4;

		uh = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
		if (uh == NULL) {
			__log("incomplete!");
			return NF_ACCEPT;	
		}

		skcd = &skb->sk->sk_cgrp_data;

		if ((ntohs(uh->dest) == 53) && sock_cgroup_classid(skcd)) {
			dnsdata = (const char *)((const char *)uh + sizeof(const struct udphdr));

	//		__log("count: %d nf_dnslisten_mod: %d", count, nf_dnslisten_mod);
			if (count++ % nf_dnslisten_mod)
				return NF_ACCEPT;

			//__log("actually percent mod:%d", 100/nf_dnslisten_ratio);

			if ((domain = parse_domain_name(dnsdata, buf, sizeof(buf))) != NULL) {
				genl_report_dns_record(sock_cgroup_classid(skcd), domain);
	//			__log("classid:%u domain:%s", sock_cgroup_classid(skcd), domain);
			}

	//		__log("found request to dns server, uh:0x%x dns:0x%x", uh, dnsdata);
	//		__log("dns request cgroup data: %d", sock_cgroup_classid(skcd));
	//		__log("skbuff len:%d data_len:%d mac_len:%d hdr_len:%d sizeof(struct sk_buff):%d", skb->len, skb->data_len, skb->mac_len, skb->hdr_len, sizeof(struct sk_buff));
		}

	}
	
	return NF_ACCEPT;	
}

static const struct nf_hook_ops dnslisten_ops = {
	.hook		= nf_dnslisten,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_FIRST,
};

static __exit int nf_dnslisten_init(void)
{

	if (nf_register_net_hook(&init_net, &dnslisten_ops) != 0) {
		__log("dnslisten nf_register_net_hook failed!");	
		goto error_out;
	}

	if (proc_ctrl_init() != 0) {
		__log("dnslisten sysctl_init failed!");	
		goto unreg_hook;
	}

	if (genl_init() != 0) {
		__log("dnslisten genl_init failed!");	
		goto proc_exit;
	}

	__log("nf_dnslisten_init success!");

	return 0;

proc_exit:
	proc_ctrl_exit();
unreg_hook:
	nf_unregister_net_hook(&init_net, &dnslisten_ops);
error_out:
	__log("nf_dnslisten_init failed!");
	return -1;
}

static __exit void nf_dnslisten_exit(void)
{
	__log("dnslisten exit");	

	genl_exit();
	
	proc_ctrl_exit();

	nf_unregister_net_hook(&init_net, &dnslisten_ops);
}

module_init(nf_dnslisten_init);
module_exit(nf_dnslisten_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("running910@gmail.com");
