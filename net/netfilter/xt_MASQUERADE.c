// SPDX-License-Identifier: GPL-2.0-only
/* Masquerade.  Simple mapping which alters range to a local IP address
   (depending on route). */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_masquerade.h>

#include "running910_netlog.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("Xtables: automatic-address SNAT with nathole enabled");

inline bool check_if_need_nathole(struct nf_conn *ct, __be32 newsrc);
inline unsigned int do_nathole(struct sk_buff *skb, struct nf_conn *ct, const struct nf_nat_range2 *range, __be32 newsrc);
void nathole_exit(void);

__be32 inet_select_addr(const struct net_device *dev, __be32 dst, int scope);

unsigned int
nf_nat_masquerade_ipv4_nathole(struct sk_buff *skb, unsigned int hooknum,
		       const struct nf_nat_range2 *range,
		       const struct net_device *out)
{
	struct nf_conn *ct;
	struct nf_conn_nat *nat;
	enum ip_conntrack_info ctinfo;
	struct nf_nat_range2 newrange;
	const struct rtable *rt;
	__be32 newsrc, nh;

	WARN_ON(hooknum != NF_INET_POST_ROUTING);

	ct = nf_ct_get(skb, &ctinfo);

	log_skb(skb, "ct: %p ctinfo %d", ct, ctinfo);

	log_skb_pref(skb, "ct: %p ctinfo %d", ct, ctinfo);

	WARN_ON(!(ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
			 ctinfo == IP_CT_RELATED_REPLY)));

	/* Source address is 0.0.0.0 - locally generated packet that is
	 * probably not supposed to be masqueraded.
	 */
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip == 0)
		return NF_ACCEPT;

	rt = skb_rtable(skb);
	nh = rt_nexthop(rt, ip_hdr(skb)->daddr);
	newsrc = inet_select_addr(out, nh, RT_SCOPE_UNIVERSE);
	if (!newsrc) {
		pr_info("%s ate my IP address\n", out->name);
		return NF_DROP;
	}

	nat = nf_ct_nat_ext_add(ct);
	if (nat)
		nat->masq_index = out->ifindex;

	if (newsrc == ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
		log_skb(skb, "########## it not from inner network!");
	} else {
		log_skb(skb, "########## it is from inner network!");
	}

	if (check_if_need_nathole(ct, newsrc))
		return do_nathole(skb, ct, range, newsrc);

	/* Transfer from original range. */
	memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
	memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));
	newrange.flags       = range->flags | NF_NAT_RANGE_MAP_IPS;
	newrange.min_addr.ip = newsrc;
	newrange.max_addr.ip = newsrc;
	newrange.min_proto   = range->min_proto;
	newrange.max_proto   = range->max_proto;

	/* Hand modified range to generic setup. */
	return nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
}
EXPORT_SYMBOL_GPL(nf_nat_masquerade_ipv4_nathole);


/* FIXME: Multiple targets. --RR */
static int masquerade_tg_check(const struct xt_tgchk_param *par)
{
	const struct nf_nat_ipv4_multi_range_compat *mr = par->targinfo;

	if (mr->range[0].flags & NF_NAT_RANGE_MAP_IPS) {
		pr_debug("bad MAP_IPS.\n");
		return -EINVAL;
	}
	if (mr->rangesize != 1) {
		pr_debug("bad rangesize %u\n", mr->rangesize);
		return -EINVAL;
	}
	return nf_ct_netns_get(par->net, par->family);
}

static unsigned int
masquerade_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct nf_nat_range2 range;
	const struct nf_nat_ipv4_multi_range_compat *mr;

	mr = par->targinfo;
	range.flags = mr->range[0].flags;
	range.min_proto = mr->range[0].min;
	range.max_proto = mr->range[0].max;

	return nf_nat_masquerade_ipv4_nathole(skb, xt_hooknum(par), &range,
				      xt_out(par));
}

static void masquerade_tg_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int
masquerade_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	return nf_nat_masquerade_ipv6(skb, par->targinfo, xt_out(par));
}

static int masquerade_tg6_checkentry(const struct xt_tgchk_param *par)
{
	const struct nf_nat_range2 *range = par->targinfo;

	if (range->flags & NF_NAT_RANGE_MAP_IPS)
		return -EINVAL;

	return nf_ct_netns_get(par->net, par->family);
}
#endif

static struct xt_target masquerade_tg_reg[] __read_mostly = {
	{
#if IS_ENABLED(CONFIG_IPV6)
		.name		= "MASQUERADE",
		.family		= NFPROTO_IPV6,
		.target		= masquerade_tg6,
		.targetsize	= sizeof(struct nf_nat_range),
		.table		= "nat",
		.hooks		= 1 << NF_INET_POST_ROUTING,
		.checkentry	= masquerade_tg6_checkentry,
		.destroy	= masquerade_tg_destroy,
		.me		= THIS_MODULE,
	}, {
#endif
		.name		= "MASQUERADE",
		.family		= NFPROTO_IPV4,
		.target		= masquerade_tg,
		.targetsize	= sizeof(struct nf_nat_ipv4_multi_range_compat),
		.table		= "nat",
		.hooks		= 1 << NF_INET_POST_ROUTING,
		.checkentry	= masquerade_tg_check,
		.destroy	= masquerade_tg_destroy,
		.me		= THIS_MODULE,
	}
};

static int __init masquerade_tg_init(void)
{
	int ret;

	net_debug_init();

	ret = xt_register_targets(masquerade_tg_reg,
				  ARRAY_SIZE(masquerade_tg_reg));
	if (ret)
		return ret;

	ret = nf_nat_masquerade_inet_register_notifiers();
	if (ret) {
		xt_unregister_targets(masquerade_tg_reg,
				      ARRAY_SIZE(masquerade_tg_reg));
		return ret;
	}

	return ret;
}

static void __exit masquerade_tg_exit(void)
{
	xt_unregister_targets(masquerade_tg_reg, ARRAY_SIZE(masquerade_tg_reg));
	nf_nat_masquerade_inet_unregister_notifiers();
}

module_init(masquerade_tg_init);
module_exit(masquerade_tg_exit);
#if IS_ENABLED(CONFIG_IPV6)
MODULE_ALIAS("ip6t_MASQUERADE");
#endif
MODULE_ALIAS("ipt_MASQUERADE");
