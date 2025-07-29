#include <linux/module.h>
#include <linux/types.h>
//#include <linux/atomic.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
//#include <linux/netfilter_ipv6.h>
#include <linux/inet.h>

#include <net/netfilter/nf_nat_masquerade.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>

#define CHECK_PORT_PARITY(a, b) ((a%2)==(b%2))

static void nathole_expect(struct nf_conn *ct, struct nf_conntrack_expect *exp)
{
	struct nf_nat_range2 range;

	log_ct_pref(ct, "before ct->master %p", ct->master);

	/* This must be a fresh one. */
	BUG_ON(ct->status & IPS_NAT_DONE_MASK);

	/* Change src to where new ct comes from */
	range.flags = NF_NAT_RANGE_MAP_IPS;
	range.min_addr = range.max_addr =
	ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC);

	log_ct_pref(ct, "middle ct->master %p", ct->master);

	/* For DST manip, map port here to where it's expected. */
	range.flags = (NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED);
	range.min_proto = range.max_proto = exp->saved_proto;
	range.min_addr = range.max_addr = exp->saved_addr;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);

	log_ct_pref(ct, "after ct->master %p", ct->master);
}

static int nathole_help(struct sk_buff *skb, unsigned int protoff, struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	int dir = CTINFO2DIR(ctinfo);
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_expect *exp;
	int ret;
	char buf[256] = {0};
	//struct net *net;

	log_ct(ct, "try to help dir %d help->expecting[NF_CT_EXPECT_CLASS_DEFAULT] %d", dir, help->expecting[NF_CT_EXPECT_CLASS_DEFAULT]);

	if ((dir != IP_CT_DIR_ORIGINAL) || (help->expecting[NF_CT_EXPECT_CLASS_DEFAULT] > 0))
		return NF_ACCEPT;

	nf_ct_dump_tuple(&ct->tuplehash[dir].tuple);
	nf_ct_dump_tuple(&ct->tuplehash[!dir].tuple);

	/* Create expect */
	if ((exp = nf_ct_expect_alloc(ct)) == NULL)
		return NF_ACCEPT;

	log_skb(skb, "expect proto %d", ct->tuplehash[dir].tuple.dst.protonum);

	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, AF_INET, NULL,
	&ct->tuplehash[!dir].tuple.dst.u3, ct->tuplehash[dir].tuple.dst.protonum,
	NULL, &ct->tuplehash[!dir].tuple.dst.u.all);
	exp->flags = NF_CT_EXPECT_PERMANENT;
	exp->saved_addr = ct->tuplehash[dir].tuple.src.u3;
	exp->saved_proto.all = ct->tuplehash[dir].tuple.src.u.all;
	exp->dir = !dir;
	exp->expectfn = nathole_expect;

	log_skb(skb, "expect tuple: %s", get_tuple_and_mask_str(&exp->tuple, &exp->mask, buf, sizeof(buf)));
	log_skb(skb, "expect saved:  %pI4:%hu", &exp->saved_addr, ntohs(exp->saved_proto.udp.port));

	/* Setup expect */
	ret = nf_ct_expect_related(exp, 0);
	nf_ct_expect_put(exp);

	//net = ;
	log_skb(skb, "expectation setup ret: %d exp->use: %d exp->master %p ct %p net->ct.expect_count: %d", ret, exp->use, exp->master, ct, nf_ct_exp_net(exp)->ct.expect_count);

	return NF_ACCEPT;
}

static struct nf_conntrack_expect_policy nathole_expect_policy __read_mostly = {
	.max_expected   = 1000,
	.timeout        = 240,
};

static struct nf_conntrack_helper nathole_helper __read_mostly = {
	.name = "nathole",
	.me = THIS_MODULE,
	.tuple.src.l3num = AF_INET,
	//.tuple.dst.protonum = IPPROTO_UDP,
	.expect_policy = &nathole_expect_policy,
	.expect_class_max = 1,
	.help = nathole_help,
};

/****************************************************************************/
static inline int find_expect_by_mapped(__be32 ip, __be16 port, struct nf_conn *ct)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_expect *i = NULL;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = AF_INET;
	//tuple.dst.protonum = IPPROTO_UDP;
	tuple.dst.protonum = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
	tuple.dst.u3.ip = ip;
	tuple.dst.u.all = port;

	log_ct(ct, "happens to be tuple.dst.u.udp.port:%d tuple.dst.protonum:%d", tuple.dst.u.udp.port, tuple.dst.protonum);

	rcu_read_lock();
	i = __nf_ct_expect_find(nf_ct_net(ct), nf_ct_zone(ct), &tuple);
	rcu_read_unlock();

	return i != NULL;
}

/****************************************************************************/
static inline struct nf_conntrack_expect *find_expect_by_unmapped(struct nf_conn *ct)
{
	struct nf_conntrack_tuple * tp =
	&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	struct nf_conntrack_expect * exp = NULL;
	struct nf_conntrack_expect * i;
	unsigned int h;

	rcu_read_lock();
	for (h = 0; h < nf_ct_expect_hsize; h++) {
		hlist_for_each_entry_rcu(i, &nf_ct_expect_hash[h], hnode) {
			if (nf_inet_addr_cmp(&i->saved_addr, &tp->src.u3) &&
				i->saved_proto.all == tp->src.u.all &&
				i->tuple.dst.protonum == tp->dst.protonum &&
				i->tuple.src.u3.ip == 0 &&
				i->tuple.src.u.all == 0) { 
				exp = i;
				break;
			}
		}
	}
	rcu_read_unlock();

	return exp;
}

unsigned int do_nathole(struct sk_buff *skb, struct nf_conn *ct, const struct nf_nat_range2 *range, __be32 newsrc)
{
	unsigned int ret;
	u_int16_t minport;
	u_int16_t maxport;
	struct nf_conntrack_expect *exp;
	struct nf_nat_range2 newrange;

	/* Choose port */
	spin_lock_bh(&nf_conntrack_expect_lock);
	/* Look for existing expectation */
	exp = find_expect_by_unmapped(ct);
	if (exp) {
		log_skb_pref(skb, "exp is found, reuse snat port %hu", htons(exp->tuple.dst.u.all));

		//  minport = maxport = exp->tuple.dst.u.udp.port;
		minport = maxport = exp->tuple.dst.u.all;
	} else { /* no previous expect */
		u_int16_t newport, tmpport, orgport;

		log_skb_pref(skb, "no exp yet");

		log_skb(skb, "miniport %hu maxport %hu", htons(range->min_proto.all), htons(range->max_proto.all));

		minport = range->min_proto.all == 0? 
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.
			u.udp.port : range->min_proto.all;
		maxport = range->max_proto.all == 0? 
			htons(65535) : range->max_proto.all;
		orgport = ntohs(minport);

		log_skb(skb, "now start to choose miniport %hu maxport %hu", htons(minport), htons(maxport));
		for (newport = ntohs(minport),tmpport = ntohs(maxport); 
			newport <= tmpport; newport++) {
			if (CHECK_PORT_PARITY(orgport, newport) && !find_expect_by_mapped(newsrc, htons(newport), ct)) {

				log_skb_pref(skb, "new snat port has been finalized %hu", newport);
				minport = maxport = htons(newport);
				break;
			}
		}
		log_skb(skb, "finally chosen miniport %hu maxport %hu", htons(minport), htons(maxport));
	}
	spin_unlock_bh(&nf_conntrack_expect_lock);

	memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
	memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));

	newrange.flags = range->flags | NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	newrange.max_addr.ip = newrange.min_addr.ip = newsrc;
	newrange.min_proto.udp.port = newrange.max_proto.udp.port = minport;

	log_ct_pref(ct, "ct bfore change");

	/* Set ct helper */
	ret = nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
	if (ret == NF_ACCEPT && !exp) {
		struct nf_conn_help *help = nfct_help(ct);

		log_skb(skb, "at this moment help %p", help);

		if (help == NULL) {
			help = nf_ct_helper_ext_add(ct, GFP_ATOMIC);
			log_skb(skb, "now nf_ct_helper_ext_add");
		}
		if (help != NULL) {
			help->helper = &nathole_helper;
			log_skb_pref(skb, "add helper");

		}
	}

	log_ct_pref(ct, "ct after change");

	return ret;
}