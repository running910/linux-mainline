#include <linux/module.h>
#include <net/netfilter/nf_nat_masquerade.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_masq_nathole.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_AUTHOR("Zhixing Chen <running910@gmail.com>");
MODULE_DESCRIPTION("Xtables: automatic-address SNAT with nathole enabled");

static int nathole_help(struct sk_buff *skb, unsigned int protoff, struct nf_conn *ct, enum ip_conntrack_info ctinfo);

static nat_setup_fn_t nat_setup_fn = NULL;

static struct nf_conntrack_expect_policy nathole_expect_policy __read_mostly = {
	// 限定对应ct的NF_CT_EXPECT_CLASS_DEFAULT类的expectation数量
	// 只需要一个(最多可设置NF_CT_EXPECT_MAX_CNT个)
	.max_expected   = 1,

	// 限定对应ct的NF_CT_EXPECT_CLASS_DEFAULT类的expectation生存时间，在这里尽量
	// 设置足够大，并且对应的master ct释放后会自动释放
	.timeout        = 3600,
};

static struct nf_conntrack_helper nathole_helper __read_mostly = {
	.name = "nathole",
	.me = THIS_MODULE,
	.tuple.src.l3num = AF_INET,
	.expect_policy = &nathole_expect_policy,

	// 限制对应ct的expect的class类的最大数量
	// 只需要一个（最多可设置NF_CT_MAX_EXPECT_CLASSES个）
	.expect_class_max = 1,
	.help = nathole_help,
};


static void nathole_expect(struct nf_conn *ct, struct nf_conntrack_expect *exp)
{
	struct nf_nat_range2 range;

	log_ct_pref(ct, "before ct->master %p", ct->master);

	/* This must be a fresh one. */
	BUG_ON(ct->status & IPS_NAT_DONE_MASK);

	// expect的连接original方向的都是远端过来的，这里
	// 应该是没有必要变更其src地址端口
#if 0
	/* Change src to where new ct comes from */
	range.flags = NF_NAT_RANGE_MAP_IPS;
	range.min_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
	range.max_addr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC);

	log_ct_pref(ct, "middle ct->master %p", ct->master);
#endif

	// expect的连接dst地址端口要变更为master ct的original方向的src地址端口
	/* For DST manip, map port here to where it's expected. */
	range.flags = (NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED);
	range.min_proto = exp->saved_proto;
	range.max_proto = exp->saved_proto;
	range.min_addr = exp->saved_addr;
	range.max_addr = exp->saved_addr;
	nat_setup_fn(ct, &range, NF_NAT_MANIP_DST);

	log_ct_pref(ct, "after ct->master %p", ct->master);
}

static int nathole_help(struct sk_buff *skb, unsigned int protoff, struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	int dir = CTINFO2DIR(ctinfo);
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_expect *exp;
	int ret;
	char buf[256] = {0};

	log_ct(ct, "try to help dir %d help->expecting[NF_CT_EXPECT_CLASS_DEFAULT] %d", dir, help->expecting[NF_CT_EXPECT_CLASS_DEFAULT]);

	if ((dir != IP_CT_DIR_ORIGINAL) || (help->expecting[NF_CT_EXPECT_CLASS_DEFAULT] > 0))
		return NF_ACCEPT;

	//nf_ct_dump_tuple(&ct->tuplehash[dir].tuple);
	//nf_ct_dump_tuple(&ct->tuplehash[!dir].tuple);

	/* Create expect */
	if ((exp = nf_ct_expect_alloc(ct)) == NULL)
		return NF_ACCEPT;

	log_skb(skb, "expect proto %d", ct->tuplehash[dir].tuple.dst.protonum);

	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, AF_INET, NULL, &ct->tuplehash[!dir].tuple.dst.u3, 
		ct->tuplehash[dir].tuple.dst.protonum, NULL, &ct->tuplehash[!dir].tuple.dst.u.all);

	// 永久有效，标识不限连接数量
	exp->flags = NF_CT_EXPECT_PERMANENT;

	// 保存的是original方向的src地址端口
	exp->saved_addr = ct->tuplehash[dir].tuple.src.u3;
	exp->saved_proto.all = ct->tuplehash[dir].tuple.src.u.all; 

	// 预期连接是主动连进来的新的ct第一个包，所以dir应该也是original方向
	// 但实际上dir未参与匹配逻辑，不设置亦可
	// exp->dir = dir;

	exp->expectfn = nathole_expect;

	log_skb(skb, "expect tuple: %s", get_tuple_and_mask_str(&exp->tuple, &exp->mask, buf, sizeof(buf)));
	log_skb(skb, "expect saved:  %pI4:%hu", &exp->saved_addr, ntohs(exp->saved_proto.all));

	/* Setup expect */
	ret = nf_ct_expect_related(exp, 0);
	nf_ct_expect_put(exp);

	log_skb(skb, "expectation setup ret: %d exp->use: %d exp->master %p ct %p net->ct.expect_count: %d", ret, exp->use.refs.counter, exp->master, ct, nf_ct_exp_net(exp)->ct.expect_count);

	return NF_ACCEPT;
}


// 新的由inner网络的五元组发出第一个包，查看映射后的地址端口是否已经有对应的expectation
static inline int find_expect_by_mapped(__be32 ip, __be16 port, struct nf_conn *ct)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_expect *i = NULL;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = AF_INET;
	tuple.dst.protonum = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
	tuple.dst.u3.ip = ip;
	tuple.dst.u.all = port;

	log_ct(ct, "happens to be tuple.dst.u.all:%d tuple.dst.protonum:%d", tuple.dst.u.all, tuple.dst.protonum);

	rcu_read_lock();
	i = __nf_ct_expect_find(nf_ct_net(ct), nf_ct_zone(ct), &tuple);
	rcu_read_unlock();

	return i != NULL;
}

// 新的由inner网络的五元组发出第一个包，寻找该src地址端口是否已经有对应的expectation
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

static inline u_int16_t select_new_port(struct sk_buff *skb, struct nf_conn *ct, const struct nf_nat_range2 *range, __be32 newsrc)
{
	u_int16_t newport;

	u_int16_t minport, maxport, orgport;

	log_skb(skb, "configed port range minport %hu maxport %hu", ntohs(range->min_proto.all), ntohs(range->max_proto.all));

	// if a port range is configured, select port within the configured range, 
	// otherwise use the original port as the starting port
	minport = ntohs(range->min_proto.all == 0 ? ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all : range->min_proto.all);
	maxport = ntohs(range->max_proto.all == 0 ? htons(65535) : range->max_proto.all);
	orgport = ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);

	log_skb(skb, "now start to choose port within minport %hu - maxport %hu", minport, maxport);

	// ensure that the port parity remains the same before and after the 
	// mapping, in accordance with RFC 4787
	for (newport = minport | (orgport & 1); newport <= maxport; newport += 2) {

		if (!find_expect_by_mapped(newsrc, htons(newport), ct)) {
			log_skb_pref(skb, "new snat port has been finalized %hu", newport);
			break;
		}
	}

	if (unlikely(newport > maxport)) {
		log_skb_pref(skb, "new port %hu out of range!", newport);
	}

	return newport <= maxport ? htons(newport) : 0;
}

inline bool check_if_need_nathole(struct nf_conn *ct, __be32 newsrc)
{
	if ((newsrc != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) &&
		(nfct_help(ct) == NULL || nfct_help(ct)->helper == NULL) &&
		(nf_ct_protonum(ct) == IPPROTO_UDP || nf_ct_protonum(ct) == IPPROTO_TCP)) {
		return true;
	} else {
		return false;
	}
}
EXPORT_SYMBOL(check_if_need_nathole);

inline unsigned int do_nathole(struct sk_buff *skb, struct nf_conn *ct, const struct nf_nat_range2 *range, __be32 newsrc)
{
	unsigned int ret;
	u_int16_t newport;
	struct nf_conntrack_expect *exp;
	struct nf_nat_range2 newrange;

	spin_lock_bh(&nf_conntrack_expect_lock);
	exp = find_expect_by_unmapped(ct);
	if (exp) {
		log_skb_pref(skb, "expectation is found, reuse snat port %hu", htons(exp->tuple.dst.u.all));

		newport = exp->tuple.dst.u.all;
	} else {

		log_skb_pref(skb, "no expectation is found! select a new snat port!");

		newport = select_new_port(skb, ct, range, newsrc);
		if (unlikely(newport == 0)) {
			return NF_DROP;
		}
	}
	spin_unlock_bh(&nf_conntrack_expect_lock);

	memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
	memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));

	// indicates that the ip and port after snat have been fixed
	newrange.flags = range->flags | NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;

	newrange.max_addr.ip = newsrc;
	newrange.min_addr.ip = newsrc;
	newrange.min_proto.all = newport;
	newrange.max_proto.all = newport;

	log_ct_pref(ct, "ct before change");

	/* Set ct helper */
	ret = nat_setup_fn(ct, &newrange, NF_NAT_MANIP_SRC);
	if (ret == NF_ACCEPT && !exp) {
		struct nf_conn_help *help = nfct_help(ct);

		if (help == NULL) {
			help = nf_ct_helper_ext_add(ct, GFP_ATOMIC);
			log_skb(skb, "now nf_ct_helper_ext_add");
		}
		if (help != NULL) {
			help->helper = &nathole_helper;
			log_skb_pref(skb, "add nathole helper");
		}
	}

	log_ct_pref(ct, "ct after change");

	return ret;
}
EXPORT_SYMBOL(do_nathole);

void nathole_init(nat_setup_fn_t setup_func)
{
	nat_setup_fn = setup_func;
}
EXPORT_SYMBOL(nathole_init);

void nathole_exit(void)
{
	nf_conntrack_helper_unregister(&nathole_helper);
}
EXPORT_SYMBOL(nathole_exit);
