// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_ptb.c	Simple 3-band Priority Token Bucket scheduler.
 *
 * Authors:	xdibin, <xdibin@gmail.com>
 */

#include "linux/compiler.h"
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#define PTB_BAND_H 0
#define PTB_BAND_M 1
#define PTB_BAND_L 2

#ifndef TCQ_PTB_BANDS
/* PTB section */
#define TCQ_PTB_BANDS	3
/* TCQ_PTB_APPS must equal 2^n - 1 */
#define TCQ_PTB_APPS	7
#define TCQ_PTB_APP_MASK (7 << 4)

struct ptb_virtq_opt {
	u64 rate;
	u32 buffer;
	u32 limit;
};

struct tc_ptb_qopt {
	struct tc_ratespec rate;
	__u32 limit;
	__u32 buffer;
	__u32 mtu;
	__u32 pad;
	struct tc_ratespec ceil;
	__u32 climit;
	__u32 cbuffer;
	struct ptb_virtq_opt apps[TCQ_PTB_APPS];
};

enum {
	TCA_PTB_UNSPEC,
	TCA_PTB_PARMS,
	TCA_PTB_RTAB,
	TCA_PTB_PTAB,
	TCA_PTB_RATE64,
	TCA_PTB_PRATE64,
	TCA_PTB_BURST,
	TCA_PTB_PBURST,
	TCA_PTB_CTAB,
	TCA_PTB_CEIL64,
	TCA_PTB_PAD,
	__TCA_PTB_MAX,
};

#define TCA_PTB_MAX (__TCA_PTB_MAX - 1)

struct tc_ptb_virtq_xstats {
	u64 packets;
	u64 bytes;
	s64 tokens;
	s32 backlog;
	u32 drops;
};

struct tc_ptb_xstats {
	__s32 tokens;
	__s32 ptokens;
	__s32 ctokens;
	__u32 app;
	struct tc_ptb_virtq_xstats apps[TCQ_PTB_APPS];
};

#endif

struct ptb_virtq {
	struct psched_ratecfg rate;  /* virtual queue rate */
	s64 buffer;  /* max buckets */
	s64 tokens;  /* current tokens */
	s64 t_c;
	u32 limit;
};

struct ptb_sched_data {
	int bands;
	struct tcf_proto __rcu *filter_list;
	struct tcf_block *block;
	u8 prio2band[TC_PRIO_MAX + 1];
	struct Qdisc *queues[TCQ_PTB_BANDS];
	struct tc_ptb_xstats xstats;

	/* Parameters */
	u32 limit;		/* Maximal length of backlog: bytes, drop packet when backlog > limit */
	u32 climit;
	u32 max_size;		/* Maximal length of packet: bytes */
	s64 buffer;		/* Token bucket depth/rate: MUST BE >= MTU/B */
	s64 cbuffer;
	s64 mtu;
	struct psched_ratecfg rate;	/* low band rate */
	struct psched_ratecfg ceil;	/* whole qdisc rate, must ceil > rate */

	/* Variables */
	s64 tokens;		/* Current number of tokens */
	s64 ctokens;	/* Current number of ceil tokens */
	s64 t_c;		/* Time check-point */

	/* Application virtual qdisc */
	u32 app;
	struct ptb_virtq apps[TCQ_PTB_APPS];

	struct qdisc_watchdog watchdog;	/* Watchdog timer */
};

#define CLASSID_TO_APPID(app_id, apps, class_id) \
    do { \
        if (apps) { \
            int _tmp = (((class_id) & TCQ_PTB_APP_MASK) >> 4); \
            if (_tmp <= (apps)) \
                app_id = _tmp; \
        } \
    } while(0)


static int ptb_classify(struct sk_buff *skb, struct Qdisc *sch,
				  int *qerr)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	int band = skb->priority;
	struct tcf_result res;
	struct tcf_proto *fl;
	int err;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	if (TC_H_MAJ(skb->priority) != sch->handle) {
		fl = rcu_dereference_bh(q->filter_list);
		err = tcf_classify(skb, fl, &res, false);
#ifdef CONFIG_NET_CLS_ACT
		switch (err) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			fallthrough;
		case TC_ACT_SHOT:
			return -1;
		}
#endif
		// printk(KERN_INFO "sch_ptb: tcf_classify return, skb->pri:%d, classid:0x%x, fl:%p, err:%d\n", skb->priority, res.classid, fl, err);
		if (!fl || err < 0) {
			if (TC_H_MAJ(band))
				return PTB_BAND_M;
			return q->prio2band[band & TC_PRIO_MAX];
		}
		band = res.classid;
		qdisc_skb_cb(skb)->tc_classid = band;
	}
	band = TC_H_MIN(band) - 1;

	return band;
}

static void ptb_stats_drop(struct Qdisc *sch, struct Qdisc *ptb, int appid)
{
	struct ptb_sched_data *q = qdisc_priv(sch);

	qdisc_qstats_drop(sch);
	qdisc_qstats_drop(ptb);
	if (appid > 0) {
		q->xstats.apps[appid - 1].drops++;
	}
}

static inline int ptb_virt_enqueue(struct sk_buff *skb, struct ptb_sched_data *q, int app_id)
{
	u32 len = qdisc_pkt_len(skb);
	struct ptb_virtq *vq = q->apps + (app_id - 1);
	struct tc_ptb_virtq_xstats *vqx = q->xstats.apps + (app_id - 1);
	if (likely(vqx->backlog + len <= vq->limit)) {
		vqx->backlog += len;
		// printk(KERN_INFO "sch_ptb: virq enqueue, skb:%p, len:%d, backlog:%d\n", skb, len, vqx->backlog);
		return NET_XMIT_SUCCESS;
	}
	// printk(KERN_INFO "sch_ptb: virq drop, skb:%p, len:%d, backlog:%d\n", skb, len, vqx->backlog);

	return NET_XMIT_DROP;
}

static inline void ptb_virt_enqueue_cancel(struct sk_buff *skb, struct ptb_sched_data *q, int app_id)
{
	struct tc_ptb_virtq_xstats *vqx = q->xstats.apps + (app_id - 1);
	vqx->backlog -= qdisc_pkt_len(skb);
	// printk(KERN_INFO "sch_ptb: virq enqueue cancel, skb:%p, len:%d, backlog:%d\n", skb, qdisc_pkt_len(skb), vqx->backlog);
}

/* GSO packet is too big, segment it so that ptb can transmit
 * each segment in time
 */
static int ptb_segment(struct sk_buff *skb, struct Qdisc *sch,
		       struct Qdisc *qdisc, struct sk_buff **to_free,
			   struct ptb_sched_data *q, int classid)
{
	struct sk_buff *segs, *tskb, *nskb;
	netdev_features_t features = netif_skb_features(skb);
	unsigned int len = 0, prev_len = qdisc_pkt_len(skb);
	int ret, nb, ret_app = NET_XMIT_SUCCESS;
	int app_id = 0;

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs)) {
		// pr_warn_ratelimited("sch_ptb: gso segment failed\n");
		return qdisc_drop(skb, sch, to_free);
	}

	CLASSID_TO_APPID(app_id, q->app, classid);

	nb = 0;
	skb_list_walk_safe(segs, tskb, nskb) {
		skb_mark_not_on_list(tskb);
		qdisc_skb_cb(tskb)->pkt_len = tskb->len;
		qdisc_skb_cb(tskb)->tc_classid = classid;
		len += tskb->len;
		if (app_id) {
			ret_app = ptb_virt_enqueue(tskb, q, app_id);
			if (ret_app == NET_XMIT_DROP) {
				if (net_xmit_drop_count(ret_app)) {
					//pr_warn_ratelimited("sch_ptb: ptb vq drop, band:%d, app_id:%d\n", classid & 0x3, app_id);
					ptb_stats_drop(sch, qdisc, app_id);
				}
					
				continue;
			}
		}
		ret = qdisc_enqueue(tskb, qdisc, to_free);
		if (ret != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(ret)) {
				//pr_warn_ratelimited("sch_ptb: ptb drop, band:%d, app_id:%d\n", classid & 0x3, app_id);
				ptb_stats_drop(sch, qdisc, app_id);
			}
			if (app_id) {
				ptb_virt_enqueue_cancel(tskb, q, app_id);
			}
		} else {
			nb++;
		}
	}
	sch->q.qlen += nb;
	if (nb > 1)
		qdisc_tree_reduce_backlog(sch, 1 - nb, prev_len - len);
	consume_skb(skb);
	// if (nb == 0) {
	// 	pr_warn_ratelimited("sch_ptb: ptb segment return drop\n");
	// }
	return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static int
ptb_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb);
	struct Qdisc *qdisc;
	int ret, ret_app = NET_XMIT_DROP;
	int band = PTB_BAND_M;
	int ret_band = -1;
	int app_id = 0;
	u32 max_size = q->max_size;

	// printk(KERN_INFO "sch_ptb: enqueue start\n");

	ret_band = ptb_classify(skb, sch, &ret);

#ifdef CONFIG_NET_CLS_ACT
	if (ret_band == -1) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return ret;
	}
#endif
	band = (ret_band) & 0x3;
	CLASSID_TO_APPID(app_id, q->app, ret_band);

	if (band >= TCQ_PTB_BANDS) {
		band = PTB_BAND_M;
	}
	
	qdisc = q->queues[band];
	if (len > max_size) {
		if (skb_is_gso(skb) &&
		    skb_gso_validate_mac_len(skb, max_size)) {
			//pr_warn_ratelimited("sch_ptb: need segment, band:%d, len:%u, max_size:%u\n", band, len, max_size);
			return ptb_segment(skb, sch, qdisc, to_free, q, ret_band);
		}
		//pr_warn_ratelimited("sch_ptb: segment disabled\n");
		return qdisc_drop(skb, sch, to_free);
	}

	if (app_id) {
		ret_app = ptb_virt_enqueue(skb, q, app_id);
		if (ret_app == NET_XMIT_DROP) {
			//pr_warn_ratelimited("sch_ptb: vq enqueue failed, band:%d, app_id:%d\n", band, app_id);
			ptb_stats_drop(sch, qdisc, app_id);
			return NET_XMIT_DROP;
		}
	}

	ret = qdisc_enqueue(skb, qdisc, to_free);
	if (ret == NET_XMIT_SUCCESS) {
		sch->qstats.backlog += len;
		sch->q.qlen++;
		// printk(KERN_INFO "sch_ptb: enqueued, skb:%p, len:%d, backlog:%u\n", skb, len, sch->qstats.backlog);
		return NET_XMIT_SUCCESS;
	}

	if (net_xmit_drop_count(ret)) {
		//pr_warn_ratelimited("sch_ptb: enqueue failed, band:%d, app_id:%d, len:%u, backlog:%u\n", band, app_id, len, qdisc->qstats.backlog);
		ptb_stats_drop(sch, qdisc, app_id);
		if (app_id) {
			ptb_virt_enqueue_cancel(skb, q, app_id);
		}
	}
	return ret;
}

static struct sk_buff *ptb_peek(struct Qdisc *sch)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	int band;

	for (band = 0; band < q->bands; band++) {
		struct Qdisc *qdisc = q->queues[band];
		struct sk_buff *skb = qdisc->ops->peek(qdisc);
		if (skb)
			return skb;
	}
	return NULL;
}

static inline s64 ptb_virt_pick(struct sk_buff *skb, struct ptb_virtq *vq, struct tc_ptb_virtq_xstats *vqx, s64 t_c)
{
	unsigned int len = qdisc_pkt_len(skb);
	s64 ts;
	s64 toks = 0, rlen;
	s32 backlog;

	backlog = vqx->backlog - len;
	if (unlikely(backlog < 0)) {
		// printk(KERN_INFO "sch_ptb: virtq overun, skb:%p, len:%d, backlog:%d\n", skb, len, vq->backlog);
		return -1;
	}

	ts = t_c - vq->t_c;
	if (unlikely(ts <= 0)) {
		return -1;
	}
	toks = min_t(s64, ts, vq->buffer);
	toks += vq->tokens;
	if (toks > vq->buffer) {
		toks = vq->buffer;
	}
	rlen = (s64) psched_l2t_ns(&vq->rate, len);
	toks -= rlen;
	if (toks >= 0) {
		return toks;
	} else {
		if (unlikely(-toks > vq->buffer)) {
			pr_warn_ratelimited("sch_ptb: virtq pick, skb:%p, len:%d, rlen:%lld, toks:%lld, buff:%lld, backlog:%d\n", skb, len, rlen, toks, vq->buffer, backlog);
		}
		return -1;
	}
}

static struct sk_buff *ptb_dequeue(struct Qdisc *sch)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct Qdisc *qdisc;
	int band= 0;
	s64 now;
	s64 ts;
	s64 toks = 0, rlen = 0;
	s64 ctoks = 0, clen = 0;
	unsigned int len;
	bool dequeue = false;
	s64 ns = 0;
	s64 vtoks = 0;
	int app_id = 0;
	struct ptb_virtq *vq;
	struct tc_ptb_virtq_xstats *vqx;

next_band:
	skb = NULL;
	vq = NULL;
	vqx = NULL;
	for (; band < q->bands; band++) {
		qdisc = q->queues[band];
		skb = qdisc->ops->peek(qdisc);
		if (skb) {
			break;
		}
	}

	if (skb) {
		len = qdisc_pkt_len(skb);
		now = ktime_get_ns();
		CLASSID_TO_APPID(app_id, q->app, qdisc_skb_cb(skb)->tc_classid);
		if (app_id) {
			vq = q->apps + (app_id - 1);
			vqx = q->xstats.apps + (app_id - 1);
			vtoks = ptb_virt_pick(skb, vq, vqx, now);

			if (vtoks < 0) {
				// FIXME: 
				band++;
				if (unlikely(band >= q->bands)) {
					qdisc_watchdog_schedule_ns(&q->watchdog, now + (-vtoks));
					qdisc_qstats_overlimit(sch);
					qdisc_qstats_overlimit(qdisc);
					return NULL;
				} else {
					goto next_band;
				}
			}
		}
		

		ts = now - q->t_c;
		if (unlikely(ts <= 0)) {
			return NULL;
		}

		ctoks = min_t(s64, ts, q->cbuffer);
		ctoks += q->ctokens;
		if (ctoks > q->cbuffer) {
			ctoks = q->cbuffer;
		}
		clen = (s64) psched_l2t_ns(&q->ceil, len);

		toks = min_t(s64, ts, q->buffer);
		toks += q->tokens;
		if (toks > q->buffer) {
			toks = q->buffer;
		}
		rlen = (s64) psched_l2t_ns(&q->rate, len);

		if (band != PTB_BAND_L) {
			/* high or mid band */
			ctoks -= clen;
			if (ctoks >= 0) {
				dequeue = true;
				toks -= rlen;
			} else {
				ns = -ctoks;
				//pr_warn_ratelimited("sch_ptb: overlimit, band:%d, len:%u, ctoks:%lld, clen:%lld, cbuff:%lld, toks:%lld, rlen:%lld, buff:%lld, ts:%lld\n", band, len, q->ctokens, clen, q->cbuffer, q->tokens, rlen, q->buffer, ts);
				if (unlikely(clen > q->cbuffer)) {
					pr_warn_ratelimited("sch_ptb: ctok overflow, len:%d, clen:%lld, ctok:%lld, cbuff:%lld", len, clen, ctoks, q->cbuffer);
				}
			}
		} else {
			/* low band */
			toks -= rlen;
			if (toks >= 0) {
				dequeue = true;
				//ctoks -= clen;
			} else {
				ns = -toks;
				//pr_warn_ratelimited("sch_ptb: overlimit, band:%d, len:%u, ctoks:%lld, clen:%lld, cbuff:%lld, toks:%lld, rlen:%lld, buff:%lld, ts:%lld\n", band, len, q->ctokens, clen, q->cbuffer, q->tokens, rlen, q->buffer, ts);
				if (unlikely(rlen > q->buffer)) {
					pr_warn_ratelimited("sch_ptb: tok overflow, len:%d, rlen:%lld, tok:%lld, buff:%lld", len, rlen, toks, q->buffer);
				}
			}
		}

		if (dequeue) {
			skb = qdisc_dequeue_peeked(q->queues[band]);
			//skb = q->queues[band]->dequeue(q->queues[band]);
			if (unlikely(!skb)) {
				pr_warn_ratelimited("sch_ptb: dequeue peeked failed, band:%d\n", band);
				return NULL;
			}

			q->t_c = now;
			q->tokens =
			    toks >= 0 ? toks : (toks >
						-q->buffer ? toks : -q->buffer);
			q->ctokens =
			    ctoks >= 0 ? ctoks : (ctoks >
						  -q->cbuffer ? ctoks : -q->
						  cbuffer);
			sch->qstats.backlog -= len;
			sch->q.qlen--;
			qdisc_bstats_update(sch, skb);
			if (vq && vqx) {
				vq->t_c = now;
				vq->tokens = vtoks;
				vqx->backlog -= len;
				vqx->packets++;
				vqx->bytes += len;
			}
			return skb;
		} else {
			qdisc_watchdog_schedule_ns(&q->watchdog, now + ns);
			qdisc_qstats_overlimit(sch);
			qdisc_qstats_overlimit(qdisc);
		}
	}
	return NULL;
}

static void ptb_reset(struct Qdisc *sch)
{
	int band;
	struct ptb_sched_data *q = qdisc_priv(sch);

	for (band = 0; band < q->bands; band++)
		qdisc_reset(q->queues[band]);
	sch->qstats.backlog = 0;
	sch->q.qlen = 0;
	q->t_c = ktime_get_ns();
	q->tokens = q->buffer;
	q->ctokens = q->cbuffer;
	for (band = 0; band < TCQ_PTB_APPS; band++) {
		q->apps[band].tokens = q->apps[band].buffer;
		q->apps[band].t_c = q->t_c;
		q->xstats.apps[band].backlog = 0;
		q->xstats.apps[band].tokens = q->apps[band].buffer;
		q->xstats.apps[band].packets = 0;
		q->xstats.apps[band].bytes = 0;
	}
	qdisc_watchdog_cancel(&q->watchdog);
}

static void ptb_destroy(struct Qdisc *sch)
{
	int band;
	struct ptb_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);

	tcf_block_put(q->block);
	for (band = 0; band < q->bands; band++)
		qdisc_put(q->queues[band]);
}

static const struct nla_policy ptb_policy[TCA_PTB_MAX + 1] = {
	[TCA_PTB_PARMS] = {.len = sizeof(struct tc_ptb_qopt) },
	[TCA_PTB_RTAB] = {.type = NLA_BINARY,.len = TC_RTAB_SIZE },
	[TCA_PTB_CTAB] = {.type = NLA_BINARY,.len = TC_RTAB_SIZE },
	[TCA_PTB_RATE64] = {.type = NLA_U64 },
	[TCA_PTB_CEIL64] = {.type = NLA_U64 },
	[TCA_PTB_BURST] = {.type = NLA_U32 },
};

/* Time to Length, convert time in ns to length in bytes
 * to determinate how many bytes can be sent in given time.
 */
static u64 psched_ns_t2l(const struct psched_ratecfg *r, u64 time_in_ns)
{
	/* The formula is :
	 * len = (time_in_ns * r->rate_bytes_ps) / NSEC_PER_SEC
	 */
	u64 len = time_in_ns * r->rate_bytes_ps;

	do_div(len, NSEC_PER_SEC);

	if (unlikely(r->linklayer == TC_LINKLAYER_ATM)) {
		do_div(len, 53);
		len = len * 48;
	}

	if (len > r->overhead)
		len -= r->overhead;
	else
		len = 0;

	return len;
}

static int ptb_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	int err;
	struct ptb_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_PTB_MAX + 1];
	struct tc_ptb_qopt *qopt;
	struct Qdisc *queues[TCQ_PTB_BANDS];
	struct psched_ratecfg rate;
	struct psched_ratecfg ceil;
	u64 max_size = 0, cmax_size;
	s64 buffer = 0, cbuffer;
	u64 rate64 = 0, ceil64 = 0;
	int i;
	unsigned int mtu;
	u32 app = 0;
	struct ptb_virtq apps[TCQ_PTB_APPS];

	err =
	    nla_parse_nested_deprecated(tb, TCA_PTB_MAX, opt, ptb_policy, NULL);
	if (err < 0) {
		printk(KERN_ERR "sch_ptb: parse attr err, %d\n", err);
		return err;
	}

	err = -EINVAL;
	if (tb[TCA_PTB_PARMS] == NULL) {
		return -EINVAL;
	}

	qopt = nla_data(tb[TCA_PTB_PARMS]);

	// printk(KERN_INFO
	//        "sch_ptb: qopt ceil:%u,rate:%u,cbuffer,%u,buffer:%u,climit:%u,limit:%u\n",
	//        qopt->ceil.rate, qopt->rate.rate, qopt->cbuffer, qopt->buffer,
	//        qopt->climit, qopt->limit);

	if (qopt->rate.linklayer == TC_LINKLAYER_UNAWARE)
		qdisc_put_rtab(qdisc_get_rtab(&qopt->rate,
					      tb[TCA_PTB_RTAB], NULL));

	if (qopt->ceil.linklayer == TC_LINKLAYER_UNAWARE)
		qdisc_put_rtab(qdisc_get_rtab(&qopt->ceil,
					      tb[TCA_PTB_CTAB], NULL));

	buffer = min_t(u64, PSCHED_TICKS2NS(qopt->buffer), ~0U);
	if (tb[TCA_PTB_RATE64])
		rate64 = nla_get_u64(tb[TCA_PTB_RATE64]);
	psched_ratecfg_precompute(&rate, &qopt->rate, rate64);

	cbuffer = min_t(u64, PSCHED_TICKS2NS(qopt->cbuffer), ~0U);
	if (tb[TCA_PTB_CEIL64])
		ceil64 = nla_get_u64(tb[TCA_PTB_CEIL64]);
	psched_ratecfg_precompute(&ceil, &qopt->ceil, ceil64);

	if (tb[TCA_PTB_BURST]) {
		max_size = nla_get_u32(tb[TCA_PTB_BURST]);
		buffer = psched_l2t_ns(&rate, max_size);
	} else {
		max_size = min_t(u64, psched_ns_t2l(&rate, buffer), ~0U);
	}

	cmax_size = min_t(u64, psched_ns_t2l(&ceil, cbuffer), ~0U);
	if (max_size > cmax_size) {
		max_size = cmax_size;
	}

	if (ceil.rate_bytes_ps < rate.rate_bytes_ps) {
		pr_warn_ratelimited
		    ("sch_ptb: ceil %llu is lower than rate %llu !\n",
		     ceil.rate_bytes_ps, rate.rate_bytes_ps);
		return -EINVAL;
	}

	mtu = psched_mtu(qdisc_dev(sch));
	if (max_size < mtu)
		pr_warn_ratelimited
		    ("sch_ptb: burst %llu is lower than device %s mtu (%u) !\n",
		     max_size, qdisc_dev(sch)->name, mtu);

	if (!max_size || qopt->climit <= 0 || qopt->limit <= 0) {
		printk(KERN_ERR "sch_ptb: max_size or limit is invalid\n");
		return -EINVAL;
	}

	memset(apps, 0, sizeof(apps));
	if (qopt->apps[0].rate > 0) {
		struct tc_ratespec app_conf = { 
			.linklayer = TC_LINKLAYER_ETHERNET,
		 };
		i = 0;
		for (; i < TCQ_PTB_APPS && qopt->apps[i].rate > 0; i++) {
			psched_ratecfg_precompute(&apps[i].rate, &app_conf, qopt->apps[i].rate);
			apps[i].limit = qopt->apps[i].limit;
			apps[i].buffer = PSCHED_TICKS2NS(qopt->apps[i].buffer);
			apps[i].tokens = apps[i].buffer;
			//printk(KERN_INFO "sch_ptb: app[%d] rate:%llu,limit:%u,buffer:%u,tokens:%lld\n", i, apps[i].rate.rate_bytes_ps, apps[i].limit, qopt->apps[i].buffer, apps[i].tokens);
		}
		app = i;
	}

	/* Before commit, make sure we can allocate all new qdiscs
	 * band0 is high priority class, and sub qdisc is pfifo, no limit of bandwidth
	 * band1 is low priortity class, and sub qdisc is bfifo, limit bandwidth
	 */
	if (!q->queues[PTB_BAND_H]) {
		queues[PTB_BAND_H] =
		    fifo_create_dflt(sch, &bfifo_qdisc_ops, qopt->climit,
				     extack);
		if (!queues[PTB_BAND_H]) {
			printk(KERN_ERR "sch_ptb: create high band failed\n");
			return PTR_ERR(queues[PTB_BAND_H]);
		}

		queues[PTB_BAND_M] =
		    fifo_create_dflt(sch, &bfifo_qdisc_ops, qopt->climit,
				     extack);
		if (!queues[PTB_BAND_M]) {
			printk(KERN_ERR "sch_ptb: create mid band failed\n");
			qdisc_put(queues[PTB_BAND_H]);
			return PTR_ERR(queues[PTB_BAND_M]);
		}

		queues[PTB_BAND_L] =
		    fifo_create_dflt(sch, &bfifo_qdisc_ops, qopt->limit,
				     extack);
		if (IS_ERR(queues[PTB_BAND_L])) {
			printk(KERN_ERR "sch_ptb: create low band failed\n");
			qdisc_put(queues[PTB_BAND_H]);
			qdisc_put(queues[PTB_BAND_M]);
			return PTR_ERR(queues[PTB_BAND_L]);
		}
	} else {
		err = fifo_set_limit(q->queues[PTB_BAND_H], qopt->climit);
		if (err) {
			printk(KERN_ERR
			       "sch_ptb: set high band limit failed\n");
			return err;
		}
		err = fifo_set_limit(q->queues[PTB_BAND_M], qopt->climit);
		if (err) {
			printk(KERN_ERR "sch_ptb: set mid band limit failed\n");
			return err;
		}
		err = fifo_set_limit(q->queues[PTB_BAND_L], qopt->limit);
		if (err) {
			printk(KERN_ERR "sch_ptb: set low band limit failed\n");
			return err;
		}
	}

	sch_tree_lock(sch);

	q->bands = TCQ_PTB_BANDS;
	/*
	   TOS     Bits  Means                    Linux Priority    Band
	   ------------------------------------------------------------
	   0x0     0     Normal Service           0 Best Effort     1
	   0x2     1     Minimize Monetary Cost   0 Best Effort     1
	   0x4     2     Maximize Reliability     0 Best Effort     1
	   0x6     3     mmc+mr                   0 Best Effort     1
	   0x8     4     Maximize Throughput      2 Bulk            2
	   0xa     5     mmc+mt                   2 Bulk            2
	   0xc     6     mr+mt                    2 Bulk            2
	   0xe     7     mmc+mr+mt                2 Bulk            2
	   0x10    8     Minimize Delay           6 Interactive     0
	   0x12    9     mmc+md                   6 Interactive     0
	   0x14    10    mr+md                    6 Interactive     0
	   0x16    11    mmc+mr+md                6 Interactive     0
	   0x18    12    mt+md                    4 Int. Bulk       1
	   0x1a    13    mmc+mt+md                4 Int. Bulk       1
	   0x1c    14    mr+mt+md                 4 Int. Bulk       1
	   0x1e    15    mmc+mr+mt+md             4 Int. Bulk       1

	   prio to band map: 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
	 */
	q->prio2band[0x0] = 1;
	q->prio2band[0x1] = 2;
	q->prio2band[0x2] = 2;
	q->prio2band[0x3] = 2;
	q->prio2band[0x4] = 1;
	q->prio2band[0x5] = 2;
	q->prio2band[0x6] = 0;
	q->prio2band[0x7] = 0;
	q->prio2band[0x8] = 1;
	q->prio2band[0x9] = 1;
	q->prio2band[0xa] = 1;
	q->prio2band[0xb] = 1;
	q->prio2band[0xc] = 1;
	q->prio2band[0xd] = 1;
	q->prio2band[0xe] = 1;
	q->prio2band[0xf] = 1;

	if (!q->queues[PTB_BAND_H]) {
		for (i = 0; i < q->bands; i++) {
			q->queues[i] = queues[i];
			qdisc_hash_add(q->queues[i], true);
		}
	}

	q->limit = qopt->limit;
	q->climit = qopt->climit;
	q->max_size = max_size;
	q->buffer = PSCHED_TICKS2NS(qopt->buffer);
	q->cbuffer = PSCHED_TICKS2NS(qopt->cbuffer);
	q->tokens = q->buffer;
	q->ctokens = q->cbuffer;

	memcpy(&q->rate, &rate, sizeof(struct psched_ratecfg));
	memcpy(&q->ceil, &ceil, sizeof(struct psched_ratecfg));

	i = 0;
	for (; i < app; i++) {
		memcpy(&q->apps[i].rate, &apps[i].rate, sizeof(struct psched_ratecfg));
		q->apps[i].buffer = apps[i].buffer;
		q->apps[i].limit = apps[i].limit;
		q->apps[i].tokens = apps[i].tokens;
		q->apps[i].t_c = q->t_c;
	}
	for (; i < TCQ_PTB_APPS; i++) {
		q->apps[i].rate.rate_bytes_ps = 0;
		q->apps[i].buffer = 0;
		q->apps[i].limit = 0;
		q->apps[i].tokens = 0;
		q->apps[i].t_c = 0;
	}
	q->app = app;
	q->xstats.app = app;

	sch_tree_unlock(sch);

	printk(KERN_INFO
	       "sch_ptb: dev:%s,bands:%d,limit:%u,climit:%u,max_size:%u,buffer:%llu,cbuffer:%llu,tokens:%lld,ctokens:%lld,rate:%llu,mult:%u,shift:%u,ceil:%llu,cmult:%u,cshift:%u,app:%d\n",
	       qdisc_dev(sch)->name, q->bands, q->limit, q->climit, q->max_size, q->buffer,
	       q->cbuffer, q->tokens, q->ctokens, q->rate.rate_bytes_ps,
	       q->rate.mult, q->rate.shift, q->ceil.rate_bytes_ps, q->ceil.mult,
	       q->ceil.shift, q->app);

	return 0;
}

static int ptb_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	int err;

	if (!opt) {
		return -EINVAL;
	}

	err = tcf_block_get(&q->block, &q->filter_list, sch, extack);
	if (err) {
		printk(KERN_ERR "sch_ptb: tcf_block_get err\n");
		return err;
	}

	q->t_c = ktime_get_ns();

	qdisc_watchdog_init(&q->watchdog, sch);

	return ptb_change(sch, opt, extack);
}

static int ptb_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;
	struct tc_ptb_qopt opt;
	int i;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	memset(&opt, 0, sizeof(opt));
	opt.limit = q->limit;
	opt.climit = q->climit;
	psched_ratecfg_getrate(&opt.rate, &q->rate);
	psched_ratecfg_getrate(&opt.ceil, &q->ceil);
	opt.mtu = PSCHED_NS2TICKS(q->mtu);
	opt.buffer = PSCHED_NS2TICKS(q->buffer);
	opt.cbuffer = PSCHED_NS2TICKS(q->cbuffer);

	if (q->app > 0) {
		i = 0;
		for (; i < q->app; i++) {
			opt.apps[i].rate = q->apps[i].rate.rate_bytes_ps;
			opt.apps[i].buffer = PSCHED_NS2TICKS(q->apps[i].buffer);
			opt.apps[i].limit = q->apps[i].limit;
		}
	}

	if (nla_put(skb, TCA_PTB_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;
	if (q->rate.rate_bytes_ps >= (1ULL << 32) &&
	    nla_put_u64_64bit(skb, TCA_PTB_RATE64, q->rate.rate_bytes_ps,
			      TCA_PTB_PAD))
		goto nla_put_failure;
	if (q->ceil.rate_bytes_ps >= (1ULL << 32) &&
	    nla_put_u64_64bit(skb, TCA_PTB_CEIL64, q->ceil.rate_bytes_ps,
			      TCA_PTB_PAD))
		goto nla_put_failure;

	// if (q->app > 0) {
	// 	if (nla_put(skb, TCA_PTB_APPS, sizeof(opt.apps), &opt.apps))
	// 		goto nla_put_failure;
	// }

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static int ptb_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old, struct netlink_ext_ack *extack)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	if (band > PTB_BAND_L) {
		printk(KERN_ERR "invalid bands\n");
		return -EINVAL;
	}

	return -EINVAL;

	if (band != PTB_BAND_L) {
		if (!new) {
			new = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
						TC_H_MAKE(sch->handle, arg), extack);
			if (!new)
				new = &noop_qdisc;
			else
				qdisc_hash_add(new, true);
		}
	} else {
		if (new == NULL)
			new = &noop_qdisc;
	}

	*old = qdisc_replace(sch, new, &q->queues[band]);

	return 0;
}

static struct Qdisc *ptb_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	if (band > PTB_BAND_L) {
		printk(KERN_ERR "invalid bands\n");
		return NULL;
	}

	return q->queues[band];
}

static unsigned long ptb_find(struct Qdisc *sch, u32 classid)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	unsigned long band = TC_H_MIN(classid);

	if (band - 1 >= q->bands)
		return 0;
	return band;
}

static unsigned long ptb_bind(struct Qdisc *sch, unsigned long parent,
			      u32 classid)
{
	return ptb_find(sch, classid);
}

static void ptb_unbind(struct Qdisc *q, unsigned long cl)
{
}

static int ptb_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct ptb_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = q->queues[cl - 1]->handle;
	return 0;
}

static int ptb_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				struct gnet_dump *d)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	struct Qdisc *cl_q;

	cl_q = q->queues[cl - 1];
	if (gnet_stats_copy_basic(qdisc_root_sleeping_running(sch),
				  d, cl_q->cpu_bstats, &cl_q->bstats) < 0 ||
	    qdisc_qstats_copy(d, cl_q) < 0)
		return -1;
	if (cl - 1 == PTB_BAND_L) {
		int i;
		q->xstats.tokens = clamp_t(s64, PSCHED_NS2TICKS(q->tokens),
					   INT_MIN, INT_MAX);
		q->xstats.ctokens = clamp_t(s64, PSCHED_NS2TICKS(q->ctokens),
					    INT_MIN, INT_MAX);
		for (i = 0; i < q->app; i++) {
			q->xstats.apps[i].tokens =  clamp_t(s64, PSCHED_NS2TICKS(q->apps[i].tokens),
					   INT_MIN, INT_MAX);
		}
		gnet_stats_copy_app(d, &q->xstats, sizeof(q->xstats));
	}

	return 0;
}

static void ptb_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct ptb_sched_data *q = qdisc_priv(sch);
	int band;

	if (arg->stop)
		return;

	for (band = 0; band < q->bands; band++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, band + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static struct tcf_block *ptb_tcf_block(struct Qdisc *sch, unsigned long cl,
				       struct netlink_ext_ack *extack)
{
	struct ptb_sched_data *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return q->block;
}

static const struct Qdisc_class_ops ptb_class_ops = {
	.graft		=	ptb_graft,
	.leaf		=	ptb_leaf,
	.find		=	ptb_find,
	.walk		=	ptb_walk,
	.tcf_block	=	ptb_tcf_block,
	.bind_tcf	=	ptb_bind,
	.unbind_tcf	=	ptb_unbind,
	.dump		=	ptb_dump_class,
	.dump_stats	=	ptb_dump_class_stats,
};

static struct Qdisc_ops ptb_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	&ptb_class_ops,
	.id			=	"ptb",
	.priv_size	=	sizeof(struct ptb_sched_data),
	.enqueue	=	ptb_enqueue,
	.dequeue	=	ptb_dequeue,
	.peek		=	ptb_peek,
	.init		=	ptb_init,
	.reset		=	ptb_reset,
	.destroy	=	ptb_destroy,
	.change		=	ptb_change,
	.dump		=	ptb_dump,
	.owner		=	THIS_MODULE,
};

static int __init ptb_module_init(void)
{
	return register_qdisc(&ptb_qdisc_ops);
}

static void __exit ptb_module_exit(void)
{
	unregister_qdisc(&ptb_qdisc_ops);
}

module_init(ptb_module_init)
module_exit(ptb_module_exit)

MODULE_AUTHOR("xiongdibin xdibin@gmail.com");
MODULE_DESCRIPTION("Priority Token Bucket");
MODULE_VERSION("1.0.1");
MODULE_LICENSE("GPL");
