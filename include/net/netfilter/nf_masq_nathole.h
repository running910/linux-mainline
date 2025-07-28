/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_MASQ_NATHOLE_H
#define _NF_MASQ_NATHOLE_H

unsigned int do_nathole(struct sk_buff *skb, struct nf_conn *ct, const struct nf_nat_range2 *range, __be32 newsrc);

#endif /* _NF_MASQ_NATHOLE_H */