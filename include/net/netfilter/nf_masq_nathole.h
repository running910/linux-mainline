/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_MASQ_NATHOLE_H
#define _NF_MASQ_NATHOLE_H

inline bool check_if_need_nathole(struct nf_conn *ct, __be32 newsrc);

inline unsigned int do_nathole(struct sk_buff *skb, struct nf_conn *ct, const struct nf_nat_range2 *range, __be32 newsrc);

void nathole_exit(void);

#endif /* _NF_MASQ_NATHOLE_H */