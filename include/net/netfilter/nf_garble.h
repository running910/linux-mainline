#ifndef _NF_GARBLE_H
#define _NF_GARBLE_H

extern void garble_insert_tcp_packet(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const struct sock *sk);

extern void garble_insert_tcp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr, __be16 sport, __be16 dport, const struct sock *sk);

extern void garble_insert_udp_packet(struct sk_buff *skb);

extern void garble_insert_udp_packet_aggressive(struct sk_buff *skb, __be16 protocol);

extern void garble_insert_tcp_packet_aggressive(struct sk_buff *skb, struct sock *sk, bool always);

static inline bool check_if_bypass_conntrack(struct sk_buff *skb)
{
	return (u8)skb->cb[47] == 147;
}


#endif
