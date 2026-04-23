#ifndef __GARBLE_HOOK_H__
#define __GARBLE_HOOK_H__


extern void garble_insert_tcp_packet(__be32 saddr, __be32 daddr, __be16 sport,
				    __be16 dport, u32 seq, u32 ack_seq,
				    const struct net *net);

extern void garble_insert_tcp_packet_v6(const struct in6_addr *saddr,
				       const struct in6_addr *daddr,
				       __be16 sport, __be16 dport,
				       u32 seq, u32 ack_seq,
				       const struct net *net);

extern void garble_insert_udp_packet(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const struct net *net);

extern void garble_insert_udp_packet_aggressive(struct sk_buff *skb, __be16 protocol, struct net *net);

extern void garble_insert_tcp_packet_aggressive(struct sk_buff *skb, const struct net *net);

extern void garble_insert_tcp_packet_client(struct sk_buff *skb, const struct net *net);

#endif