#ifndef _NF_GARBLE_H
#define _NF_GARBLE_H

#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/types.h>

struct nf_garble_ops {
	void (*insert_tcp_packet)(__be32 saddr, __be32 daddr, __be16 sport,
				  __be16 dport, u32 seq, u32 ack_seq,
				  const struct net *net);
	void (*insert_tcp_packet_v6)(const struct in6_addr *saddr,
				     const struct in6_addr *daddr,
				     __be16 sport, __be16 dport,
				     u32 seq, u32 ack_seq,
				     const struct net *net);
	void (*insert_udp_packet_aggressive)(struct sk_buff *skb,
				       __be16 protocol,
				       struct net *net);
	void (*insert_tcp_packet_aggressive)(struct sk_buff *skb,
				       const struct net *net);
	void (*insert_tcp_packet_client)(struct sk_buff *skb,
				   const struct net *net);
};

#if IS_ENABLED(CONFIG_NETFILTER)
int nf_garble_register_ops(const struct nf_garble_ops *ops);
void nf_garble_unregister_ops(const struct nf_garble_ops *ops);

void nf_garble_insert_tcp_packet(__be32 saddr, __be32 daddr, __be16 sport,
				       __be16 dport, u32 seq, u32 ack_seq,
				       const struct net *net);
void nf_garble_insert_tcp_packet_v6(const struct in6_addr *saddr,
				       const struct in6_addr *daddr,
				       __be16 sport, __be16 dport,
				       u32 seq, u32 ack_seq,
				       const struct net *net);
void nf_garble_insert_udp_packet_aggressive(struct sk_buff *skb,
					    __be16 protocol,
					    struct net *net);
void nf_garble_insert_tcp_packet_aggressive(struct sk_buff *skb,
					    const struct net *net);
void nf_garble_insert_tcp_packet_client(struct sk_buff *skb,
					const struct net *net);
#else
static inline int nf_garble_register_ops(const struct nf_garble_ops *ops)
{
	return -EOPNOTSUPP;
}

static inline void nf_garble_unregister_ops(const struct nf_garble_ops *ops)
{
}

static inline void nf_garble_insert_tcp_packet(__be32 saddr, __be32 daddr,
					      __be16 sport, __be16 dport,
					      u32 seq, u32 ack_seq,
					      const struct net *net)
{
}

static inline void nf_garble_insert_tcp_packet_v6(const struct in6_addr *saddr,
					      const struct in6_addr *daddr,
					      __be16 sport, __be16 dport,
					      u32 seq, u32 ack_seq,
					      const struct net *net)
{
}

static inline void nf_garble_insert_udp_packet_aggressive(struct sk_buff *skb,
						   __be16 protocol,
						   struct net *net)
{
}

static inline void nf_garble_insert_tcp_packet_aggressive(struct sk_buff *skb,
						   const struct net *net)
{
}

static inline void nf_garble_insert_tcp_packet_client(struct sk_buff *skb,
					       const struct net *net)
{
}
#endif

static inline bool garble_check_if_conn_first_packet(struct sk_buff *skb)
{
	return (u8)skb->cb[47] == 146;
}

static inline bool garble_check_if_obfuscation_packet(struct sk_buff *skb)
{
	// maybe IP_CT_UNTRACKED can do the same thing, but we want to be more explicit 
	// and not just rely on conntrack's behavior
	return (u8)skb->cb[47] == 147;
}

static inline void garble_mark_conn_first_packet(struct sk_buff *skb)
{
	skb->cb[47] = 146;
}

static inline void garble_mark_obfuscation_packet(struct sk_buff *skb)
{
	skb->cb[47] = 147;
}

static inline void garble_clear_packet_mark(struct sk_buff *skb)
{
	skb->cb[47] = 0;
}


#endif
