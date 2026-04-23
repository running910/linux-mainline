// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

#include <net/netfilter/nf_garble.h>

static DEFINE_MUTEX(nf_garble_lock);
static const struct nf_garble_ops __rcu *nf_garble_ops;

int nf_garble_register_ops(const struct nf_garble_ops *ops)
{
	int err = 0;

	if (!ops || !ops->insert_tcp_packet || !ops->insert_tcp_packet_v6 ||
	    !ops->insert_udp_packet_aggressive ||
	    !ops->insert_tcp_packet_aggressive ||
	    !ops->insert_tcp_packet_client)
		return -EINVAL;

	mutex_lock(&nf_garble_lock);
	if (rcu_access_pointer(nf_garble_ops))
		err = -EBUSY;
	else
		rcu_assign_pointer(nf_garble_ops, ops);
	mutex_unlock(&nf_garble_lock);

	return err;
}
EXPORT_SYMBOL_GPL(nf_garble_register_ops);

void nf_garble_unregister_ops(const struct nf_garble_ops *ops)
{
	mutex_lock(&nf_garble_lock);
	if (rcu_access_pointer(nf_garble_ops) == ops)
		RCU_INIT_POINTER(nf_garble_ops, NULL);
	mutex_unlock(&nf_garble_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_garble_unregister_ops);

void nf_garble_insert_tcp_packet(__be32 saddr, __be32 daddr, __be16 sport,
				       __be16 dport, u32 seq, u32 ack_seq,
				       const struct net *net)
{
	const struct nf_garble_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(nf_garble_ops);
	if (ops)
		ops->insert_tcp_packet(saddr, daddr, sport, dport, seq, ack_seq,
				       net);
	rcu_read_unlock();
}

void nf_garble_insert_tcp_packet_v6(const struct in6_addr *saddr,
				       const struct in6_addr *daddr,
				       __be16 sport, __be16 dport,
				       u32 seq, u32 ack_seq,
				       const struct net *net)
{
	const struct nf_garble_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(nf_garble_ops);
	if (ops)
		ops->insert_tcp_packet_v6(saddr, daddr, sport, dport, seq,
					  ack_seq, net);
	rcu_read_unlock();
}

void nf_garble_insert_udp_packet_aggressive(struct sk_buff *skb,
					    __be16 protocol,
					    struct net *net)
{
	const struct nf_garble_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(nf_garble_ops);
	if (ops)
		ops->insert_udp_packet_aggressive(skb, protocol, net);
	rcu_read_unlock();
}

void nf_garble_insert_tcp_packet_aggressive(struct sk_buff *skb,
					    const struct net *net)
{
	const struct nf_garble_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(nf_garble_ops);
	if (ops)
		ops->insert_tcp_packet_aggressive(skb, net);
	rcu_read_unlock();
}

void nf_garble_insert_tcp_packet_client(struct sk_buff *skb,
					const struct net *net)
{
	const struct nf_garble_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(nf_garble_ops);
	if (ops)
		ops->insert_tcp_packet_client(skb, net);
	rcu_read_unlock();
}
