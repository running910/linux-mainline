#ifndef __GARBLE_PACKET_H__
#define __GARBLE_PACKET_H__

typedef struct garble_tuple_type {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	u8 protocol;
} garble_tuple_t;

typedef struct garble_tuple_v6_type {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__be16 sport;
	__be16 dport;
	u8 protocol;
} garble_tuple_v6_t;

struct sk_buff *generate_and_send_tcp_packet(garble_tuple_t *tuple, const struct sock *sk, 
					struct sk_buff *in_skb, char *payload, 
					int payload_len);

struct sk_buff *generate_and_send_tcp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr, 
					__be16 sport, __be16 dport, const struct sock *sk, 
					char *payload, int payload_len);

struct sk_buff *generate_and_send_udp_packet(garble_tuple_t *tuple, struct sk_buff *skb, struct net *net, char *payload, 
					int payload_len);

struct sk_buff *generate_and_send_udp_packet_v6(garble_tuple_v6_t *tuple, struct sk_buff *skb, struct net *net, char *payload, 
					int payload_len);

#endif // __GARBLE_PACKET_H__