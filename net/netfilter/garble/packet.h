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

garble_tuple_t *extract_tuple_info(struct sk_buff *skb, garble_tuple_t *tuple);

garble_tuple_v6_t *extract_tuple_info_v6(struct sk_buff *skb, garble_tuple_v6_t *tuple);

struct sk_buff *generate_and_send_tcp_packet(__be32 saddr, __be32 daddr,
				     __be16 sport, __be16 dport,
				     u32 seq, u32 ack_seq,
				     const struct net *net, char *payload,
				     int payload_len);

struct sk_buff *generate_and_send_tcp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr,
						__be16 sport, __be16 dport,
						u32 seq, u32 ack_seq,
						const struct net *net,
						char *payload, int payload_len);

struct sk_buff *generate_and_send_udp_packet(__be32 saddr, __be32 daddr, __be16 sport, 
					     __be16 dport, const struct net *net, 
					     char *payload, int payload_len);

struct sk_buff *generate_and_send_udp_packet_v6(const struct in6_addr *saddr, const struct in6_addr *daddr,
					        __be16 sport, __be16 dport, const struct net *net, 
						char *payload, int payload_len);

#endif // __GARBLE_PACKET_H__