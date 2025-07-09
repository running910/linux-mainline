#ifndef _NF_GARBLE_H
#define _NF_GARBLE_H


void response_tls_client_hello(struct sk_buff *skb, const struct sock *sk);

void response_tls_client_hello_v6(const struct in6_addr *saddr, const struct in6_addr *daddr, __be16 sport, __be16 dport, const struct sock *sk);


#endif