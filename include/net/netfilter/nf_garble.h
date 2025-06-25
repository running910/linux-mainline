#ifndef _NF_GARBLE_H
#define _NF_GARBLE_H

void response_tls_client_hello(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport, const struct sock *sk);

#endif