/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RUNNING910_NETLOG_H
#define _RUNNING910_NETLOG_H

#define __log(fmt, ...) printk("wx_debug: func: %s line: %d file: %s "fmt"\n", __FUNCTION__, __LINE__, __FILE__, ##__VA_ARGS__)


extern u32 netlog_remote_addr;
extern u32 netlog_inner_addr;
extern u32 netlog_enable;

#define ct_netlog_should_log(ct) \
	(unlikely(netlog_enable) && ct_if_netlog_packet(ct))

static inline int ct_if_netlog_packet(const struct nf_conn *ct)
{
	const struct nf_conntrack_tuple *orig_tuple, *reply_tuple;

	if (!ct)
		return 0;

	orig_tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

	//if (orig_tuple->dst.protonum != IPPROTO_UDP)
	//	return 0;

	if (orig_tuple->src.u3.ip == netlog_remote_addr ||  /* ORIG src */
	    orig_tuple->dst.u3.ip == netlog_remote_addr ||  /* ORIG dst */
	    reply_tuple->src.u3.ip == netlog_remote_addr || /* REPLY src */
	    reply_tuple->dst.u3.ip == netlog_remote_addr)   /* REPLY dst */
		return 1;

	if (orig_tuple->src.u3.ip == netlog_inner_addr ||   /* ORIG src */
	    orig_tuple->dst.u3.ip == netlog_inner_addr ||   /* ORIG dst */
	    reply_tuple->src.u3.ip == netlog_inner_addr ||  /* REPLY src */
	    reply_tuple->dst.u3.ip == netlog_inner_addr)    /* REPLY dst */
		return 1;

	return 0;
}

// implemented with reference to the function nf_ct_dump_tuple_ip
static inline void log_ct_info(const struct nf_conn *ct, const char *extra)
{
	const struct nf_conntrack_tuple *orig_tuple, *reply_tuple;
	const char *proto_str = "UNKNOWN";

	//if (!ct || !ct_if_netlog_packet(ct))
	//	return;

	orig_tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	reply_tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

	switch (orig_tuple->dst.protonum) {
	case IPPROTO_TCP: proto_str = "TCP"; break;
	case IPPROTO_UDP: proto_str = "UDP"; break;
	case IPPROTO_ICMP: proto_str = "ICMP"; break;
	}

	__log("[%s][orig %pI4:%hu -> %pI4:%hu][reply %pI4:%hu -> %pI4:%hu] | %s",
		proto_str,
		&orig_tuple->src.u3.ip, ntohs(orig_tuple->src.u.all),
		&orig_tuple->dst.u3.ip, ntohs(orig_tuple->dst.u.all),
		&reply_tuple->src.u3.ip, ntohs(reply_tuple->src.u.all),
		&reply_tuple->dst.u3.ip, ntohs(reply_tuple->dst.u.all),
		extra);
}

#define log_ct_pref(ct, fmt, ...) \
    do { \
        if (ct_netlog_should_log(ct)) { \
            const struct nf_conntrack_tuple *orig_tuple = &(ct)->tuplehash[IP_CT_DIR_ORIGINAL].tuple; \
            const struct nf_conntrack_tuple *reply_tuple = &(ct)->tuplehash[IP_CT_DIR_REPLY].tuple; \
            const char *proto_str = "UNKNOWN"; \
            char __extra_info[256]; \
            \
            switch (orig_tuple->dst.protonum) { \
            case IPPROTO_TCP: proto_str = "TCP"; break; \
            case IPPROTO_UDP: proto_str = "UDP"; break; \
            case IPPROTO_ICMP: proto_str = "ICMP"; break; \
            } \
            \
            snprintf(__extra_info, sizeof(__extra_info), fmt, ##__VA_ARGS__); \
            __log("[%s][orig %pI4:%hu -> %pI4:%hu][reply %pI4:%hu -> %pI4:%hu] | %s", \
                 proto_str, \
                 &orig_tuple->src.u3.ip, ntohs(orig_tuple->src.u.all), \
                 &orig_tuple->dst.u3.ip, ntohs(orig_tuple->dst.u.all), \
                 &reply_tuple->src.u3.ip, ntohs(reply_tuple->src.u.all), \
                 &reply_tuple->dst.u3.ip, ntohs(reply_tuple->dst.u.all), \
                 __extra_info); \
        } \
    } while (0)

#define log_ct(ct, fmt, ...) \
	do { \
		if (ct_netlog_should_log(ct)) { \
			__log(fmt, ##__VA_ARGS__); \
		} \
	} while (0)

#define log_ct_pref_func(ct, fmt, ...) \
	do { \
		if (ct_netlog_should_log(ct)) { \
			char __extra_info[256]; \
			snprintf(__extra_info, sizeof(__extra_info), fmt, ##__VA_ARGS__); \
			log_ct_info(ct, __extra_info); \
		} \
	} while (0)

static inline const char *get_tuple_and_mask_str(const struct nf_conntrack_tuple *tuple, const struct nf_conntrack_tuple_mask *mask, char *buf, int len)
{
	const char *proto_str = "UNKNOWN";

	if (!tuple || !mask) {
		return buf;
	}

	// 协议类型转换
	switch (tuple->dst.protonum) {
	case IPPROTO_TCP: proto_str = "TCP"; break;
	case IPPROTO_UDP: proto_str = "UDP"; break;
	case IPPROTO_ICMP: proto_str = "ICMP"; break;
	}

	snprintf(buf, len, "[Tuple][%s] %pI4:%hu -> %pI4:%hu [Mask] src_ip=%pI4 src_port=%hu", 
		proto_str,
		&tuple->src.u3.ip, ntohs(tuple->src.u.all),
		&tuple->dst.u3.ip, ntohs(tuple->dst.u.all),
		&mask->src.u3.ip, ntohs(mask->src.u.all));

	return buf;
}







#define skb_netlog_should_log(skb) \
	(unlikely(netlog_enable) && skb_if_netlog_packet(skb))

static inline int skb_if_netlog_packet(const struct sk_buff *skb)
{
	const struct iphdr *iph;

	if (!skb)
		return 0;

	iph = ip_hdr(skb);

	//if (iph->protocol != IPPROTO_UDP)
	//	return 0;

	if (iph->daddr == netlog_remote_addr || iph->saddr == netlog_remote_addr)
		return 1;

	if (iph->daddr == netlog_inner_addr || iph->saddr == netlog_inner_addr)
		return 1;

	return 0;
}

static inline void log_tuple_info(const struct sk_buff *skb, const char *extra)
{
	const struct iphdr *ip_header;
	char proto_str[8] = "UNKNOWN";
	__be16 src_port = 0, dst_port = 0;

	//if (!skb || !skb_if_netlog_packet(skb))
	//	return;

	ip_header = ip_hdr(skb);

	switch (ip_header->protocol) {
	case IPPROTO_TCP: {
		const struct tcphdr *tcp = tcp_hdr(skb);
		src_port = tcp->source;
		dst_port = tcp->dest;
		strcpy(proto_str, "TCP");
		break;
	}
	case IPPROTO_UDP: {
		const struct udphdr *udp = udp_hdr(skb);
		src_port = udp->source;
		dst_port = udp->dest;
		strcpy(proto_str, "UDP");
		break;
	}
	}

	if (src_port && dst_port) {
		__log("[%s] %pI4:%d -> %pI4:%d | %s",
		      proto_str,
		      &ip_header->saddr, ntohs(src_port),
		      &ip_header->daddr, ntohs(dst_port),
		      extra);
	} else {
		__log("[%s] %pI4 -> %pI4 | %s",
		      proto_str,
		      &ip_header->saddr,
		      &ip_header->daddr,
		      extra);
	}
}

#define log_skb_pref(skb, fmt, ...) \
	do { \
		if (skb_netlog_should_log(skb)) { \
			const struct iphdr *ip_header = ip_hdr(skb); \
			char proto_str[8] = "UNKNOWN"; \
			__be16 src_port = 0, dst_port = 0; \
			char __extra_info[256]; \
			\
			switch (ip_header->protocol) { \
			case IPPROTO_TCP: { \
				const struct tcphdr *tcp = tcp_hdr(skb); \
				src_port = tcp->source; \
				dst_port = tcp->dest; \
				strcpy(proto_str, "TCP"); \
				break; \
			} \
			case IPPROTO_UDP: { \
				const struct udphdr *udp = udp_hdr(skb); \
				src_port = udp->source; \
				dst_port = udp->dest; \
				strcpy(proto_str, "UDP"); \
				break; \
			} \
			} \
			\
			snprintf(__extra_info, sizeof(__extra_info), fmt, ##__VA_ARGS__); \
			\
			if (src_port && dst_port) { \
				__log("[%s] %pI4:%d -> %pI4:%d | %s", \
					proto_str, \
					&ip_header->saddr, ntohs(src_port), \
					&ip_header->daddr, ntohs(dst_port), \
					__extra_info); \
			} else { \
				__log("[%s] %pI4 -> %pI4 | %s", \
					proto_str, \
					&ip_header->saddr, \
					&ip_header->daddr, \
					__extra_info); \
			} \
		} \
	} while (0)

#define log_skb(skb, fmt, ...) \
	do { \
		if (skb_netlog_should_log(skb)) { \
			__log(fmt, ##__VA_ARGS__); \
		} \
	} while (0)

#define log_skb_pref_func(skb, fmt, ...) \
	do { \
		if (skb_netlog_should_log(skb)) { \
			char __extra_info[256]; \
			snprintf(__extra_info, sizeof(__extra_info), fmt, ##__VA_ARGS__); \
			log_tuple_info(skb, __extra_info); \
		} \
	} while (0)


void __init net_debug_init(void);

#endif