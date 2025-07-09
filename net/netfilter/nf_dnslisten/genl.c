#include <net/netlink.h>
#include <net/genetlink.h>

#include "common.h"

enum genl_dnslisten_attr {
	DNS_LISTEN_ATTR_UNSPEC,

	DNS_LISTEN_ATTR_CLASS_ID,

	DNS_LISTEN_ATTR_DOMAIN,
	
	__DNS_LISTEN_ATTR_MAX,
};
#define DNS_LISTEN_ATTR_MAX (__DNS_LISTEN_ATTR_MAX - 1)

enum genl_dnslisten_ops {
	DNS_LISTEN_CMD_UNSPEC,

	DNS_LISTEN_CMD_REPORT,

	__DNS_LISTEN_CMD_MAX,
};
#define DNS_LISTEN_CMD_MAX (__DNS_LISTEN_CMD_MAX - 1)

static struct genl_family genl_dnslisten_family;

static struct nla_policy genl_dnslisten_policy[DNS_LISTEN_ATTR_MAX + 1] = {
	[DNS_LISTEN_ATTR_CLASS_ID] = {
		.type = NLA_U32,
	},
	[DNS_LISTEN_ATTR_DOMAIN] = {
		.type = NLA_NUL_STRING,
	},
};

static int genl_dnslisten_doit(struct sk_buff *skb, struct genl_info *info)
{
	return 0;	
}

static const struct genl_ops genl_dnslisten_ops[] = {
	{
		.cmd = DNS_LISTEN_CMD_REPORT,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = genl_dnslisten_doit
	},
};


static const struct genl_multicast_group dnslisten_mcgrps[] = {
	{ .name = "records", },
};

static struct genl_family genl_dnslisten_family __ro_after_init = {
	.hdrsize	= 0,
	.name		= "DNS_LISTEN",
	.version	= 1,
	.maxattr	= DNS_LISTEN_ATTR_MAX,
	.policy		= genl_dnslisten_policy,
	.module		= THIS_MODULE,
	.ops		= genl_dnslisten_ops,
	.n_ops		= ARRAY_SIZE(genl_dnslisten_ops),
	.mcgrps		= dnslisten_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(dnslisten_mcgrps),
};

int genl_report_dns_record(u32 class_id, const char *domain)
{
	struct sk_buff *skb;
	void *hdr;
//	int size = strlen(domain) + 1;
	int rc;

//	skb = genlmsg_new(size, GFP_KERNEL);
	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb) {
		__log("nlmsg_new failed!");
		return -1;
	}

	hdr = genlmsg_put(skb, 0, 0, &genl_dnslisten_family, 0, DNS_LISTEN_CMD_REPORT);
	if (!hdr) {
		__log("genlmsg_put failed!");
		goto nla_put_failed;
	}

	rc = nla_put_u32(skb, DNS_LISTEN_ATTR_CLASS_ID, class_id);
	if (rc) {
		__log("nla_put_u32 failed!");
		goto nla_put_failed;
	}

	rc = nla_put_string(skb, DNS_LISTEN_ATTR_DOMAIN, domain);
	if (rc) {
		__log("nla_put_string failed!");
		goto nla_put_failed;
	}

	genlmsg_end(skb, hdr);

//	__log("seems generic netlink is done! rc: %d skb:%x", rc, (unsigned int)skb);
	
	/* skb will be consumed or freed in genlmsg_multicast() */
	return genlmsg_multicast(&genl_dnslisten_family, skb, 0, 0, GFP_ATOMIC);

nla_put_failed:

	nlmsg_free(skb);

	return -1;
};

int genl_init(void)
{
	return genl_register_family(&genl_dnslisten_family);
}

int genl_exit(void)
{
	return genl_unregister_family(&genl_dnslisten_family);
}
